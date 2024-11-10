import base64
import datetime
import uuid
from flask import Flask, request, Response
import jwt
app = Flask(__name__)

# =============================================================================
# 
# JWTs are always signed with a secret key. Docker registry requires this to be
# a private key from a asymmetric cryptography scheme.
#
# Additionally, Docker Registry requires the JWT to contain one of three
# possible header claims (key id, jwk or certificate chain) [1]. This example
# uses the certificate chain. Other methods may require more work and
# configuration so that Docker Registry/Docker trusts unverified data.
#
# Therefore, we must provide the certificate chain inside every single JWT
# issued by our server to Docker Registry. In this example, we only pass the
# self-signed certificate, as it makes up the whole chain. We cannot pass the
# '.pem' file contents, because the JWT specification expects base64 encoded
# .der certificates [2] (that is, .pem certificates without headers and footers
# and all linebreaks removed).
#
# [1] https://distribution.github.io/distribution/spec/auth/jwt/
# [2] https://datatracker.ietf.org/doc/html/rfc7517#appendix-B

SECRET_KEY = ""
with open("/mnt/local/certs/private_key.pem", "r") as f:
    SECRET_KEY = f.read()
    
CERT_DER_B64 = ""
with open("/mnt/local/certs/cert.der.b64", "r") as f:
    CERT_DER_B64 = f.read()

# =============================================================================
# 
# This is a mock database.
# `users` contains dummy users in the form:
#       username: password
#
# `acl` contains repository authorization data in the form:
#       username: { reponame: [actions] }
#
# The data format does not matter, however:
# - users should have usernames
# - repositories should have names

users = {
    "user1": "1234",
    "user2": "qwerty",
}

acl = {
    'user1': {
        'registry': ['pull', 'push'],
    },
    'user2': {
        'registry': ['pull'],
    }
}

# ============================================================================
#
# All authentication and authorization from Docker Registry to our server goes
# thorugh this single endpoint. Docker Registry always sends a GET request.
# 
# ----------------------------------------------------------------------------
#                            Scenario 1: Login
# ----------------------------------------------------------------------------
#
# Step 1: User logs in to our Docker Registry through the Docker Client:
#
#       $ docker login localhost:5000
#       Username: user1
#       Password: 1234
#
# Step 2: Docker Registry delegates the request to localhost:8000/registry with
# the following request:
#
#       GET http://localhost:8000/registry?service=localhost:5000
#       Authorization BASIC user1:1234
#
# Note: some HTTP query parameters have been omitted. Note: Authorization is
# base-64 encoded. This doesn't make communication safe, which is why Docker
# Registry _requires_ TLS (registry/config.yaml).
#
# Step 3: Our server must decrypt the user credentials from the Authorization
# header and check if such user exists. If login fails, return 401. Otherwise,
# create a JWT (see below).
#
# Step 4: Docker Registry receives a JWT and validates it. If everything is ok,
# Registry will tell Client to save the credentials in /.docker/config.json.
#
# Step 5: Whenever the user issues a command e.g. `docker push`, `docker pull`;
# Client will send the authorization headers automatically.
#
# ----------------------------------------------------------------------------
#                            Scenario 2: Push
# ----------------------------------------------------------------------------
#
# Step 1: User pushes an image to our Registry:
#
#       $ docker push localhost:5000/nginx
#
# Step 2: Registry delegates authorization to our server:
#
#    GET
#    http://localhost:8000/registry?service=localhost:5000&scope=repository:nginx:pull,push
#    Authorization BASIC user1:1234
#
# Step 3: The server has to decide whether `user1` can `pull,push` to the
# `nginx` repository.
#
# Step 4: If the user is authorizaed, we return the same JWT as in Scenario 1
# with the `access` claim set properly (see below). If the user is unauthorized,
# return 401.
#
# Step 5: Based on the response from our server, Registry will proceed or cancel
# the push operation.
#
# ----------------------------------------------------------------------------
#                            Scenario 3: Pull
# ----------------------------------------------------------------------------
#
# This is idential to Scenario 2, but the scope actions are just `pull`. Since
# pull is a read operation, it requires fewer priveleges than `push` and should
# be permitted to most users (even unauthenticated ones), but this depends on
# the server policy that we implement.
#
# ----------------------------------------------------------------------------
#                            Appendix A: JWT
# ----------------------------------------------------------------------------
#
# Our server must construct a JWT when responding to Docker Registry. The JWT is
# used only as a response from our server to Docker Registry. The JWT has a
# required list of claims as specified in [1]. We will go over the more
# important claims here.
#
# [1] https://distribution.github.io/distribution/spec/auth/jwt/
#
# x5c    As mentioned, we must supply a certificate chain so that Registry can
#        validate the signed JWT. 
#
# iss    Our web server (in this case it's localhost:8000). 
#
# sub    Username of the user that issued a login/push/pull command.
#  
# aud    Docker registry (localhost:5000). 
#
# jti    All tokens must have an ID. In this example we used a UUID 
#
# access Custom claim used by Registry to check for the user's access scope. When the user is logging in, this claim
# should be empty. 
#       type    Should be "repository" 
#       name    Name of the repository (`name` or `username/name`) 
#       actions Array of `pull` and/or `push`.
#
# The JWT is signed with the private key using the same algorithm that was used
# to generate the certificate (in this example, RSA).

@app.route("/registry", methods=["GET"])
def registry_endpoint():
    service = request.args.get("service")
    scope = request.args.get("scope")
    authorization_header = request.headers.get('Authorization')

    if not authorization_header:
        # You could permit some requests here. For example, most `pull`
        # operations should be allowed even for unauthenticated users.

        return Response(status=401)
    
    if not authorization_header.startswith("Basic "):
        return Response(status=401)

    auth_token = authorization_header.split(" ")[1]
    username, password = decode_auth_header(auth_token)
  
    if not user_exists(username, password):
        return Response(status=401)

    if scope is not None and not has_permissions(username, scope):
        return Response(status=401)

    jwt = build_jwt_for_docker_registry(username, service, scope)

    return { "token": jwt }


def decode_auth_header(auth_token):
    """
    Decode the username and password fields from an HTTP Basic authorization
    header.

    ---
    
    `auth_token` is the encoded token. In other words, if the authorization
    header is:

        Authorization: Basic dhkj3h289,

    then `auth_token` must be `dhkj3h289`.

    ---

    Returns a pair of strings `username`, `password`.
    """
    decoded_bytes = base64.b64decode(auth_token).decode('utf-8')
    username, password = decoded_bytes.split(':')
    return username, password


def has_permissions(username, scope):
    """
    Determine if a user has the requested priveleges for the given repository.

    ---

    `username` is the name of the user.

    `scope` is a string including the name of the repository and the list of
    actions the user is requesting.
    
    For example: `repository:nginx:push,pull` means that the user wants access
    to push and pull to the official `nginx` repository.

    ---

    Returns `true` if the user is authorized, `false` otherwise.  
    """
    scope_parts = scope.split(':')

    if len(scope_parts) != 3 or scope_parts[0] != 'repository':
        return False
    
    repository_name = scope_parts[1]
    requested_actions = scope_parts[2].split(',')

    user_permissions = acl.get(username, {})
    allowed_actions = user_permissions.get(repository_name, [])

    return all(a in allowed_actions for a in requested_actions)


def user_exists(username, password):
    """
    Check if a user with the specified credentials exists in the database. This
    method should return `True` or `False` in the exact same cases as a standard
    login.
    """
    return username in users and users[username] == password


def build_jwt_for_docker_registry(username, service, scope):
    """
    Create a JWT as required by Docker Registry.

    ---

    `username` is the name of the user.

    `service` is the name of the service requesting the JWT. In other words,
    this is the audience for the JWT. This value should be extracted from the
    HTTP request issued by Docker Registry.

    `scope` is the scope of resource access built into the JWT, or `None` if the
    Docker Registry request is just a login operation. For example:
    `repository:nginx:push,pull` means that the user wants access to push and
    pull to the official `nginx` repository.

    ---

    Returns a string representaiton of the encoded JWT.
    """
    now = datetime.datetime.now()

    token_payload = {
        'iss': 'localhost:8000',
        'sub': username,
        'aud': service,
        'exp': now + datetime.timedelta(hours=1),
        'nbf': now,
        'iat': now,
        'jti': str(uuid.uuid4()),
        'access': []
    }
    token_headers = { 
        'x5c': [CERT_DER_B64] 
    }

    if scope is not None:
        scope_parts = scope.split(':')   
        token_payload['access'] = [
            {
                'type': 'repository',
                'name': scope_parts[1],
                'actions': scope_parts[2].split(',')
            }
        ]

    return jwt.encode(token_payload, SECRET_KEY, algorithm='RS256', headers=token_headers)    

# ============================================================================
#
# This is a webhook endpoint.
# It will fire on every `docker pull` and `docker push` (among other things).
# 
@app.route("/registry/notifications", methods=["POST", "PUT"])
def registry_notification_endpoint():
    data = request.get_json()
    for event in data["events"]:
        action = event.get("action", None)
        username = event.get("actor", {}).get("name", None)
        repository = event.get("target", {}).get("repository", None)
        tag = event.get("target", {}).get("tag", None)
        
        print(f"User '{username}' completed '{action}' of repository '{repository}' with tag '{tag}'")

    return {}


if __name__ == "__main__":
    app.run(debug=True)