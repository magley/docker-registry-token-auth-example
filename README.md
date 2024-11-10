# Docker Registry token based authentification example

## About

This repository demonstrates how to create a server which handles
authentification and authorization for a private Docker Registry (Docker
Distribution).

The official documentation for this is cryptic and useful resources are scarce.

The example server is written in Flask and it handles logging in through `docker
login` and authorization for `docker push` and `docker pull` using access
control lists (i.e. a mock database).

Token signing is done with a certificate chain. You must have a public and
private key pair to sign the JWT used by Docker Registry. See `certs/README.md`.

Additionally, a Docker Registry webhook implementation is also demonstrated.

## Getting started

Run everything:

```sh
docker compose up
```

Test manually:

```sh
# 1) Sign in
docker login localhost:5000
    # username user1
    # password 1234

# 2) Push an image to the repository.
# (check `acl` server/main.py).
docker tag registry:2 localhost:5000/registry:2
docker push localhost:5000/registry:2 # Will succeed

# 3) Sign in as another user
docker logout localhost:5000
docker login localhost:5000
    # username user2
    # password qwerty

# 4) Try to push and pull the image.
docker push localhost:5000/registry:2 # Will fail
docker pull localhost:5000/registry:2 # Will succeed
```