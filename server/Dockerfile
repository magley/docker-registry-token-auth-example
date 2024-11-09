FROM python:3.9-alpine3.19

WORKDIR /code
COPY ./requirements.txt /code/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt
COPY . .

CMD ["flask", "--app", "main.py", "run", "--host=0.0.0.0", "--port=8000"]