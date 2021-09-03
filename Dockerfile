FROM ikerlin/php:7.1-fpm-python3-dev

COPY . /app
WORKDIR /app

ENTRYPOINT ["python3", "exp.py"]