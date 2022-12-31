FROM python:3.11-slim-bullseye

WORKDIR /usr/src/dns-rebind
COPY . .

# RUN adduser --disabled-password --no-create-home python
# USER python:python

ENTRYPOINT [ "python", "./dns-server.py" ]

EXPOSE 53