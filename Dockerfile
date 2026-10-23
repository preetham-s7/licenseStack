FROM python:3.12-slim

WORKDIR /app
COPY . /app

ENV LICENSE_HOST=0.0.0.0
ENV LICENSE_DB_PATH=/app/data/licenses.sqlite3

RUN mkdir -p /app/data
EXPOSE 8080
VOLUME ["/app/data"]

CMD ["python", "run_server.py"]
