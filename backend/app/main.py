import os

import psycopg
from elasticsearch import Elasticsearch
from fastapi import FastAPI

app = FastAPI(title="DNS Anomaly Detection Platform", version="0.1.0")

ES_URL = os.environ["ELASTICSEARCH_URL"]
DB_URL = os.environ["DATABASE_URL"]


@app.get("/health")
def health():
    status = {"api": "ok"}

    try:
        es = Elasticsearch(ES_URL)
        status["elasticsearch"] = es.cluster.health()["status"]
    except Exception as exc:
        status["elasticsearch"] = f"error: {exc}"

    try:
        with psycopg.connect(DB_URL) as conn:
            conn.execute("SELECT 1")
        status["postgres"] = "ok"
    except Exception as exc:
        status["postgres"] = f"error: {exc}"

    return status
