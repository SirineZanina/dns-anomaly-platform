#!/usr/bin/env bash
echo "== Elasticsearch =="; curl -s "localhost:9200/_cluster/health?pretty"
echo "== Kibana ==";        curl -s -o /dev/null -w "HTTP %{http_code}\n" localhost:5601/api/status
echo "== Backend ==";       curl -s localhost:8000/health; echo
