# Plan, weeks 2 to 8

Week 1 (environment, stack, catalogue, sources, datasets, architecture) is done.

| Week | Focus | Deliverable |
|---|---|---|
| 2 | Collection and ingestion | Zeek logs flowing end to end into `dns-logs-*` with ECS fields |
| 3 | Feature engineering | Labeled dataset and a feature module with tests |
| 4 | ML models | Trained models and an evaluation report |
| 5 | Real-time scoring and correlation | Working detection and incidents (MVP checkpoint) |
| 6 | Backend API and dashboard | FastAPI with JWT and RBAC, admin pages |
| 7 | Notifications, feedback, hardening | Alerts, attack simulations, security enabled |
| 8 | Testing, docs, demo | End-to-end tests, documentation, live demo |

## MVP scope

Detect DNS tunneling, DGA domains and DNS flooding. Fast-flux, exfiltration and NXDOMAIN storms are stretch goals.

## Risks

| Risk | Mitigation |
|---|---|
| Elasticsearch runs out of the VM's 8 GB RAM | Cap the JVM heap at 2 to 3 GB and keep indices small |
| Thin pool (80 GB) fills up | Check `lvs` weekly, stay under about 80%, delete old indices |
| Public datasets differ from lab traffic | Evaluate on public data and on own lab captures, report both |
| Live demo fails | Replay saved pcaps with `tcpreplay` |
| Pasting into SSH corrupts files | Run `head -n 2` after each paste, make small fixes in vim |
| Attack tools run against the wrong network | Use them only inside the isolated lab |
