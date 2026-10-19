# Plan: Weeks 1 to 8

Version 0.1, 19 Oct 2026.

**Goal:** a working DNS anomaly detection platform that ingests several log sources, detects tunneling, DGA and DNS flooding (MVP), shows incidents in a dashboard, and can be demonstrated live from replayed traffic.

## Overview

| Week | Focus | Deliverable |
|---|---|---|
| 1 | Planning and preparation | Environment, threat catalogue, data sources, datasets, architecture, plan |
| 2 | Collection and ingestion | Logs flowing end to end into Elasticsearch |
| 3 | Feature engineering | Labeled dataset and feature module |
| 4 | ML models | Trained models and evaluation report |
| 5 | Real-time scoring and correlation | Working detection and incidents (**MVP checkpoint**) |
| 6 | Backend API and dashboard | FastAPI with JWT/RBAC and admin pages |
| 7 | Notifications, feedback, hardening | Alerts, attack simulations, security on |
| 8 | Testing, docs, demo | End-to-end tests, documentation, live demo |

## Details

**Week 1: Planning and preparation.** Lab VM, Docker stack, repository, `docs/threat-catalogue.md`, `docs/data-sources.md`, datasets in `data/`, Zeek reading a pcap, `docs/architecture.md`, this plan.

**Week 2: Collection and ingestion.**
- Zeek writes `dns.log` and `conn.log` as JSON; Filebeat ships them with ECS mapping into `dns-logs-*` and `flows-*`.
- Loaders for DHCP and the threat-intel feeds (`dhcp-*`, `ti-indicators`).
- Ingest pipeline for derived domain fields.
- A benign traffic generator in the lab, and first test with `iodine` or `dnscat2` (preparation only, short runs).
- *Done when:* a `dig` in the lab appears in Kibana with the right ECS fields within seconds.

**Week 3: Feature engineering.**
- Per-query features: length, entropy, label count, digit and consonant ratio, n-gram score.
- Per-window features per client: queries per second, NXDOMAIN ratio, unique domains, record-type mix.
- Labeled dataset from Tranco (benign), DGA lists (malicious) and tunneling pcaps, with a fixed train/test split.
- *Done when:* the feature module has unit tests and produces a labeled table from the datasets.

**Week 4: ML models.**
- DGA classifier (Random Forest or gradient boosting), tunneling model (supervised plus Isolation Forest), flood baseline (rolling z-score).
- Evaluation: precision, recall, F1, false-positive rate, confusion matrix, comparison with the simple rule baseline.
- Models stored with versions and metrics in `model_registry`.
- *Done when:* the evaluation report is written and the best models are registered.

**Week 5: Real-time scoring and correlation (MVP checkpoint).**
- A worker reads new windows from Elasticsearch, computes features, applies rules and models, and writes alerts to `alerts-*` and PostgreSQL.
- Correlation groups alerts from DNS, flows and threat intel into incidents (`incident_id`).
- *Done when:* replaying the test pcaps raises the right alerts and at least one correlated incident for all three MVP threats. If this fails, the stretch work stops and Week 6 starts later.

**Week 6: Backend API and dashboard.**
- FastAPI endpoints for alerts, incidents, whitelist, data sources and models, with JWT login and the `admin` and `analyst` roles.
- Dashboard pages: alert list and detail, status changes, source health, model list. Kibana remains the log explorer.
- *Done when:* an analyst can log in, see an alert and mark it as a false positive.

**Week 7: Notifications, feedback, hardening.**
- Alert notifications (email or webhook) by severity.
- Feedback loop: false positives feed the whitelist and the next training set.
- Hardening: secrets handling, password policy, rate limits, audit log, enabling Elasticsearch security and TLS.
- Take a VM snapshot first (after checking thin pool space), then run the attack simulations from the threat catalogue and record the results.
- Stretch threats (exfiltration, fast-flux, NXDOMAIN storm) only if the MVP is stable.

**Week 8: Testing, documentation, demo.**
- End-to-end tests with replayed pcaps, API tests, final evaluation numbers.
- Documentation: install guide, user guide, architecture, limitations (for example DoH blind spot).
- Rehearsed demo script using replay only. Buffer time for fixes.

## Risks

The risks and mitigations are listed in `docs/architecture.md`, section 5. The three that matter most for the schedule: Elasticsearch memory on the 8 GB VM, thin-pool space, and public datasets that differ from lab traffic.
