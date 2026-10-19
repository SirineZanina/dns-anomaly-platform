# DNS Anomaly Detection Platform

A lab platform that collects DNS traffic, normalizes it to the Elastic Common Schema (ECS), and detects suspicious behaviour such as DNS tunneling, DGA domains and DNS flooding.

**Author:** <your name>  
**Supervisor:** <teacher's name>  
**Status:** Week 1 of 8 complete (environment, stack, documentation, datasets, architecture)

## Threats covered

| Priority | Threat |
|---|---|
| MVP | DNS tunneling, DGA / botnet domains, DNS flooding and amplification |
| Stretch | Data exfiltration, fast-flux, NXDOMAIN storms |

Details of each threat (signs in DNS, features, detection approach, false positives) are in [`docs/threat-catalogue.md`](docs/threat-catalogue.md).

## Stack

| Component | Version | Role |
|---|---|---|
| Elasticsearch | 8.15.3 | Event and alert storage |
| Kibana | 8.15.3 | Log exploration |
| PostgreSQL | 16 | Incidents, feedback, users |
| FastAPI | - | Backend API |
| Zeek | container image | Turns pcaps or live traffic into `dns.log` |

Everything runs with Docker Compose inside a Kubuntu VM (KVM/libvirt, 8 GB RAM, 4 CPUs).

## Quick start

```bash
git clone git@github.com:SirineZanina/dns-anomaly-platform.git
cd dns-anomaly-platform
# create .env with the database credentials (it is not stored in Git)
docker compose up -d
docker compose ps
./scripts/check_stack.sh
```

Elasticsearch needs `vm.max_map_count=262144` set on the host, for example in `/etc/sysctl.d/99-elasticsearch.conf`.

Once running:
- Kibana: `http://<vm-ip>:5601`
- API docs: `http://<vm-ip>:8000/docs`

## Try the DNS pipeline

```bash
# Read a saved capture with Zeek and print the main fields
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/data/pcaps:/pcaps:ro" -v "$PWD/data/zeek-out:/out" -w /out \
  zeek/zeek zeek -C -r /pcaps/sample-rich.pcap

grep -v '^#' data/zeek-out/dns.log | cut -f1,3,10,14,16 | head
```

Columns: time, client IP, queried domain, record type, response code.

## Datasets

Datasets are not stored in Git. Run the download script in `scripts/` to fetch them into `data/datasets/`:

- Tranco top 1M (benign domain baseline)
- Labeled DGA dataset (DGA families vs benign domains)
- OpenPhish and Feodo Tracker feeds (threat intelligence)

## Documentation

| File | Content |
|---|---|
| [`docs/threat-catalogue.md`](docs/threat-catalogue.md) | Threats, signs and detection approach |
| [`docs/data-sources.md`](docs/data-sources.md) | The 4 data sources and ECS field mapping |
| [`docs/architecture.md`](docs/architecture.md) | Architecture diagram and design decisions |
| [`docs/plan.md`](docs/plan.md) | 8-week plan and risks |

## Roadmap

| Week | Focus | Status |
|---|---|---|
| 1 | Environment, stack, threat catalogue, sources, datasets, architecture | Done |
| 2 | Collection and ingestion | Planned |
| 3 | Feature engineering | Planned |
| 4 | ML models | Planned |
| 5 | Real-time scoring and correlation | Planned |
| 6 | Backend API and dashboard | Planned |
| 7 | Notifications, feedback, hardening | Planned |
| 8 | Testing, documentation, demo | Planned |

## Safety

Attack tools (`hping3`, `iodine`, `scapy`, `dnscat2`) are used only inside the isolated lab network, never against networks I do not own.

## Commit convention

Conventional Commits: `<type>(<scope>): <description>`, for example `docs: add threat catalogue`.
