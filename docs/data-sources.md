# Data Sources and ECS Mapping

Version 0.1, 19 Oct 2026. This document lists the 4 data sources of the platform, how each field maps to the Elastic Common Schema (ECS), the capture strategy, and the Elasticsearch index names.

## 1. Overview

| Source | Tool or origin | Main content | Protocol | Index |
|---|---|---|---|---|
| DNS logs | Zeek `dns.log` (Packetbeat as alternative) | queries, answers, record types, response codes | UDP/TCP 53 | `dns-logs-*` |
| Firewall / NetFlow | Zeek `conn.log` in the lab; nfdump or firewall logs if available | flows, bytes, packets, ports | any | `flows-*` |
| DHCP / auth logs | Zeek `dhcp.log` or the lab DHCP server (syslog), auth logs | IP to MAC and host name, logins | UDP 67/68, syslog | `dhcp-*`, `auth-*` |
| Threat-intel feeds | abuse.ch, OpenPhish | known bad domains, URLs and IPs | HTTP download | `ti-indicators` |

**Why `conn.log` as the flow source:** `dns.log` has no packet or byte sizes, but the flood and exfiltration features need bytes per second and response size. Zeek's `conn.log` has them and shares the connection `uid` with `dns.log`, so the two can be joined. A real NetFlow exporter is optional and maps to the same ECS fields.

## 2. Mapping conventions

- ECS 8.x field names. Timestamps in UTC, stored in `@timestamp`.
- Every document has `event.dataset` (for example `zeek.dns`), `event.module`, `event.kind: event`, and `event.category` (`network` for DNS and flows, `authentication` or `network` for the others).
- The raw log line is kept in `event.original`, so nothing is lost if a mapping changes.
- Fields that ECS does not define go under the namespace `dnsplat.*` (for example `dnsplat.dhcp.lease_time`). The Zeek connection `uid` is stored as `zeek.session_id` and is the join key between DNS and flow records.
- Derived DNS fields are created at ingest by an Elasticsearch ingest pipeline (`registered_domain` processor): `dns.question.registered_domain`, `dns.question.top_level_domain`, `dns.question.subdomain`. Detection features use these.
- Zeek must write JSON (`LogAscii::use_json=T`) so that fields are not parsed from tab-separated text.

## 3. Field mappings

### 3.1 DNS logs (Zeek `dns.log`)

| Meaning | ECS field | Zeek `dns.log` field | Note |
|---|---|---|---|
| Timestamp | `@timestamp` | `ts` | epoch seconds to ISO 8601 |
| Client IP | `source.ip` | `id.orig_h` | |
| Client port | `source.port` | `id.orig_p` | |
| DNS server IP | `destination.ip` | `id.resp_h` | |
| DNS server port | `destination.port` | `id.resp_p` | |
| Transport | `network.transport` | `proto` | lowercase `udp` / `tcp` |
| Protocol | `network.protocol` | set to `dns` | |
| Transaction ID | `dns.id` | `trans_id` | |
| Queried domain | `dns.question.name` | `query` | |
| Query class | `dns.question.class` | `qclass_name` | |
| Record type | `dns.question.type` | `qtype_name` | |
| Response code | `dns.response_code` | `rcode_name` | `NOERROR`, `NXDOMAIN`, ... |
| Answers | `dns.answers.data` | `answers` | a list in Zeek |
| TTL | `dns.answers.ttl` | `TTLs` | parallel list to `answers`; the normalizer pairs them one to one |
| Resolved IPs | `dns.resolved_ip` | derived from A/AAAA answers | |
| Header flags | `dns.header_flags` | `AA`, `TC`, `RD`, `RA` | list of flags that are true |
| Connection ID | `zeek.session_id` | `uid` | join key with flows |
| Dataset tag | `event.dataset` | set to `zeek.dns` | |

### 3.2 Firewall / NetFlow (Zeek `conn.log`)

| Meaning | ECS field | Zeek `conn.log` field | Note |
|---|---|---|---|
| Timestamp | `@timestamp` | `ts` | flow start |
| Source IP / port | `source.ip`, `source.port` | `id.orig_h`, `id.orig_p` | |
| Destination IP / port | `destination.ip`, `destination.port` | `id.resp_h`, `id.resp_p` | |
| Transport | `network.transport` | `proto` | |
| Application protocol | `network.protocol` | `service` | |
| Bytes from client | `source.bytes` | `orig_bytes` | |
| Bytes from server | `destination.bytes` | `resp_bytes` | |
| Total bytes | `network.bytes` | `orig_bytes` + `resp_bytes` | computed |
| Total packets | `network.packets` | `orig_pkts` + `resp_pkts` | computed |
| Duration | `event.duration` | `duration` | ECS uses nanoseconds, Zeek uses seconds |
| Connection state | `dnsplat.conn.state` | `conn_state` | custom |
| Connection ID | `zeek.session_id` | `uid` | |
| Dataset tag | `event.dataset` | set to `zeek.connection` | |

If a firewall log or nfdump export is used later, it maps to the same ECS targets (`source.ip`, `destination.ip`, `destination.port`, `network.bytes`, `network.transport`). Only the input column names change.

### 3.3 DHCP and auth logs

| Meaning | ECS field | Zeek `dhcp.log` field | Note |
|---|---|---|---|
| Timestamp | `@timestamp` | `ts` | |
| Client MAC | `client.mac` | `mac` | |
| Assigned IP | `source.ip` | `assigned_addr` | the IP currently leased to the host |
| Host name | `host.name` | `host_name` | |
| DHCP server IP | `server.ip` | `server_addr` | |
| Lease time | `dnsplat.dhcp.lease_time` | `lease_time` | custom |
| Dataset tag | `event.dataset` | set to `zeek.dhcp` | |

The lab DHCP server (libvirt dnsmasq) can also be read from syslog and mapped to the same fields. This table is what allows an alert on an IP to be shown as a host name or MAC.

Auth logs (SSH and login events, optional): `user.name`, `event.action` (for example `login`), `event.outcome` (`success` or `failure`), `source.ip`, `host.name`, dataset `system.auth`.

### 3.4 Threat-intel feeds

| Meaning | ECS field | Feed field | Note |
|---|---|---|---|
| Indicator type | `threat.indicator.type` | by feed | `domain-name`, `ipv4-addr` or `url` |
| Indicator value | `threat.indicator.name` | domain, IP or URL | the value used for matching |
| Domain | `threat.indicator.url.domain` | domain or URL host | for domain and URL indicators |
| IP | `threat.indicator.ip` | IP | for IP indicators |
| Provider | `threat.indicator.provider` | `OpenPhish`, `abuse.ch` | |
| Feed name | `threat.feed.name` | feed identifier | |
| Description | `threat.indicator.description` | malware family or note | |
| First / last seen | `threat.indicator.first_seen`, `threat.indicator.last_seen` | feed date, or download time | |
| Dataset tag | `event.dataset` | set to `ti.<feed>` | |

| Feed | Content | Indicator type |
|---|---|---|
| OpenPhish | phishing URLs | `url` |
| abuse.ch (Feodo Tracker, URLhaus) | botnet C2 IPs, malware URLs | `ipv4-addr`, `url` |

Feed URLs and access rules change, and abuse.ch has been moving some services to free API keys. Check the download script comments before relying on a feed.
The Bambenek feeds (DGA and C2 domains) are no longer public: since 2019 they require a license, and a download returned 403 on 19 Oct 2026. They are not used. The labeled DGA dataset replaces them for training, and they could be added later if a research license is granted.

## 4. Capture mode decision

**Decision: support both live capture and replay.**

- **Live capture:** a Docker lab network with a few client containers, a resolver, and Zeek sniffing the bridge. This is realistic and gives timestamps equal to "now".
- **Replay:** saved pcaps sent through `tcpreplay` onto the lab bridge. The Week 8 demo and the automated tests use replay, so they never depend on live traffic and always give the same result.

**Timestamp rule:** if Zeek reads a pcap file offline (`zeek -r file.pcap`), the log timestamps are the original capture times, so the data lands in the past. For the dashboard demo, replay through `tcpreplay` onto the interface that Zeek is sniffing, so the timestamps are current. Offline reading is only for dataset preparation and feature work.

## 5. Elasticsearch indices

| Index pattern | Content | Notes |
|---|---|---|
| `dns-logs-*` | normalized DNS events | daily indices |
| `flows-*` | normalized flow records | daily indices |
| `dhcp-*` | DHCP leases | small, daily or monthly |
| `auth-*` | login events | optional |
| `ti-indicators` | threat-intel indicators | single index, updated by a loader |
| `features-*` | per-window features per client and domain | written by feature extraction, read by detectors |
| `alerts-*` | alert documents | `Alert.es_alert_id` in PostgreSQL points here |

Retention for the project is simple: keep everything for the 8 weeks, and delete old `dns-logs-*` indices by hand if the disk pool goes over 80%.

## 6. Open points for Week 2

- Confirm whether Filebeat's Zeek module (which applies ECS mapping itself) is enough, or whether a small Python normalizer is needed. The module covers DNS, connection and DHCP logs. The threat-intel loader needs custom code in any case.
- If Filebeat writes to its default data streams, choose between keeping that naming or overriding it to the names above.
- Check the real `dns.log` from the Day 4 sample pcap against the table in 3.1 and fix any field that differs.
