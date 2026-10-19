# Threat Catalogue: DNS Anomaly Detection Platform

Version 0.1, 18 Oct 2026. This document states which attacks the platform detects, how each one appears in DNS traffic, and how it will be generated and tested in the lab.

All thresholds below are **starting points**. They will be tuned in Weeks 3 and 4 against the real datasets and lab traffic.

## Overview

| #   | Threat                       | `alert_type`        | Priority | Default severity | Main approach               |
| --- | ---------------------------- | ------------------- | -------- | ---------------- | --------------------------- |
| 1   | DNS tunneling                | `dns_tunneling`     | MVP      | high             | rule + ML                   |
| 2   | DGA / botnet domains         | `dga`               | MVP      | high             | supervised ML + rule        |
| 3   | DNS flooding / amplification | `dns_flood`         | MVP      | high             | rule + statistical baseline |
| 4   | Data exfiltration            | `data_exfiltration` | Stretch  | high             | rule + unsupervised ML      |
| 5   | Fast-flux                    | `fast_flux`         | Stretch  | medium           | rule + threat intel         |
| 6   | NXDOMAIN storm               | `nxdomain_storm`    | Stretch  | medium           | rule                        |

The `alert_type` column gives the values of the `AlertType` enumeration used by the `Alert` class and the `alerts` table. Severity values are `low`, `medium`, `high`.

---

## 1. DNS tunneling

- **Priority:** MVP
- **What it is:** An attacker encodes data (a shell session, a file, a C2 channel) inside DNS queries and answers, so it passes through a firewall that allows port 53. The attacker controls the authoritative server for the domain and reads the encoded subdomains.
- **How it looks in DNS:**
  - Very long query names, often close to the 253-character limit, with labels near the 63-character limit.
  - Random-looking, high-entropy subdomains (base32, base64 or hex encoding).
  - Unusual record types: TXT, NULL, CNAME, MX, sometimes PRIVATE.
  - Very many unique subdomains under a single parent domain, rarely or never repeated.
  - Large answers, and a steady, regular query rhythm to one domain.
- **Features that expose it:**
  - Per query: total name length, longest label length, label count (subdomain depth), Shannon entropy of the subdomain, digit ratio, record type, response size.
  - Per client and window (e.g. 1 and 5 minutes): unique subdomains per parent domain, queries per parent domain, share of TXT/NULL/CNAME, mean and maximum query length, average response size.
- **Detection approach:**
  - Rule: length above a threshold AND entropy above a threshold AND an unusual record type, as a fast baseline.
  - Unsupervised ML: Isolation Forest on the per-window features, for tunnels not seen in training.
  - Supervised ML: Random Forest or gradient boosting on labeled tunneling versus benign data.
- **How I will generate it:** `iodine` and `dnscat2` between two lab containers or VMs, with a domain delegated to a lab authoritative server; public tunneling pcaps as additional labeled data. Replay with `tcpreplay`.
- **Likely false positives:**
  - CDN and cloud hostnames with long generated names.
  - Email security lookups (DNSBL, SPF, DKIM TXT records).
  - Antivirus and endpoint-security cloud lookups that encode hashes in the name.
  - Service discovery and some telemetry agents.
  - Mitigation: whitelist known parent domains, and require several signals together (rate AND entropy AND type).
- **Severity:** high

---

## 2. DGA / botnet domains

- **Priority:** MVP
- **What it is:** Malware uses a Domain Generation Algorithm to produce many pseudo-random domain names each day and tries them to find its live C2 server. Defenders cannot block a fixed list, because the domains keep changing.
- **How it looks in DNS:**
  - Random-looking second-level domains with no dictionary words (e.g. consonant-heavy strings).
  - A client trying many different, never-seen domains in a short time.
  - A high share of NXDOMAIN, because almost all generated domains are not registered.
  - Occasional uncommon TLDs, and bursts at regular intervals.
- **Features that expose it:**
  - Per domain: length, Shannon entropy, digit ratio, consonant ratio, vowel ratio, longest consonant run, character n-gram (bigram/trigram) score against a benign reference, TLD.
  - Per client and window: NXDOMAIN ratio, number of distinct second-level domains, number of domains never seen before for this client.
- **Detection approach:**
  - Supervised ML (main): Random Forest or XGBoost on the lexical features, trained on DGA lists versus benign domains.
  - Rule: NXDOMAIN ratio and distinct-domain count above a threshold in a window, to catch a client behaving like infected.
  - Optional later: a character-level model (LSTM/CNN) as comparison in the evaluation report.
- **How I will generate it:** The labeled DGA dataset built from 360 netlab data (DGA and legitimate domains) plus Tranco top-1M as benign. For live tests, a small script that queries generated names through the lab resolver, so Zeek logs real `NXDOMAIN` responses.
- **Likely false positives:**
  - Browsers that send random single-label probe queries at startup (for example Chromium's DNS-hijack check).
  - Hash-based or machine-generated hostnames (CDNs, cloud storage, mail tracking links).
  - Typos and mistyped domains.
  - Internationalized domains in punycode (`xn--...`).
  - Weakness: dictionary-based DGAs (words joined together) have low entropy, so lexical features alone will miss some of them. Mention this in the evaluation report.
- **Severity:** high (a DGA hit usually means an infected host)

---

## 3. DNS flooding / amplification

- **Priority:** MVP
- **What it is:** A denial-of-service attack made of DNS traffic. In a flood, one or many clients send a very high rate of queries to exhaust the server. In an amplification attack, the attacker spoofs the victim's IP and sends small queries (often `ANY` or large TXT) to open resolvers, which send much larger answers to the victim. A related variant is the random-subdomain attack ("water torture") against an authoritative server.
- **How it looks in DNS:**
  - A very high query rate from one client, or toward one server, compared with its baseline.
  - Repeated `ANY` or large-response queries, and a large response-to-request size ratio.
  - Many responses leaving toward an IP that never asked (spoofed source).
  - Random subdomains of one domain with a high NXDOMAIN share.
  - Unusual UDP versus TCP mix and a spike in bytes per second.
- **Features that expose it:**
  - Per client and per server, per window (e.g. 10 seconds and 1 minute): queries per second, bytes per second, UDP/TCP ratio, share of `ANY`/TXT queries, response-to-request size ratio, distinct source IPs per server, NXDOMAIN ratio.
- **Detection approach:**
  - Rule: a fixed threshold on query rate per client and per server, as a first line.
  - Statistical baseline: compare the current window to a rolling mean and standard deviation (z-score) for each client, so a normally busy client does not trigger.
  - Optional ML: Isolation Forest on the rate and volume features.
- **How I will generate it:** `hping3` (UDP to port 53) and `scapy` scripts for crafted queries (`ANY`, large TXT), run only between lab machines in the isolated network. Short pcaps saved for replay.
- **Likely false positives:**
  - A cache warm-up after a resolver restart.
  - A busy client behind NAT (an office, a shared Wi-Fi) that looks like one very active IP.
  - Monitoring, backup or mail servers doing many lookups.
  - A web page that loads dozens of third-party domains at once.
  - Mitigation: per-client baselines instead of one global threshold, and a whitelist for known heavy resolvers.
- **Severity:** high (service availability)

---

## 4. Data exfiltration over DNS

- **Priority:** Stretch
- **What it is:** Stolen data is split, encoded and sent out as subdomains of an attacker-controlled domain. It overlaps with tunneling, but the traffic is mostly one-way (outbound) and focused on moving data, not on keeping an interactive channel.
- **How it looks in DNS:**
  - A steady stream of encoded subdomains to one domain, often with regular timing.
  - A large total volume of query bytes sent to one parent domain.
  - High-entropy labels of similar length, TXT queries, and few repeated names.
- **Features that expose it:**
  - Per client and parent domain, per window: bytes sent in query names, unique subdomains, TXT ratio, entropy of labels, regularity of the inter-arrival time.
- **Detection approach:** rule on bytes per parent domain per window combined with entropy, plus Isolation Forest on the per-domain volume features. Correlation with NetFlow is described below.
- **How I will generate it:** a small Python or `scapy` script that reads a file, encodes it in base32, splits it into labels, and sends the queries to a lab domain.
- **Likely false positives:** cloud backup and sync agents, telemetry and update services, email servers doing many DNSBL lookups.
- **Severity:** high

---

## 5. Fast-flux

- **Priority:** Stretch
- **What it is:** A domain whose DNS records change very often, resolving to a large and rotating set of IP addresses (usually compromised hosts) with a very short TTL. It hides the real C2 or phishing server behind a changing proxy network.
- **How it looks in DNS:**
  - Very low TTL (for example 300 seconds or less).
  - Many distinct IP addresses in the answers, and a high number of unique IPs for one domain over time.
  - High IP churn between queries, often across many networks.
- **Features that expose it:**
  - Per domain, per window: minimum and mean TTL, number of A/AAAA records per answer, unique IPs over the window, unique /24 networks, IP churn rate.
  - Optional: number of distinct ASNs, if a GeoIP/ASN database is added.
- **Detection approach:** rule on low TTL AND high unique-IP count; match against threat-intelligence feeds (abuse.ch and similar) for known fast-flux domains.
- **How I will generate it:** synthetic Zeek-style log records with low TTLs and rotating IPs, plus real domains from threat-intel feeds. Real fast-flux traffic is hard to reproduce safely in the lab.
- **Likely false positives:** CDNs (Akamai, Cloudflare), DNS-based load balancing, large cloud services that use short TTLs legitimately. Mitigation: whitelist known CDN domains.
- **Severity:** medium

---

## 6. NXDOMAIN storm

- **Priority:** Stretch
- **What it is:** A sudden burst of failed lookups (`NXDOMAIN`) from one client or toward one server. It can come from DGA malware, a scanner probing for subdomains, a random-subdomain attack, or simply a broken application.
- **How it looks in DNS:**
  - A sharp increase in `NXDOMAIN` responses for one client in a short window.
  - A high NXDOMAIN ratio and a high count of distinct failed names.
- **Features that expose it:** per client and window (e.g. 1 minute): NXDOMAIN count, NXDOMAIN ratio, distinct failed domains, share of failed names under one parent domain.
- **Detection approach:** rule: NXDOMAIN ratio above a threshold AND count above a minimum, so a few typos do not alert. It also serves as an input feature for the DGA detector.
- **How I will generate it:** the DGA generator script from section 2, or a simple loop of `dig` queries for random non-existent names.
- **Likely false positives:**
  - A misconfigured client or stale search-domain suffix.
  - An application polling a dead domain. This case repeats the **same** name, so require many distinct failed names to tell it from a real storm.
  - Browser startup probes.
- **Severity:** medium

---

## Correlation example

Single signals are weak, but together they form a high-confidence incident. Example:

1. Client `192.168.122.60` sends many high-entropy DNS queries to `x7f2k9.evil-example.net` (DNS source, tunneling or exfiltration rule).
2. In the same time window, the firewall/NetFlow source shows a large outbound transfer from the same client to the same destination IP (flow source).
3. The domain appears in a threat-intelligence feed (threat-intel source).

Three independent sources agree, so the correlation engine (Week 5) raises **one incident of high severity** with the three alerts attached through `incident_id`, instead of three separate low-confidence alerts.

## Out of scope for the MVP

- DNS cache poisoning, DNS hijacking and DNSSEC validation attacks.
- Encrypted DNS (DoH/DoT). The platform sees only plain DNS on port 53, so traffic that bypasses the resolver through DoH is a known blind spot. Record it as a limitation in the final documentation.
- Attribution of the attacker or any active blocking. The platform only detects and alerts.
