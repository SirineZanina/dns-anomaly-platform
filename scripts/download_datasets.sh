#!/usr/bin/env bash
# Download the public datasets used by the DNS Anomaly Detection Platform.
# Run from anywhere inside the VM:  ./scripts/download_datasets.sh
# Datasets stay out of Git (data/ is in .gitignore). This script is the record of where they came from.
#
# Required downloads fail the script. Optional ones only print a warning,
# because feed URLs and access rules change over time.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA="$ROOT/data/datasets"
MANIFEST="$DATA/MANIFEST.txt"

mkdir -p "$DATA"/{benign,dga,threat-intel,cic-bell-dns}

warn() { echo "WARNING: $*" >&2; }
log()  { echo ">> $*"; }

# --- disk check -------------------------------------------------------------
avail_gb=$(df --output=avail -BG "$ROOT" | tail -n 1 | tr -dc '0-9')
log "Free space: ${avail_gb} GB"
if [ "$avail_gb" -lt 5 ]; then
  echo "Less than 5 GB free. Free some space first (docker system df)." >&2
  exit 1
fi

# fetch <url> <output> <required|optional>
fetch() {
  local url="$1" out="$2" mode="$3"
  if [ -s "$out" ]; then
    log "Already present: $out"
    return 0
  fi
  log "Downloading $url"
  if curl -fL -A "Mozilla/5.0" --retry 3 --connect-timeout 20 -o "$out" "$url"; then
    printf '%s\t%s\t%s\n' "$(date -u +%FT%TZ)" "$url" "$out" >> "$MANIFEST"
  else
    rm -f "$out"
    if [ "$mode" = "required" ]; then
      echo "Required download failed: $url" >&2
      exit 1
    fi
    warn "Optional download failed: $url"
  fi
}

# --- 1. Benign baseline: Tranco top 1M --------------------------------------
# The plain URL redirects to the daily list, so curl needs -L.
# If it fails, check https://tranco-list.eu for the current link.
fetch "https://tranco-list.eu/top-1m.csv.zip" "$DATA/benign/top-1m.csv.zip" required
if [ ! -s "$DATA/benign/top-1m.csv" ]; then
  unzip -o "$DATA/benign/top-1m.csv.zip" -d "$DATA/benign/"
  rm -f "$DATA/benign/top-1m.csv.zip"
fi

# --- 2. DGA lists -----------------------------------------------------------
# Bambenek DGA feed (research use; read the license at
# https://osint.bambenekconsulting.com/license.txt). It covers a rolling window of days.
fetch "https://osint.bambenekconsulting.com/feeds/dga-feed.txt" \
      "$DATA/dga/bambenek-dga-feed.txt" optional

# Labeled dataset built from the 360 netlab DGA data (25 DGA families) plus benign domains.
# Reliable fallback, and already balanced for classification. Cite the paper if you publish:
# Cucchiarelli et al., Expert Systems with Applications 170 (2021).
fetch "https://raw.githubusercontent.com/chrmor/DGA_domains_dataset/master/dga_domains_full.csv" \
      "$DATA/dga/dga_domains_full.csv" optional

# Direct 360 netlab feed. The site has changed over time and may be offline.
fetch "https://data.netlab.360.com/feeds/dga/dga.txt" \
      "$DATA/dga/netlab360-dga.txt" optional

# --- 3. Threat-intel feeds (used by the ti-indicators index) -----------------
fetch "https://osint.bambenekconsulting.com/feeds/c2-dommasterlist.txt" \
      "$DATA/threat-intel/bambenek-c2-domains.txt" optional
fetch "https://openphish.com/feed.txt" \
      "$DATA/threat-intel/openphish-feed.txt" optional
# abuse.ch has been moving services to free API keys. If this fails, register at abuse.ch.
fetch "https://feodotracker.abuse.ch/downloads/ipblocklist.txt" \
      "$DATA/threat-intel/feodo-ipblocklist.txt" optional

# --- 4. CIC-Bell-DNS-2021 (manual) ------------------------------------------
# Needs a short request form on the Canadian Institute for Cybersecurity (UNB) site,
# and the files are large. Check the size before downloading, take only the parts you need,
# and place them in data/datasets/cic-bell-dns/.
if [ -z "$(ls -A "$DATA/cic-bell-dns" 2>/dev/null)" ]; then
  warn "CIC-Bell-DNS-2021 not found. Download it manually (see comment in this script)."
fi

echo
log "Done. Contents:"
du -sh "$DATA"/* 2>/dev/null
echo "Manifest: $MANIFEST"
