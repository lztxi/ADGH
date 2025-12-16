#!/usr/bin/env python3
# merge.py – SAFE VERSION (keep upstream whitelist for AdGuardHome only)

import re
import json
import sys
import os
import yaml
import requests
from pathlib import Path

# ================= Paths =================
BASE = Path(__file__).resolve().parents[1]

out_dir = os.getenv("OUTPUT_DIR")
if out_dir:
    OUT = Path(out_dir).resolve()
else:
    OUT = BASE / "output"

CFG = BASE / "config/sources.yaml"
OUT.mkdir(parents=True, exist_ok=True)

# ================= Regex =================
DOMAIN_RE = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$", re.I)


# ================= Parser =================
def parse_line(line: str):
    line = line.strip()

    if not line or line.startswith(("#", "!", "[")):
        return None, None

    is_whitelist = False
    if line.startswith("@@"):
        is_whitelist = True
        line = line[2:]

    # hosts format
    if line.startswith(("0.0.0.0", "127.0.0.1")):
        parts = line.split()
        if len(parts) < 2:
            return None, None
        domain = parts[1]
    else:
        domain = line.replace("||", "").replace("^", "").strip()

    if not DOMAIN_RE.match(domain):
        return None, None

    return domain.lower(), is_whitelist


# ================= Main =================
block_rules: set[str] = set()
white_rules: set[str] = set()

cfg = yaml.safe_load(CFG.read_text(encoding="utf-8"))

for src in cfg.get("sources", []):
    if not src.get("enabled", True):
        continue

    resp = requests.get(src["url"], timeout=30)
    resp.raise_for_status()

    for raw in resp.text.splitlines():
        domain, is_white = parse_line(raw)
        if not domain:
            continue

        if is_white:
            white_rules.add(f"@@||{domain}^")
        else:
            block_rules.add(f"||{domain}^")

# ================= Stats =================
stats_file = OUT / "stats.json"
old_total = 0
if stats_file.exists():
    old_total = json.loads(stats_file.read_text()).get("total", 0)

new_total = len(block_rules)
delta = new_total - old_total
ratio = (delta / old_total) if old_total else 0

stats = {
    "total": new_total,
    "previous": old_total,
    "delta": delta,
    "ratio": round(ratio, 4),
}

stats_file.write_text(json.dumps(stats, indent=2), encoding="utf-8")

# ================= Threshold =================
threshold = cfg.get("threshold", {})
max_inc = threshold.get("max_increase", 0.2)
max_dec = threshold.get("max_decrease", 0.2)
force = os.getenv("FORCE_PASS", "false").lower() == "true"

if old_total and not force:
    if ratio > max_inc or ratio < -max_dec:
        print("❌ Rule change exceeds threshold")
        sys.exit(1)

# ================= Output =================

# AdGuardHome（包含白名单）
(OUT / "adguardhome.txt").write_text(
    "\n".join(sorted(white_rules | block_rules)) + "\n",
    encoding="utf-8",
)

# dnsmasq（仅阻断）
(OUT / "dnsmasq.conf").write_text(
    "\n".join(
        f"address=/{r[2:-1]}/0.0.0.0"
        for r in sorted(block_rules)
    ) + "\n",
    encoding="utf-8",
)

# Clash（仅阻断）
(OUT / "clash.yaml").write_text(
    "payload:\n"
    + "\n".join(f"  - '{r[2:-1]}'" for r in sorted(block_rules))
    + "\n",
    encoding="utf-8",
)

print(
    f"✔ Build success | block={len(block_rules)} whitelist={len(white_rules)}"
)
