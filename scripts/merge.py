# merge.py
# Adgh Rules Engine - Stable CI Version
# 功能：
# - 多上游规则整合（hosts / adblock）
# - 去重 + AdGuardHome 统一格式
# - 二级域名聚合（支持白名单）
# - 全局白名单
# - 规则数量统计 + 阈值失败 CI
# - 输出多格式（AdGuardHome / dnsmasq / Clash）

import re
import json
import yaml
import sys
import requests
from pathlib import Path

# ================= 基础路径 =================
BASE = Path(__file__).resolve().parents[1]
CONFIG = BASE / "config/sources.yaml"
WHITELIST = BASE / "config/whitelist.txt"
AGG_WHITELIST = BASE / "config/aggregate_whitelist.txt"
OUT = BASE / "output"

# ================= 正则与常量 =================
DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$",
    re.I
)

KNOWN_2LD = {
    "co.uk", "org.uk", "gov.uk",
    "com.cn", "net.cn", "org.cn"
}

# ================= 工具函数 =================

def is_valid(domain: str) -> bool:
    return DOMAIN_RE.match(domain) is not None


def load_set(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return {
        d.strip().lower()
        for d in path.read_text(encoding="utf-8").splitlines()
        if is_valid(d.strip())
    }


AGG_WHITE = load_set(AGG_WHITELIST)
GLOBAL_WHITE = load_set(WHITELIST)


def aggregate_domain(domain: str) -> str | None:
    """二级域名聚合（支持白名单）"""
    if domain in AGG_WHITE:
        return domain

    parts = domain.split('.')
    if len(parts) < 2:
        return None

    last_two = '.'.join(parts[-2:])
    last_three = '.'.join(parts[-3:])

    if last_two in KNOWN_2LD and len(parts) >= 3:
        return last_three
    return last_two


def normalize_line(line: str):
    """解析并标准化规则行"""
    line = line.strip()
    if not line or line.startswith(("#", "!", "[")):
        return None, False

    whitelist = False
    if line.startswith("@@"):
        whitelist = True
        line = line[2:].strip()

    # hosts 格式
    if line.startswith(("0.0.0.0", "127.0.0.1")):
        parts = line.split()
        if len(parts) < 2:
            return None, False
        domain = parts[1]
    else:
        # adblock 格式
        domain = line.replace("||", "").replace("^", "").strip()

    if not is_valid(domain):
        return None, False

    return aggregate_domain(domain.lower()), whitelist


# ================= 主流程 =================

def main():
    OUT.mkdir(exist_ok=True)

    cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    threshold = cfg.get("threshold", {})
    max_inc = threshold.get("max_increase", 0.2)
    max_dec = threshold.get("max_decrease", 0.2)

    rules: set[str] = set()

    for src in cfg.get("sources", []):
        if not src.get("enabled", True):
            continue

        name = src.get("name", "unknown")
        url = src.get("url")
        if not url:
            continue

        print(f"→ Fetching [{name}] {url}")
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()

        for line in resp.text.splitlines():
            domain, is_white = normalize_line(line)
            if not domain:
                continue

            if domain in GLOBAL_WHITE:
                is_white = True

            rule = f"@@||{domain}^" if is_white else f"||{domain}^"
            rules.add(rule)

    # ================= 统计 =================
    stats_file = OUT / "stats.json"
    old_total = 0
    if stats_file.exists():
        old_total = json.loads(stats_file.read_text()).get("total", 0)

    new_total = len(rules)
    delta = new_total - old_total
    ratio = (delta / old_total) if old_total else 0

    stats = {
        "total": new_total,
        "previous": old_total,
        "delta": delta,
        "ratio": round(ratio, 4)
    }

    stats_file.write_text(json.dumps(stats, indent=2), encoding="utf-8")

    print(f"Rules: {new_total} (Δ {delta}, {ratio:+.2%})")

    # ================= 阈值保护 =================
    force_pass = str(os.getenv("FORCE_PASS", "false")).lower() == "true"

    if old_total > 0 and not force_pass:
        if ratio > max_inc or ratio < -max_dec:
            print("❌ Rule change exceeds threshold, build failed")
            sys.exit(1)

    # ================= 输出 =================
    (OUT / "adguardhome.txt").write_text(
        "\n".join(sorted(rules)) + "\n",
        encoding="utf-8"
    )

    (OUT / "dnsmasq.conf").write_text(
        "\n".join(
            sorted(
                f"address=/{r[2:-1]}/0.0.0.0"
                for r in rules
