import re


if line.startswith(("0.0.0.0", "127.0.0.1")):
parts = line.split()
if len(parts) < 2:
return None, False
domain = parts[1]
else:
domain = line.replace("||", "").replace("^", "").strip()


if not valid(domain):
return None, False


return aggregate(domain.lower()), white




cfg = yaml.safe_load(CONFIG.read_text())
threshold = cfg.get("threshold", {})
max_inc = threshold.get("max_increase", 0.2)
max_dec = threshold.get("max_decrease", 0.2)


OUT.mkdir(exist_ok=True)
rules = set()


for src in cfg["sources"]:
if not src.get("enabled", True):
continue


print(f"→ {src['name']}")
r = requests.get(src["url"], timeout=30)
r.raise_for_status()


for line in r.text.splitlines():
domain, white = normalize(line)
if not domain:
continue


if domain in GLOBAL_WHITE:
white = True


rule = f"@@||{domain}^" if white else f"||{domain}^"
rules.add(rule)


stats_file = OUT / "stats.json"
old_total = 0
if stats_file.exists():
old_total = json.loads(stats_file.read_text()).get("total", 0)


new_total = len(rules)
delta = new_total - old_total
ratio = delta / old_total if old_total else 0


stats = {
"total": new_total,
"previous": old_total,
"delta": delta,
"ratio": round(ratio, 4)
}


stats_file.write_text(json.dumps(stats, indent=2))


print(f"Rules: {new_total} (Δ {delta}, {ratio:+.2%})")


if old_total > 0:
if ratio > max_inc or ratio < -max_dec:
print("❌ Rule change exceeds threshold")
sys.exit(1)


(OUT / "adguardhome.txt").write_text("\n".join(sorted(rules)) + "\n")


(OUT / "dnsmasq.conf").write_text(
"\n".join(sorted(f"address=/{r[2:-1]}/0.0.0.0" for r in rules if r.startswith("||"))) + "\n"
)


(OUT / "clash.yaml").write_text(
"payload:\n" + "\n".join(f" - '{r[2:-1]}'" for r in sorted(rules) if r.startswith("||")) + "\n"
)


print("✔ Build success")
