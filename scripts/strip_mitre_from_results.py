import json
from pathlib import Path

infile = Path("collector/results/20251128/UnstructuredRSSIntel_20251128.ndjson")
backup = infile.with_suffix(".ndjson.bak")
if not infile.exists():
    print(f"Input file not found: {infile}")
    raise SystemExit(1)

backup.write_bytes(infile.read_bytes())
print(f"Backup written to {backup}")

out_lines = []
count = 0
removed = 0
for line in infile.read_text().splitlines():
    line = line.strip()
    if not line:
        continue

    if line.startswith("```") or line.endswith("```"):
        continue
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:

        continue

    th = obj.get("threat")
    if th and isinstance(th, dict):
        technique = th.get("technique")
        if technique and isinstance(technique, dict) and "mitre" in technique:
            del technique["mitre"]
            removed += 1
    out_lines.append(json.dumps(obj, ensure_ascii=False))
    count += 1

out_path = infile
out_path.write_text("\n".join(out_lines) + "\n")
print(
    f"Processed {count} records; removed 'mitre' from {removed} records; wrote {out_path}"
)
