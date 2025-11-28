# Threat_intel — Collector and Analysis

Version: 1

This repository contains a lightweight threat-intel collector and processing
pipeline. It supports two collection flows:

- Structured CVE/KEV collection (CVE feeds and known exploited vulnerabilities).
- Unstructured RSS/article pipeline — fetches articles from RSS feeds,
  extracts indicators (IOCs), infers MITRE ATT&CK techniques, computes
  relevance/priority scores, and writes sanitized NDJSON + Markdown reports.

This README explains how to run the collector, expected outputs, testing,
configuration, and useful helper scripts.

## Quick Start

- Create and activate a Python virtual environment and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

- Run only the unstructured RSS pipeline for the last 28 hours:

```bash
python3 -m collector.main --unstructured --hours 28
```

- Run the structured + unstructured pipelines together for 24 hours:

```bash
python3 -m collector.main --structured --unstructured --hours 24
```

Notes:
- Results are written under `collector/results/<YYYYMMDD>/` by default.
- Full article bodies are written into `rawtext-<date>.json` (kept separate
  from NDJSON to avoid embedding long text directly in the NDJSON records).

## What the collector does (high level)

- Poll RSS feeds and fetch article HTML/text (parallelized with a thread pool).
- Sanitize and normalize article text (boilerplate removal, dehyphenation).
- Extract IOCs (IPs, domains, URLs, hashes, emails) via regex patterns.
- Match keywords and phrase maps to infer MITRE ATT&CK techniques and produce
  `threat.technique` and `threat.technique_mitigations` entries.
- Compute relevance and MITRE-based priority scores.
- Produce a sanitized NDJSON file, a `rawtext` JSON file with full bodies, and
  a Markdown report aggregation for human review.

## CLI flags (common)

- `--structured` — run structured CVE/KEV collection.
- `--unstructured` — run unstructured RSS/article pipeline.
- `--unstructured-pdf <path>` — run the PDF extraction pipeline on a path.
- `--llm` — run LLM rawtext translation pipeline (if enabled).
- `--tests` — run unit tests using the active Python interpreter.
- `--hours <N>` — look-back window in hours for RSS items.
- `--no-banner` — suppress ASCII banner at program start.

Run `python3 -m collector.main -h` to view all flags and help text.

Important note about the interactive menu and `--tests`:
- The interactive menu and the `--tests` CLI flag run pytest using the same
  Python interpreter that launched the collector (for example
  `sys.executable -m pytest`). This ensures tests run consistently inside a
  virtual environment.

## Outputs and file conventions

- `UnstructuredRSSIntel_<date>.ndjson` — sanitized NDJSON output. Each line is
  a JSON object with fields such as `id`, `source`, `title`, `@timestamp`,
  `threat` (including `technique` names/IDs and `technique_mitigations`),
  `iocs`, and `provenance`.
- `rawtext-<date>.json` — array of objects containing full article text and
  metadata (full extracted article bodies).
- `UnstructuredRSSReport_<date>.md` — human-readable Markdown report for
  quick review and triage.

NDJSON records intentionally exclude the full article bodies; they are kept
in `rawtext-<date>.json` to simplify downstream indexing and reduce NDJSON size.

## Configuration (env vars / CONFIG keys)

All runtime configuration is provided via the `CONFIG` mapping in
`collector/config.py`. Most values may be overridden using environment
variables (often prefixed with `TI_`). Examples of commonly used env vars:

- `TI_RSS_FEEDS` (CONFIG[`RSS_FEEDS`]) — Comma-separated list or JSON array
  of RSS feed URLs to ingest.
- `TI_OUTPUT_DIR` (CONFIG[`OUTPUT_DIR`]) — Output directory (defaults to
  `collector/results`).
- `TI_USER_AGENT` (CONFIG[`USER_AGENT`]) — HTTP User-Agent used for requests.
- `TI_MAX_WORKERS` (CONFIG[`MAX_WORKERS`]) — Thread pool size for fetching.
- `TI_PATTERNS_FILE`, `TI_MITRE_MAP_FILE`, `TI_MITRE_MITIGATIONS_FILE` — Files
  used for pattern matching and MITRE enrichment.

Refer to `collector/config.py` for the full `CONFIG` mapping and more
environment variables that control extraction, scoring, and delivery.

## Tests & development

- Run the full test suite:

```bash
python3 -m pytest -q
```

- Run a single test file or nodeid for faster iteration:

```bash
python3 -m pytest tests/test_unstructured.py -q
python3 -m pytest tests/test_unstructured.py::TestUnstructuredExtraction::test_short_nav_reject -q
```

The repository includes helper scripts under `scripts/` (see below). The
interactive menu and `--tests` flag use `sys.executable -m pytest` so tests
execute inside the same interpreter/venv that launched the application.

## Helper scripts

- `scripts/sanitize_results.py` — sanitize NDJSON/rawtext files in a results
  directory (for example remove long `text/raw_text/excerpt` fields).
- `scripts/build_mitre_map.py`, `scripts/build_mitre_mitigations.py` — create
  or transform MITRE mapping artifacts under `data/`.
- `scripts/minify_py.py` — (developer) safely remove comments and collapse
  redundant blank lines across `.py` files (useful for shrinking code for
  archival; a backup is recommended before running).
- `scripts/strip_mitre_from_results.py` — ad-hoc utility to remove legacy
  `mitre` classifier fields from historical NDJSON outputs.

Use these helper scripts for offline maintenance of mapping files or to clean
historical outputs.

## Troubleshooting

- If the collector fails to fetch articles, check HTTP timeouts and
  `TI_USER_AGENT` to ensure the target site does not block requests.
- If MITRE mapping or mitigations appear missing, confirm `TI_MITRE_MAP_FILE`
  and `TI_MITRE_MITIGATIONS_FILE` point to valid JSON artifacts or use the
  built-in defaults in `data/`.
- Use the test suite to validate local edits: `python3 -m pytest -q`.

---

Developer and backup artifacts (older backups) were previously stored under
the `backups/` folder. Keep a fresh backup before running any mass-edit
operations (for example before using `scripts/minify_py.py`).