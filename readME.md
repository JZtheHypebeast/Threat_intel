# Threat_intel — Collector and Analysis

Version: 1

This repository contains a lightweight threat-intel collector and processing
pipeline. It supports these flows:

- Structured CVE/KEV collection with vendor cleanup and affected software pulled via a guarded LLM refinement step.
- PDF pipeline — extracts text from PDFs and (optionally) enriches each document via the PDF-specific LLM prompt; outputs NDJSON + Markdown.
- LLM enrichment — fetches RSS articles (rawtext) and then sends them to a local Ollama model (default `llama3.1`), producing cleaned NDJSON/Markdown without embedding full raw text.
- GeoFeed — geopolitical RSS scanner with scoring, watchlists, and optional LLM summaries.
- Reporting — builds a cumulative management report from recent LLM outputs (2/7/14/30 days).

This README explains how to run the collector, expected outputs, testing,
configuration, and useful helper scripts.

## Repository structure

A quick view of the repository layout and important files/folders:

- `readME.md` — this file (usage and configuration guide).
- `requirements.txt` — runtime and dev dependencies.
- `.venv/` — optional virtualenv (not checked in by default).
- `collector/` — main application package; contains the collector and pipeline code, e.g.:
  - `collector/__init__.py`
  - `collector/main.py` — CLI entrypoint and interactive menu.
  - `collector/config.py` — runtime `CONFIG` mapping (all env-vars are defined here).
- `collector/pdf.py` — PDF extraction + optional PDF LLM enrichment.
- `collector/CVE.py` — structured CVE/KEV collection (with LLM refinement of vendor/description/affected software).
- `collector/articles.py` — RSS fetch + rawtext generation + LLM enrichment.
- `collector/geofeed.py` — geopolitical RSS scanner with scoring and LLM summaries.
- `collector/reporting.py` — cumulative reporting over recent LLM outputs.
- `collector/progress.py` and other helpers.
- `collector/logs/` and `collector/results/` — runtime output folders.
- `data/` — static data artifacts used by the collector (PDF samples).
- `scripts/` — helper and maintenance scripts (examples: `sanitize_results.py`, `minify_py.py`).
- `tests/` — pytest unit tests covering extraction, normalization, and writer behavior.

This layout is intentionally simple: application code lives under `collector/`,
data under `data/`, dev scripts under `scripts/`, and tests under `tests/`.
Use this section as a quick reference for where to look when making changes.

## Quick Start

### Ubuntu Server install (collector + Ollama 3.1)

1) Install system dependencies and Python venv:
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git curl
```

2) Clone the repo and set up venv:
```bash
git clone <your-repo-url> threat_intel
cd threat_intel
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

3) Install Ollama and pull llama3.1 (on the server):
```bash
curl -fsSL https://ollama.com/install.sh | sh
sudo systemctl enable --now ollama
# Verify service
curl http://localhost:11434/api/version
# Pull model
ollama pull llama3.1
```

4) Run pipelines:
```bash
# Structured CVE (24h window)
python3 -m collector.main --structured --hours 24

# LLM enrichment (fetches rawtext + runs LLM)
python3 -m collector.main --llm --hours 24

# PDF extraction (defaults to data/PDF)
python3 -m collector.main --unstructured-pdf

# GeoFeed (geopolitical scanner)
python3 -m collector.geofeed --hours 24

# Cumulative reporting (e.g., last 7 days)
python3 -m collector.main --reporting 7
```

Notes:
- Ensure `OLLAMA_HOST` and `OLLAMA_MODEL`/`LLM_MODEL` (default `llama3.1`) are set if the Ollama service is remote or uses a non-default model.
- Results are written under `collector/results/<category>/<YYYYMMDD>/<HHMMSS>/` with categories: `cve/`, `articles/`, `pdf/`, `llmrawtext/`, `llm/`, `reporting/`, and `geofeed/`.

Notes:
- Results are written under `collector/results/<category>/<YYYYMMDD>/<HHMMSS>/`.
  Categories: `cve/`, `articles/`, `pdf/`, `llmrawtext/` (raw articles), `llm/`, and `reporting/`.
- LLM pipeline writes full article bodies to `collector/results/llmrawtext/<date>/<time>/rawtext-<date>.json`
  so enrichment can consume them; NDJSON excludes raw bodies.
- Structured CVE uses an internal LLM refinement per CVE to clean vendor and add affected software; if LLM is disabled the deterministic fields remain.
- PDF pipeline can call the PDF LLM prompt per document; failures fall back to extraction-only output.
- LLM summarization uses a local Ollama instance (`OLLAMA_HOST`, `OLLAMA_MODEL`
  or `LLM_MODEL`, `LLM_ENABLED=true`), default model `llama3.1`, and the configured timeout. If Ollama is not reachable the run logs the failure and moves on.
- The LLM pipeline fetches rawtext for the selected hours, then enriches that same window.

## What the collector does (high level)

- Poll RSS feeds and fetch article HTML/text (parallelized with a thread pool).
- Sanitize and normalize article text (boilerplate removal, dehyphenation).
- LLM pipeline: fetch rawtext, then produce structured intel (summary, MITRE, actors, IOCs, detections, recommendations, etc.) and Markdown.
- Structured CVE: fetch NVD/KEV, normalize CVEs, and optionally refine vendor/description/affected via LLM.
- PDF pipeline: extract text from PDFs and optionally LLM-enrich for management-friendly summaries.
- Reporting: combine recent LLM outputs into a cumulative report (2/7/14/30 days).
- GeoFeed: score and summarize geopolitical signals from RSS feeds.

## CLI flags and menu

Flags (non-interactive):
- `--structured` — run structured CVE/KEV collection.
- `--unstructured-pdf <path>` — run the PDF extraction pipeline on a path (defaults to `data/PDF` if omitted in the menu).
- `--llm` — fetch rawtext + run LLM enrichment for the given hours.
- `--reporting <days>` — build a cumulative LLM-based report over 2/7/14/30 days.
- `--tests` — run unit tests using the active Python interpreter.
- `--hours <N>` — look-back window in hours for RSS items.
- `--no-banner` — suppress ASCII banner at program start.

Interactive menu commands mirror the above:
- `structured` — structured CVE/KEV collection.
- `pdf <PATH>` — run PDF extraction on the given path (defaults to `data/PDF` if omitted).
- `llm` — prompt for hours, fetch rawtext, then run LLM enrichment.
- `reporting` — build cumulative report (prompt for 2/7/14/30 days).
- `tests` — run pytest.
- `all` — structured + llm in sequence.
- `hours <N>` — adjust the default look-back for fetch/structured in the session.

Important note about the interactive menu and `--tests`:
- The interactive menu and the `--tests` CLI flag run pytest using the same
  Python interpreter that launched the collector (for example
  `sys.executable -m pytest`). This ensures tests run consistently inside a
  virtual environment.

## Outputs and file conventions

- `collector/results/llmrawtext/<date>/<time>/rawtext-<date>.json` — raw article bodies
  produced by the LLM pipeline for enrichment.
- `collector/results/cve/<date>/<time>/StructuredCVEData_<date>.ndjson` — structured CVE/KEV NDJSON.
- `collector/results/cve/<date>/<time>/StructuredCVEReport_<date>.md` — structured CVE/KEV Markdown.
- `collector/results/pdf/<date>/<time>/UnstructuredPDFIntel_<date>.ndjson` —
  PDF extraction/enrichment output.
- `collector/results/pdf/<date>/<time>/UnstructuredPDFReport_<date>.md` —
  PDF human-readable Markdown.
- `collector/results/llm/<date>/<time>/LLM-JSON_<date>.ndjson` —
  LLM-enriched NDJSON (pretty-printed; no `raw_text`/`text` fields).
- `collector/results/llm/<date>/<time>/LLM-UnstructuredReport_<date>.md` —
  LLM-enriched Markdown summary.
- `collector/results/cve/<date>/<time>/StructuredCVEReport_<date>.md` —
  structured CVE/KEV Markdown.
- `collector/results/reporting/<date>/<time>/LLM-CumulativeReport_*` —
  cumulative reports (markdown/json/pdf) built from recent LLM outputs.
- `collector/results/geofeed/<date>/<time>/geofeed.ndjson` —
  GeoFeed scored NDJSON.
- `collector/results/geofeed/<date>/<time>/geofeed_summary_<date>.md` —
  GeoFeed summary markdown.

NDJSON records intentionally exclude the full article bodies; they are kept
in `rawtext-<date>.json` to simplify downstream indexing and reduce NDJSON size.

## Configuration (env vars / CONFIG keys)

All runtime configuration is provided via the `CONFIG` mapping in
`collector/config.py`. Common knobs (env var override shown in parentheses):

- `RSS_FEEDS` (`TI_RSS_FEEDS`) — list of RSS feed URLs.
- `VENDORS` (`TI_VENDORS`) — vendor names used for CVE grouping/heuristics.
- Output dirs (auto-set per run): `OUTPUT_DIR_STRUCTURED`, `OUTPUT_DIR_LLM`, `OUTPUT_DIR_LLM_RAW`, `OUTPUT_DIR_PDF`, `OUTPUT_DIR_REPORTING`.
- Logging / UA: `LOG_FILE`, `USER_AGENT` (`TI_USER_AGENT`).
- HTTP: `HTTP_RETRIES_TOTAL`, `HTTP_BACKOFF_FACTOR`, `HTTP_STATUS_FORCELIST`, `HTTP_POOL_CONNECTIONS`, `HTTP_POOL_MAXSIZE`, `REQUEST_TIMEOUT`, `BOILERPLATE_KEYWORDS`, `HTML_STRIP_ELEMENTS`, `ENABLE_UA_ROTATION`, `FALLBACK_USER_AGENTS`.
- CVE feeds: `NVD_API_BASE`, `CISA_KEV_URL`, `COMMUNITY_KEV_URL`, `CVE_REGEX`, `CRITICAL_THRESHOLD`, `INTERESTING_MIN`.
- PDF: `PDF_MAX_PAGES`, `SUMMARY_MAX_SENTENCES`, `SUMMARY_MAX_CHARS`.
- LLM / Ollama: `LLM_ENABLED`, `OLLAMA_HOST`, `LLM_MODEL` (`OLLAMA_MODEL`), `LLM_REQUEST_TIMEOUT`, `LLM_TEMPERATURE`.
- Reporting: `OUTPUT_DIR_REPORTING` for cumulative reports.
- SIEM: `SIEM_ENABLED`, `SIEM_TYPE`, `ELASTIC_*` settings, `SIEM_DRY_RUN`.

Refer to `collector/config.py` for exact defaults and optional keys.

## Tests & development

- Run the full test suite:

```bash
python3 -m pytest -q
```

- Run a single test file or nodeid for faster iteration:

```bash
python3 -m pytest tests/test_pdf_pipeline.py -q
```

The repository includes helper scripts under `scripts/` (see below). The
interactive menu and `--tests` flag use `sys.executable -m pytest` so tests
execute inside the same interpreter/venv that launched the application.

## Helper scripts

- `scripts/sanitize_results.py` — sanitize NDJSON/rawtext files in a results
  directory (for example remove long `text/raw_text/excerpt` fields).
- `scripts/minify_py.py` — (developer) safely remove comments and collapse
  redundant blank lines across `.py` files (useful for shrinking code for
  archival; a backup is recommended before running).

Use these helper scripts for offline maintenance of mapping files or to clean
historical outputs.

## Troubleshooting

- If the collector fails to fetch articles, check HTTP timeouts and
  `TI_USER_AGENT` to ensure the target site does not block requests.
- If MITRE mapping or mitigations appear missing, confirm `TI_MITRE_MAP_FILE`
  and `TI_MITRE_MITIGATIONS_FILE` point to valid JSON artifacts or use the
  built-in defaults in `data/`.
- Use the test suite to validate local edits: `python3 -m pytest -q`.

## Logging

- Log files are now written into a day-specific folder under `collector/logs/<YYYYMMDD>/`.
  The active log file for a run will be:

  `collector/logs/<YYYYMMDD>/threat_intel_collector.log`

- This behavior is configured in `collector/config.py` via `CONFIG['LOG_FILE']`.
- CLI shows per-entry progress (`entry X/Y`) and elapsed time per article; the
  same timing is emitted to logs to trace long-running steps (fetching, parsing,
  LLM enrichment).
- Alternatives:
  - Use a `TimedRotatingFileHandler` or `RotatingFileHandler` (in `logging.handlers`) if you prefer
    automatic rotation/compression inside a single `logs/` directory. I can add this option if you want.
  - To change the path or naming scheme, update `CONFIG['LOG_FILE']` or set `TI_OUTPUT_DIR`/logging env vars as needed.

Refer to `collector/config.py` for implementation details and to customize behavior.

---

Developer and backup artifacts (older backups) were previously stored under
the `backups/` folder. Keep a fresh backup before running any mass-edit
operations (for example before using `scripts/minify_py.py`).
