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
- `requirements.txt` — runtime dependencies.
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

### Prereqs

- Python 3.10+ (uses `str | None` type hints).
- `pip`, `venv`, `git`.
- Optional: Ollama for LLM enrichment. ReportLab is used for PDF outputs (installed via `requirements.txt`).

### Ubuntu Server install (collector + Ollama)

This is a step-by-step setup for a Ubuntu server so Ollama runs on boot and the
collector can use the local LLM.

1) Install system dependencies and Python 3.10+:
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git curl
python3 --version
```

2) Clone the repo:
```bash
git clone <your-repo-url> threat_intel
cd threat_intel
```

3) Create and activate a virtual environment:
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
```

4) Install Python dependencies:
```bash
pip install -r requirements.txt
```

5) Install Ollama and enable it on boot (systemd):
```bash
curl -fsSL https://ollama.com/install.sh | sh
sudo systemctl enable --now ollama
sudo systemctl status ollama --no-pager
```

6) Pull the model used by this repo (default):
```bash
ollama pull llama3.1
```

7) Verify Ollama is reachable:
```bash
curl http://localhost:11434/api/version
```

8) (Optional) Make Ollama reachable from other hosts:
```bash
sudo mkdir -p /etc/systemd/system/ollama.service.d
sudo tee /etc/systemd/system/ollama.service.d/override.conf >/dev/null <<'EOF'
[Service]
Environment=OLLAMA_HOST=0.0.0.0:11434
EOF
sudo systemctl daemon-reload
sudo systemctl restart ollama
```

9) Run pipelines:
```bash
# Interactive menu
python3 -m collector.main

# Structured CVE (24h window)
python3 -m collector.main --cve --hours 24

# LLM enrichment (fetches rawtext + runs LLM)
python3 -m collector.main --articles --hours 24

# PDF extraction (interactive menu defaults to data/PDF)
python3 -m collector.main --unstructured-pdf data/PDF

# GeoFeed (geopolitical scanner)
python3 -m collector.main --geofeed --hours 24

# Cumulative reporting (e.g., last 7 days)
python3 -m collector.main --reporting 7
```

Notes:
- If you expose Ollama on the network, restrict access via firewall rules or a reverse proxy.
- Ensure `OLLAMA_HOST` and `OLLAMA_MODEL`/`LLM_MODEL` (default `llama3.1`) are set if the Ollama service is remote or uses a non-default model.
- For best PDF extraction, PyMuPDF (`fitz`) is used; if it is unavailable the pipeline falls back to `pypdf` with lower fidelity.
- PDF outputs (CVE report, reporting, GeoFeed `--pdf`) require ReportLab; it is included in `requirements.txt`.
- Results are written under `collector/results/<category>/<YYYYMMDD>/<HHMMSS>/` with categories: `cve/`, `articles/`, `pdf/`, `llmrawtext/`, `llm/`, `reporting/`, and `geofeed/`.
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
- `--cve` — run structured CVE/KEV collection.
- `--articles` — fetch RSS articles + run LLM enrichment.
- `--geofeed` — run the GeoFeed geopolitical scanner (requires `collector/geofeed.py`).
- `--geofeed-compare {latest,2d,7d}` — add a comparison section to GeoFeed output.
- `--unstructured-pdf <path>` — run the PDF extraction pipeline on a path.
- `--reporting <days>` — build a cumulative LLM-based report over 2/7/14/30 days.
- `--tests` — run unit tests using the active Python interpreter.
- `--hours <N>` — look-back window in hours for RSS items.
- `--no-banner` — suppress ASCII banner at program start.
- `--no-history` — placeholder (currently does not change CVE behavior).

Interactive menu commands mirror the above:
- `cve` — structured CVE/KEV collection.
- `articles` — prompt for hours, fetch rawtext, then run LLM enrichment.
- `geofeed` — run GeoFeed (prompt for hours; PDF rendering prompt).
- `pdf` — run PDF extraction on `data/PDF` by default.
- `reporting` — build cumulative report (prompt for 2/7/14/30 days).
- `tests` — run pytest.
- `all` — CVE + articles in sequence.
- `hours <N>` — adjust the default look-back for fetch/structured in the session.

Important note about the interactive menu and `--tests`:
- The interactive menu and the `--tests` CLI flag run pytest using the same
  Python interpreter that launched the collector (for example
  `sys.executable -m pytest`). This ensures tests run consistently inside a
  virtual environment.

GeoFeed standalone CLI (extra options):
- `python3 -m collector.geofeed --hours 24 --pdf --compare latest`
- Flags: `--outdir`, `--results-root`, `--timeout`, `--max-items`, `--pdf`, `--compare {latest,2d,7d}`
  - To force LLM-driven comparisons, set `GEOFEED_COMPARE_USE_LLM=1` (otherwise a deterministic summary is used).

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
- `collector/results/reporting/<date>/<time>/ManagementReport_<Nd>_<date>.*` —
  cumulative reports (markdown/json/pdf) built from recent LLM outputs.
- `collector/results/geofeed/<date>/<time>/geofeed_summary_<date>.md` —
  GeoFeed summary markdown.
- `collector/results/geofeed/<date>/<time>/geofeed_summary_<date>.json` —
  GeoFeed summary JSON (used for comparisons).
- `collector/results/geofeed/<date>/<time>/rawtext4geofeed_<date>.jsonl` —
  GeoFeed rawtext inputs (JSON lines).
- `collector/results/geofeed/<date>/<time>/geofeed_llm_failures_<date>.jsonl` —
  GeoFeed LLM failures (JSON lines).
- `collector/results/geofeed/<date>/<time>/geofeed_comparison_failures_<date>.jsonl` —
  GeoFeed comparison failures (JSON lines).

NDJSON records intentionally exclude the full article bodies; they are kept
in `rawtext-<date>.json` to simplify downstream indexing and reduce NDJSON size.

## Configuration

All runtime configuration is provided via the `CONFIG` mapping in
`collector/config.py`. Most settings can be overridden via environment
variables (usually prefixed `TI_`). JSON strings are required for lists/objects.
Changes take effect on the next run.

Example overrides:
```bash
export TI_RSS_FEEDS='["https://example.com/rss"]'
export TI_LLM_ENABLED=false
export TI_HTTP_STATUS_FORCELIST='[429,500,502,503]'
```

### Core inputs (RSS/CVE)
- `TI_RSS_FEEDS` (`RSS_FEEDS`) — JSON list of RSS feeds used by articles and CVE RSS.
- `TI_VENDORS` (`VENDORS`) — JSON list of vendor names used for CVE grouping.
- `TI_EXCLUDED_SOFTWARE` (`EXCLUDED_SOFTWARE`) — JSON list of software names to ignore in CVE parsing.
- `TI_NVD_API_BASE` (`NVD_API_BASE`) — NVD CVE API base URL.
- `TI_CISA_KEV_URL` (`CISA_KEV_URL`) — CISA KEV feed URL.
- `TI_COMMUNITY_KEV_URL` (`COMMUNITY_KEV_URL`) — community KEV feed URL.
- `TI_CVE_REGEX` (`CVE_REGEX`) — regex for CVE detection in text.

### Output paths and logging
- `LOG_FILE` (CONFIG only) — log file path; set in `collector/config.py`.
- `OUTPUT_DIR_STRUCTURED`, `OUTPUT_DIR_UNSTRUCTURED`, `OUTPUT_DIR_LLM`,
  `OUTPUT_DIR_LLM_RAW`, `OUTPUT_DIR_REPORTING`, `OUTPUT_DIR_PDF` (CONFIG only) — output directories per run.
- `TI_RESULTS_ROOT` — GeoFeed results root for `collector.geofeed` (overridable via `--results-root`).
- `COLLECTOR_NO_BANNER` — set to `true`/`1` to suppress the ASCII banner.

### HTTP fetch, parsing, and sanitization
- `TI_USER_AGENT` (`USER_AGENT`) — User-Agent for NVD/KEV and as a fallback for article fetching.
- `HTTP_USER_AGENT` (CONFIG only) — overrides the User-Agent used by the article fetcher.
- `TI_REQUEST_TIMEOUT` (`REQUEST_TIMEOUT`) — default HTTP timeout (seconds).
- `HTTP_CONNECT_TIMEOUT`, `HTTP_READ_TIMEOUT` (CONFIG only) — connect/read timeouts for article fetches.
- `HTTP_MAX_CONTENT_LENGTH` (CONFIG only) — max bytes to read per article.
- `TI_HTTP_RETRIES_TOTAL`, `TI_HTTP_BACKOFF_FACTOR`, `TI_HTTP_STATUS_FORCELIST`,
  `TI_HTTP_POOL_CONNECTIONS`, `TI_HTTP_POOL_MAXSIZE` — retry and pooling controls.
- `TI_INCLUDE_ENTRIES_WITHOUT_DATE` — include RSS items without a published date.
- `TI_BOILERPLATE_KEYWORDS` — JSON list of keywords to strip from fetched text.
- `PROXIES` (CONFIG only) — requests proxy mapping for article fetches.

### LLM / Ollama
- `TI_LLM_ENABLED` (`LLM_ENABLED`) — enable/disable LLM calls.
- `TI_OLLAMA_HOST` (`OLLAMA_HOST`) or `OLLAMA_HOST` — Ollama base URL.
- `TI_LLM_MODEL` (`LLM_MODEL`) or `OLLAMA_MODEL` — Ollama model name.
- `TI_LLM_REQUEST_TIMEOUT` (`LLM_REQUEST_TIMEOUT`) — LLM request timeout (seconds).
- `TI_LLM_TEMPERATURE` (`LLM_TEMPERATURE`) — temperature for LLM calls.
- `LLM_HOST` (CONFIG only) — reporting uses this if set; otherwise falls back to `OLLAMA_HOST`.

### PDF pipeline
- `ENABLE_SUMMARIZATION` — when `true`, add `summary_text` in PDF NDJSON outputs.
- `MAX_WORKERS` (`TI_MAX_WORKERS`) — thread pool size for RSS fetching and PDF analysis.

### SIEM delivery (Elastic)
- `TI_SIEM_ENABLED` (`SIEM_ENABLED`) — enable Elastic bulk delivery (used in PDF pipeline).
- `TI_SIEM_TYPE` (`SIEM_TYPE`) — currently only `elastic`.
- `TI_ELASTIC_ENDPOINT`, `TI_ELASTIC_INDEX` — target Elastic endpoint/index.
- `TI_ELASTIC_API_KEY` or `TI_ELASTIC_USER`/`TI_ELASTIC_PASS` — authentication.
- `TI_SIEM_BATCH_SIZE`, `TI_SIEM_MAX_RETRIES`, `TI_SIEM_TIMEOUT`, `TI_SIEM_DRY_RUN` — delivery behavior.

### Reporting
- `REPORT_MAX_ENTRIES` (CONFIG only) — max LLM records to summarize (default 30).
- `REPORT_BATCH_SIZE` (CONFIG only) — batch size for intermediate LLM prompts (default 6).

### GeoFeed
- `TI_GEOFEED_RSS_FEEDS` (`GEOFEED_RSS_FEEDS`) — JSON list of GeoFeed RSS URLs.
- `GEOFEED_RSS_FEEDS` (env only) — comma-separated RSS URLs (legacy fallback).
- `TI_GEOFEED_MAX_ITEMS_PER_FEED` — max items to read per feed.
- `TI_GEOFEED_SUMMARY_LIMIT` — max entries included in GeoFeed summary output.
- `TI_GEOFEED_REQUEST_TIMEOUT` — per-request timeout (seconds).
- `TI_GEOFEED_USE_OLLAMA` — enable GeoFeed LLM summarization.
- `TI_GEOFEED_OLLAMA_MODEL` — model used by GeoFeed LLM prompts.
- `TI_GEOFEED_ADD_LLM_SUMMARY` — include LLM summary in output.
- `TI_GEOFEED_LLM_SUMMARY_MAX_CHARS` — cap LLM summary length.
- `TI_GEOFEED_GEO_ONLY` — enable geo-only filtering for reports.
- `TI_GEOFEED_MIN_GEO_TIER` — minimum tier to include (A, B, or C).
- `TI_GEOFEED_INCLUDE_TIER_C_APPENDIX` — append filtered Tier C titles in an appendix section.
- `TI_GEOFEED_COMPARISON_MAX_ITEMS` — cap entries sent to the comparison LLM.
- `GEOFEED_COMPARE_USE_LLM` (env only) — set to `1`/`true` to use LLM for GeoFeed comparisons (default is deterministic).
- `TI_GEOFEED_SALIENT_EVENT_TERMS` — JSON list of salient phrases to keep beyond window.
- `TI_GEOFEED_SALIENT_LOOKBACK_HOURS` — extended lookback window for salient items.
- `TI_GEOFEED_WATCHLIST_LOCATIONS` — JSON list of location watchlist terms.
- `TI_GEOFEED_WATCHLIST_ASSETS` — JSON list of asset watchlist terms.
- `TI_GEOFEED_SIGNAL_WEIGHTS` — JSON object of scoring weights for signals.
- `TI_GEOFEED_AMPLIFIERS` — JSON object for amplification keywords.
- `TI_GEOFEED_DAMPENERS` — JSON object for dampening keywords.
- `TI_GEOFEED_EXCLUDE_KEYWORDS` — JSON list of phrases to exclude.
- `TI_GEOFEED_PROXIMITY_WEIGHTS` — JSON object for proximity scoring.
- `TI_GEOFEED_DECISION_THRESHOLDS` — JSON object for decision thresholds.
- `GEOFEED_BOILERPLATE_KEYWORDS` (CONFIG only) — keywords stripped from GeoFeed article text.
- `GEOFEED_MIN_PARAGRAPH_WORDS`, `GEOFEED_MIN_TOTAL_WORDS` (CONFIG only) — minimum text length thresholds.
- `GEOFEED_VALIDATE_LLM` (CONFIG only) — enable/disable GeoFeed LLM output validation.
- `GEOFEED_SKIP_VALIDATE` (env only) — force-skip GeoFeed LLM validation.

### Defined but currently unused (reserved)
- `ENABLE_SCORING`, `EXPORT_NAVIGATOR`, `ARCHIVE_TTL_DAYS`
- `MIN_SENTENCE_WORDS`, `MIN_PARAGRAPH_WORDS`
- `HTML_PARSER`, `HTML_MAX_LEN`, `HTML_STRIP_ELEMENTS`
- `PDFTOTEXT_TIMEOUT`, `PDF_MAX_PAGES`, `SUMMARY_MAX_SENTENCES`, `SUMMARY_MAX_CHARS`
- `EXCERPT_RADIUS`, `TOP_FINDING_MIN_WORDS`, `TOP_FINDING_MAX_WORDS`
- `PROVENANCE_KEYWORDS`, `PROVENANCE_STRIP_PATTERNS`
- `ENABLE_UA_ROTATION`, `FALLBACK_USER_AGENTS`
- `ENABLER_KEYWORDS`, `CRITICAL_THRESHOLD`, `INTERESTING_MIN`, `INTERESTING_MAX`
- `GEOFEED_ENABLED`

Refer to `collector/config.py` for exact defaults, and edit that file for any
CONFIG-only settings.

## Tests & development

- Run the full test suite:

```bash
python3 -m pytest -q
```

- Run a single test file or nodeid for faster iteration:

```bash
python3 -m pytest tests/test_pdf_pipeline.py -q
```

If `pytest` is not installed, add it with:

```bash
pip install pytest
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
