# Threat_intel — Collector and Analysis

Version: 1

This repository contains a lightweight threat-intel collector and processing
pipeline. It supports four flows:

- Structured CVE/KEV collection (CVE feeds and known exploited vulnerabilities).
- Fetch pipeline — pulls RSS articles and writes rawtext JSON for downstream use
  (no in-app enrichment).
- PDF pipeline — extracts text from PDFs, performs light summarization/scoring,
  and writes NDJSON/Markdown.
- LLM enrichment — reads the latest rawtext bundle, sends it to a local Ollama
  model (default `llama3.1`), and produces cleaned NDJSON/Markdown without
  embedding full raw text.

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
- `collector/fetch.py` — fetches RSS articles and writes rawtext bundles (no enrichment).
  - `collector/pdf.py` — PDF extraction helper.
  - `collector/CVE.py` — structured CVE/KEV collection.
  - `collector/delivery.py` — SIEM/delivery hooks.
  - `collector/LLM.py`, `collector/progress.py` and other helpers.
  - `collector/logs/` and `collector/results/` — runtime output folders.
- `data/` — static data artifacts used by the collector (PDF samples).
- `scripts/` — helper and maintenance scripts (examples: `sanitize_results.py`, `minify_py.py`).
- `tests/` — pytest unit tests covering extraction, normalization, and writer behavior.

This layout is intentionally simple: application code lives under `collector/`,
data under `data/`, dev scripts under `scripts/`, and tests under `tests/`.
Use this section as a quick reference for where to look when making changes.

## Quick Start

- Create and activate a Python virtual environment and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

- Run only the fetch (RSS) pipeline for the last 28 hours:

```bash
python3 -m collector.main --unstructured --hours 28
```

- Run the structured + fetch pipelines together for 24 hours:

```bash
python3 -m collector.main --structured --unstructured --hours 24
```

- Run the LLM enrichment pipeline on the most recent rawtext bundle (no hours prompt):

```bash
python3 -m collector.main --llm
```

Notes:
- Results are written under `collector/results/<category>/<YYYYMMDD>/<HHMMSS>/`.
  Categories: `structured/`, `pdf/`, `llmrawtext/` (raw articles), and `llm/`.
- Fetch pipeline writes full article bodies to `collector/results/llmrawtext/<date>/<time>/rawtext-<date>.json`
  so the LLM pipeline can consume them; NDJSON excludes raw bodies.
- LLM summarization uses a local Ollama instance (`OLLAMA_HOST`, `OLLAMA_MODEL`
  or `LLM_MODEL`, `LLM_ENABLED=true`), default model `llama3.1`, and a 300s
  request timeout. If Ollama is not reachable the run logs the failure and moves on.
- The LLM pipeline automatically selects the most recent `rawtext-<date>.json`
  under `collector/results/llmrawtext/` and skips any `--hours` prompt.

## What the collector does (high level)

- Poll RSS feeds and fetch article HTML/text (parallelized with a thread pool).
- Sanitize and normalize article text (boilerplate removal, dehyphenation).
- Write rawtext JSON bundles for downstream LLM processing (no in-app enrichment).
- PDF pipeline: extract text from PDFs, perform light summarization/scoring, and emit NDJSON/Markdown.

## CLI flags and menu

Flags (non-interactive):
- `--structured` — run structured CVE/KEV collection.
- `--unstructured` — run RSS/article fetch to build rawtext (no enrichment).
- `--unstructured-pdf <path>` — run the PDF extraction pipeline on a path.
- `--llm` — run LLM rawtext translation (uses latest rawtext bundle; no hours prompt).
- `--reporting <days>` — build a cumulative LLM-based report over 2/7/14/30 days.
- `--tests` — run unit tests using the active Python interpreter.
- `--hours <N>` — look-back window in hours for RSS items.
- `--no-banner` — suppress ASCII banner at program start.

Interactive menu commands mirror the above:
- `structured` — structured CVE/KEV collection.
- `unstructured` — fetch RSS articles to build rawtext.
- `pdf <PATH>` — run PDF extraction on the given path (defaults to `data/PDF` if omitted).
- `llm` — translate latest rawtext with the LLM.
- `reporting` — build cumulative report (prompt for 2/7/14/30 days).
- `tests` — run pytest.
- `all` — structured + fetch + llm in sequence.
- `hours <N>` — adjust the default look-back for fetch/structured in the session.

Important note about the interactive menu and `--tests`:
- The interactive menu and the `--tests` CLI flag run pytest using the same
  Python interpreter that launched the collector (for example
  `sys.executable -m pytest`). This ensures tests run consistently inside a
  virtual environment.

## Outputs and file conventions

- `collector/results/llmrawtext/<date>/<time>/rawtext-<date>.json` — raw article bodies
  produced by the fetch pipeline for LLM consumption.
- `collector/results/structured/<date>/<time>/StructuredCVEData_<date>.ndjson` — structured CVE/KEV NDJSON.
- `collector/results/structured/<date>/<time>/StructuredCVEReport_<date>.md` — structured CVE/KEV Markdown.
- `collector/results/pdf/<date>/<time>/UnstructuredPDFIntel_<date>.ndjson` —
  PDF extraction/enrichment output.
- `collector/results/pdf/<date>/<time>/UnstructuredPDFReport_<date>.md` —
  PDF human-readable Markdown.
- `collector/results/llm/<date>/<time>/rawtext-LLM_<date>.ndjson` —
  LLM-enriched NDJSON (pretty-printed; no `raw_text`/`text` fields).
- `collector/results/llm/<date>/<time>/LLM-UnstructuredReport_<date>.md` —
  LLM-enriched Markdown summary.
- `collector/results/structured/<date>/<time>/StructuredCVEReport_<date>.md` —
  structured CVE/KEV Markdown.

NDJSON records intentionally exclude the full article bodies; they are kept
in `rawtext-<date>.json` to simplify downstream indexing and reduce NDJSON size.

## Configuration (env vars / CONFIG keys)

All runtime configuration is provided via the `CONFIG` mapping in
`collector/config.py`. Most values may be overridden using environment
variables (often prefixed with `TI_`). Below is a complete, grouped list of
`CONFIG` keys and their corresponding env vars / defaults to help with
customization.

General
- `VENDORS` / `TI_VENDORS` — list of vendor/product names used for grouping
  and heuristics (default: built-in vendor list).
- `RSS_FEEDS` / `TI_RSS_FEEDS` — list of RSS feed URLs to ingest (default:
  built-in feed list).
- `OUTPUT_DIR` / `TI_OUTPUT_DIR` — output directory (default: `collector/results/<YYYYMMDD>`).
- `LOG_FILE` — log file path (default: `collector/logs/threat_intel_collector.log`).
- `USER_AGENT` / `TI_USER_AGENT` — HTTP User-Agent header (default: `ThreatIntelCollector/5.0 (+https://example.local)`).
- `OLLAMA_HOST` / `TI_OLLAMA_HOST` — Ollama API host (default: `http://localhost:11434`).
- `LLM_MODEL` / `OLLAMA_MODEL` — Ollama model name (default: `llama3`).
- `LLM_ENABLED` — enable/disable LLM enrichment (default: true).

Feeds & external APIs
- `NVD_API_BASE` / `TI_NVD_API_BASE` — base URL for NVD API (default NVD v2 endpoint).
- `CISA_KEV_URL` / `TI_CISA_KEV_URL` — CISA Known Exploited Vulnerabilities feed URL.
- `COMMUNITY_KEV_URL` / `TI_COMMUNITY_KEV_URL` — community KEV feed URL.

HTTP / Fetching
- `ENABLE_UA_ROTATION` / `TI_ENABLE_UA_ROTATION` — enable rotating user agents (default: true).
- `FALLBACK_USER_AGENTS` / `TI_FALLBACK_USER_AGENTS` — JSON array of fallback UA strings.
- `HTTP_RETRIES_TOTAL` / `TI_HTTP_RETRIES_TOTAL` — total retries for requests (default: 3).
- `HTTP_BACKOFF_FACTOR` / `TI_HTTP_BACKOFF_FACTOR` — backoff factor for retries (default: 0.3).
- `HTTP_STATUS_FORCELIST` / `TI_HTTP_STATUS_FORCELIST` — status codes to retry (default: [500,502,503,504]).
- `HTTP_POOL_CONNECTIONS` / `TI_HTTP_POOL_CONNECTIONS` — connection pool size (default: 100).
- `HTTP_POOL_MAXSIZE` / `TI_HTTP_POOL_MAXSIZE` — pool max size (default: 100).
- `REQUEST_TIMEOUT` / `TI_REQUEST_TIMEOUT` — request timeout seconds (default: 25).

Concurrency & dedupe
- `MAX_WORKERS` / `TI_MAX_WORKERS` — thread pool size for fetching (default: 8).
- `FUZZY_MATCHING_ENABLE` / `TI_FUZZY_MATCHING_ENABLE` — enable fuzzy title deduplication (default: false).
- `FUZZY_MATCH_THRESHOLD` / `TI_FUZZY_MATCH_THRESHOLD` — fuzzy threshold percent (default: 85).

Text processing & sanitization
- `HTML_PARSER` / `TI_HTML_PARSER` — HTML parser to use (e.g., `html.parser`, `lxml`).
- `HTML_MAX_LEN` / `TI_HTML_MAX_LEN` — max HTML length to process (default: 50000).
- `HTML_STRIP_ELEMENTS` / `TI_HTML_STRIP_ELEMENTS` — JSON array of tags to drop (default: [`script`,`style`,`noscript`,`header`,`footer`,`nav`]).
- `BOILERPLATE_KEYWORDS` / `TI_BOILERPLATE_KEYWORDS` — keywords to treat as boilerplate (list default includes `cookies`, `privacy`, `subscribe`, etc.).
- `EXCERPT_RADIUS` / `TI_EXCERPT_RADIUS` — characters around matched snippet for excerpt (default: 160).
- `MIN_SENTENCE_WORDS`, `MIN_PARAGRAPH_WORDS`, `MIN_REPEAT_FOR_SHORT_MATCH` — processing thresholds (defaults: 5, 20, 2).

PDF & OCR
- `PDFTOTEXT_TIMEOUT` / `TI_PDFTOTEXT_TIMEOUT` — timeout for pdftotext helper (default: 30).
- `PDF_MAX_PAGES` / `TI_PDF_MAX_PAGES` — maximum pages to process from a PDF (default: 50).

Extraction, patterns & MITRE
- `PATTERNS_FILE` / `TI_PATTERNS_FILE` — custom JSON file with extraction regexes and classification rules.
- `MITRE_MAP_FILE` / `TI_MITRE_MAP_FILE` — optional MITRE mapping JSON file to enrich technique IDs/names.
- `MITRE_MITIGATIONS_FILE` / `TI_MITRE_MITIGATIONS_FILE` — optional mitigation mapping JSON file.
- `CVE_REGEX` / `TI_CVE_REGEX` — regex used to detect CVE identifiers (default: `\\bCVE-\\d{4}-\\d{4,7}\\b`).
- `TECHNIQUE_SCORE_BOOST` / `TECHNIQUE_SCORE_BOOST` — JSON mapping to boost specific technique scores.

Summarization, scoring & actionability
- `ENABLE_SUMMARIZATION` — enable auto summaries (default: true).
- `SUMMARY_MAX_SENTENCES` / `TI_SUMMARY_MAX_SENTENCES` — max sentences in summary (default: 2).
- `SUMMARY_MAX_CHARS` / `TI_SUMMARY_MAX_CHARS` — max chars in summary (default: 500).
- `ENABLE_SCORING` — enable scoring pipeline (default: true).
- `WEIGHT_ACTORS`, `WEIGHT_CAMPAIGNS`, `WEIGHT_THREATS`, `WEIGHT_DENSITY` — numeric weights used when computing scores (defaults: 30,25,25,20).
- `ACTIONABILITY_WEIGHTS` / `TI_ACTIONABILITY_WEIGHTS` — optional JSON map to tune actionability scoring.

Top findings / snippet extraction
- `TOP_FINDING_MIN_WORDS` / `TI_TOP_FINDING_MIN_WORDS` — min words for top finding (default: 10).
- `TOP_FINDING_MAX_WORDS` / `TI_TOP_FINDING_MAX_WORDS` — max words for top finding (default: 80).
- `BULLET_FINDING_REGEX` / `TI_BULLET_FINDING_REGEX` — regex for bullet list detection (default provided).
- `PROMO_PATTERNS` / `TI_PROMO_PATTERNS` — patterns to filter promotional text.
- `SHORT_SOCIAL_REGEX`, `SHORT_SOCIAL_MAX_WORDS` — filters for short social posts.
- `MAX_SNIPPETS_PER_TYPE` / `TI_MAX_SNIPPETS_PER_TYPE` — number of excerpt snippets to keep per type (default: 3).

Provenance & LLM detection
- `PROVENANCE_KEYWORDS` / `TI_PROVENANCE_KEYWORDS` — keywords considered LLM/provenance indicators (default includes `chatgpt`, `openai`, etc.).
- `PROVENANCE_STRIP_PATTERNS` / `TI_PROVENANCE_STRIP_PATTERNS` — regexes to strip provenance boilerplate.

Mitigations / mitigation snippets
- `MITIG_SNIPPET_FIRST_SENT_MAX` / `TI_MITIG_SNIPPET_FIRST_SENT_MAX` — max chars for the first mitigation sentence (default: 200).
- `MITIG_SNIPPET_MAX_CHARS` / `TI_MITIG_SNIPPET_MAX_CHARS` — max chars for mitigation snippets (default: 300).

Suricata / rule generation
- `SURICATA_SID_START` / `TI_SURICATA_SID_START` — starting SID for generated Suricata rules (default: 1000001).
- `SURICATA_ALERT_TEMPLATE` / `TI_SURICATA_ALERT_TEMPLATE` — template string used when generating Suricata alerts.

Misc runtime knobs
- `COMPILED_PATTERNS_CACHE_MAXSIZE` / `TI_COMPILED_PATTERNS_CACHE_MAXSIZE` — cache size for compiled regex loader (default: 1).
- `INCLUDE_ENTRIES_WITHOUT_DATE` / `TI_INCLUDE_ENTRIES_WITHOUT_DATE` — include entries lacking a published date (default: true).
- `ARCHIVE_TTL_DAYS` / `ARCHIVE_TTL_DAYS` — days to keep archive files (default: 90).
- `EXPORT_NAVIGATOR` / `EXPORT_NAVIGATOR` — produce a Mitre navigator layer (default: false).

SIEM / Delivery
- `SIEM_ENABLED` / `TI_SIEM_ENABLED` — enable SIEM delivery (default: false).
- `SIEM_TYPE` / `TI_SIEM_TYPE` — SIEM backend type (default: `elastic`).
- `ELASTIC_ENDPOINT`, `ELASTIC_INDEX`, `ELASTIC_API_KEY`, `ELASTIC_USER`, `ELASTIC_PASS` — Elastic delivery settings.
- `SIEM_BATCH_SIZE`, `SIEM_MAX_RETRIES`, `SIEM_TIMEOUT`, `SIEM_DRY_RUN` — delivery controls and dry-run toggle.

MITRE priority tuning
- `MITRE_PRIORITY_BASE_WEIGHT`, `MITRE_PRIORITY_EVIDENCE_WEIGHT` — weights used to compute MITRE priority (defaults: 0.6 and 0.4).
- `INFERRED_TECHNIQUE_SCORE_MULTIPLIER` — multiplier for inferred techniques (default: 0.8).
- `MITRE_SIGNAL_MENTION`, `MITRE_SIGNAL_CVE`, `MITRE_SIGNAL_IOC`, `MITRE_SIGNAL_ACTIONABILITY` — numeric signals used when scoring MITRE relevance.

Advanced / developer
- `COMPILED_PATTERNS_CACHE_MAXSIZE` — compiled regex cache size.
- `LLM_REQUEST_TIMEOUT` — Ollama request timeout seconds (default: 300).
- `OLLAMA_MODEL`/`LLM_MODEL` — Ollama model name (default: `llama3.1`).

Refer to `collector/config.py` for exact defaults and the code-side behavior. Environment variables that accept JSON (arrays/dicts) should be provided as valid JSON strings.

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
