# Threat_intel — Collector and Analysis

Version: 1

This repository contains a small threat-intel collector and processing pipeline.
It supports structured CVE collection and an unstructured RSS/article pipeline that
enriches items with MITRE mappings, priority scoring and writes results as
NDJSON + Markdown reports (raw article bodies are written separately).

This README documents how to run the collector, what outputs to expect, and
how to run the unit tests and formatting tools used during development.

## Quick start (recommended)

- Create a Python virtual environment and install dependencies:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

- Run the unstructured RSS pipeline for the last 28 hours and write outputs:

```bash
.venv/bin/python3 -m collector.main --unstructured --hours 28
```

- Or run full collector (structured + unstructured) for 24 hours:

```bash
.venv/bin/python3 -m collector.main --structured --unstructured --hours 24
```

Notes
- When run the collector writes results into `collector/results/<YYYYMMDD>/`.
- Typical output files produced by the unstructured pipeline:
	- `UnstructuredRSSIntel_<date>.ndjson` — sanitized NDJSON (no full article text)
	- `rawtext-<date>.json` — full article bodies (kept separate by design)
	- `UnstructuredRSSReport_<date>.md` — human-readable markdown report

## CLI flags (common)

- `--unstructured` — run the unstructured RSS/article pipeline only (or combined)
- `--structured` — run the structured CVE/KEV collection pipeline
- `--hours <N>` — look-back window in hours for RSS items (used to limit the run)

Only flags used in the project runs are documented above. For additional options,
inspect `collector/main.py` for available CLI flags.

## Running outside VS Code

You can run the collector from any POSIX shell (macOS, Linux). Typical steps:

# Threat Intel Collector — Overview

This repository provides a lightweight threat-intelligence collector and
processing pipeline written in Python. It supports two primary collection
flows:

- Structured CVE/KEV collection (CVE feeds and known exploited vulnerabilities).
- Unstructured RSS/article pipeline — fetches articles from RSS feeds,
	extracts indicators (IOCs), infers MITRE ATT&CK techniques, computes
	relevance/priority scores, and writes sanitized NDJSON + Markdown reports.

The focus is on producing actionable, searchable intelligence records with
separate storage of full article bodies (`rawtext-<date>.json`).

This README documents how to run the collector, the outputs it produces,
and a comprehensive list of configuration variables (env-var names and the
`CONFIG` keys used by the code).

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

Notes
- Results are written under `collector/results/<YYYYMMDD>/` by default.
- Full article bodies are written into `rawtext-<date>.json` (separate from
	the NDJSON output to avoid embedding long text in the NDJSON records).

## What the collector does (functional summary)

- Poll RSS feeds and fetch article HTML/text (parallelized with a thread
	pool).
- Sanitize and normalize article text (boilerplate removal, dehyphenation).
- Extract IOCs (IPs, domains, URLs, hashes, emails) via regex patterns.
- Match keywords and phrase maps to infer MITRE ATT&CK techniques and
	populate `threat.technique` / `threat.technique_mitigations`.
- Compute relevance and MITRE-based priority scores.
- Produce a sanitized NDJSON file, a rawtext JSON file containing full
	extracted article text, and a Markdown report aggregation.

## CLI flags

- `--structured` — run structured CVE/KEV collection.
- `--unstructured` — run unstructured RSS/article pipeline.
- `--unstructured-pdf <path>` — run the PDF extraction pipeline on a path.
- `--llm` — run LLM rawtext translation pipeline (if enabled).
- `--tests` — run unit tests using the active Python interpreter.
- `--hours <N>` — look-back window in hours for RSS items.
- `--no-banner` — suppress ASCII banner at program start.

Run `python3 -m collector.main -h` to see available flags and help text.

## Outputs and file conventions

- `UnstructuredRSSIntel_<date>.ndjson` — sanitized NDJSON output. Each line
	is a JSON object with fields such as `id`, `source`, `title`, `@timestamp`,
	`threat` (with `technique` names/IDs and `technique_mitigations`), `iocs`,
	and `provenance`.
- `rawtext-<date>.json` — array of objects containing full article text and
	metadata. This file contains the full extracted article bodies.
- `UnstructuredRSSReport_<date>.md` — human-readable Markdown report used for
	quick review and triage.

NDJSON records intentionally exclude the full article bodies; they are kept
in `rawtext-<date>.json` to simplify downstream indexing and reduce NDJSON
size.

## Configuration (env vars / CONFIG keys)

All runtime configuration is provided via the `CONFIG` mapping in
`collector/config.py`. Most values may be overridden using environment
variables (often prefixed with `TI_`). Below is a grouped, annotated list of
the most important configuration options and their corresponding env var names.

General
- `TI_RSS_FEEDS` (CONFIG[`RSS_FEEDS`]) — Comma-separated list or JSON array
	of RSS feed URLs to ingest. Defaults to a curated list in `config.py`.
- `TI_VENDORS` (CONFIG[`VENDORS`]) — Vendor/product keywords used for
	grouping and heuristics.
- `TI_OUTPUT_DIR` (CONFIG[`OUTPUT_DIR`]) — Output directory (set via
	`RESULTS_DIR` by default). Override `TI_OUTPUT_DIR` by setting
	`CONFIG['OUTPUT_DIR']` programmatically or editing `config.py`.

HTTP & fetching
- `TI_USER_AGENT` (CONFIG[`USER_AGENT`]) — HTTP User-Agent used for
	requests. Default: `ThreatIntelCollector/5.0 (+https://example.local)`.
- `TI_HTTP_RETRIES_TOTAL` & `TI_HTTP_BACKOFF_FACTOR` — Retry policy for HTTP
	requests (used when fetching feeds/articles).
- `TI_HTTP_STATUS_FORCELIST` — JSON array of status codes that should
	trigger retries (default: `[500,502,503,504]`).
- `TI_REQUEST_TIMEOUT` — Request timeout in seconds for fetch operations.
- `TI_ENABLE_UA_ROTATION` & `TI_FALLBACK_USER_AGENTS` — Enable rotating
	User-Agent headers and provide fallback agent strings.

Concurrency & dedupe
- `TI_MAX_WORKERS` (CONFIG[`MAX_WORKERS`]) — Thread pool size for article
	fetching (default: 8).
- `TI_FUZZY_MATCHING_ENABLE` — Enable fuzzy title deduplication (default:
	false).
- `TI_FUZZY_MATCH_THRESHOLD` — Percentage (0-100) threshold for fuzzy title
	matching (default: 85).

Text processing & sanitization
- `TI_HTML_PARSER` — HTML parser to use (e.g., `html.parser`, `lxml`).
- `TI_HTML_MAX_LEN` — Max HTML length to consider for extraction.
- `TI_HTML_STRIP_ELEMENTS` — HTML tag names to drop before text extraction (e.g.
	`script`, `style`, `header`, `footer`, `nav`).
- `TI_BOILERPLATE_KEYWORDS` — Patterns used to drop boilerplate paragraphs.
- `TI_EXCERPT_RADIUS` — Characters around a matched snippet used to build
	excerpts.

Summarization & findings
- `TI_ENABLE_SUMMARIZATION` — Whether to compute a short text summary for
	each article.
- `TI_SUMMARY_MAX_SENTENCES` / `TI_SUMMARY_MAX_CHARS` — Controls summary
	length.

Pattern & MITRE data files
- `TI_PATTERNS_FILE` — Optional path to a JSON file with extraction regexes
	and classification rules.
- `TI_MITRE_MAP_FILE` — Optional path to a MITRE mapping JSON file (used to
	enrich technique IDs/names and references).
- `TI_MITRE_MITIGATIONS_FILE` — Optional path to mitigation items used for
	building `technique_mitigations`.

Scoring & thresholds
- `TI_CRITICAL`, `TI_INTERESTING_MIN`, `TI_INTERESTING_MAX` — Numeric
	thresholds used in scoring and labeling relevance.
- `TI_MITRE_PRIORITY_BASE_WEIGHT`, `TI_MITRE_PRIORITY_EVIDENCE_WEIGHT` —
	Weights used for combining signals into MITRE priority scores.

IOCs & actionable items
- `TI_MAX_SNIPPETS_PER_TYPE` — Number of excerpt snippets to keep per type.
- `TI_MITIG_SNIPPET_FIRST_SENT_MAX` & `TI_MITIG_SNIPPET_MAX_CHARS` —
	Controls for mitigation snippet extraction.

Provenance & LLM detection
- `TI_PROVENANCE_KEYWORDS` — Keywords to mark content as LLM generated
	(e.g., `chatgpt`, `openai`).
- `TI_PROVENANCE_STRIP_PATTERNS` — Regexes used to remove provenance
	boilerplate from extracted text.

SIEM / Delivery
- `TI_SIEM_ENABLED` — Whether to send results to a SIEM (default: false).
- `TI_SIEM_TYPE` — SIEM backend (e.g., `elastic`).
- `TI_ELASTIC_ENDPOINT`, `TI_ELASTIC_INDEX`, `TI_ELASTIC_API_KEY` — Elastic
	delivery settings.
- `TI_SIEM_DRY_RUN` — If true, delivery logic will simulate delivery without
	sending (default: true).

Advanced runtime knobs
- `TI_COMPILED_PATTERNS_CACHE_MAXSIZE` — Cache size used by compiled
	regex loaders.
- `TI_INCLUDE_ENTRIES_WITHOUT_DATE` — Include feed entries without a
	published date (default: true).

Note: For boolean env vars the code generally interprets the string `true`
case-insensitively; JSON-style env vars (arrays/dicts) can be provided as
JSON strings.

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

The interactive menu and the `--tests` CLI flag run pytest using the same
Python interpreter that launched the collector (`sys.executable -m pytest`),
so tests will run consistently when using a virtual environment.

## Helper scripts

- `scripts/sanitize_results.py` — sanitizes NDJSON/rawtext files in a results
	directory (e.g., removes `text/raw_text/excerpt` fields from NDJSON).
- `scripts/build_mitre_map.py`, `scripts/build_mitre_mitigations.py` —
	create or transform MITRE mapping artifacts under `data/`.

Use the helper scripts for offline maintenance of mapping files or to clean
historical outputs.

## Troubleshooting

- If the collector fails to fetch articles, check HTTP timeouts and
	`TI_USER_AGENT` to ensure the target site does not block requests.
- If MITRE mapping or mitigations appear missing, confirm `TI_MITRE_MAP_FILE`
	and `TI_MITRE_MITIGATIONS_FILE` point to valid JSON artifacts or use the
	built-in defaults.
- Use the test suite to validate local edits: `python3 -m pytest -q`.

---

This README focuses on usage and configuration; developer-facing notes
and backup artifacts live under the `backups/` folder in this repository.