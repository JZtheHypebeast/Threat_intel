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
.venv/bin/python3 -m collector.main --unstructured-rss --hours 28
```

- Or run full collector (structured + unstructured) for 24 hours:

```bash
.venv/bin/python3 -m collector.main --structured --unstructured-rss --hours 24
```

Notes
- When run the collector writes results into `collector/results/<YYYYMMDD>/`.
- Typical output files produced by the unstructured pipeline:
	- `UnstructuredRSSIntel_<date>.ndjson` — sanitized NDJSON (no full article text)
	- `rawtext-<date>.json` — full article bodies (kept separate by design)
	- `UnstructuredRSSReport_<date>.md` — human-readable markdown report

## CLI flags (common)

- `--unstructured-rss` — run the unstructured RSS/article pipeline only (or combined)
- `--structured` — run the structured CVE/KEV collection pipeline
- `--hours <N>` — look-back window in hours for RSS items (used to limit the run)

Only flags used in the project runs are documented above. For additional options,
inspect `collector/main.py` for available CLI flags.

## Important configuration variables

The collector has many runtime knobs exposed via the `CONFIG` mapping and
environment variables (prefix `TI_` for most settings). Below are the most
important ones you may want to change and why.

- `TI_RSS_FEEDS` (CONFIG[`RSS_FEEDS`]) — list of RSS feed URLs to ingest. Update
	this to add or remove sources.
- `TI_VENDORS` (CONFIG[`VENDORS`]) — vendor/product keywords used to group
	findings by vendor. Useful to bias detection toward your tracked vendors.
- `TI_USER_AGENT` (CONFIG[`USER_AGENT`]) — HTTP User-Agent string used for
	requests. Set a descriptive UA for polite scraping.
- `TI_MAX_WORKERS` (CONFIG[`MAX_WORKERS`]) — number of parallel worker threads
	used for IO-bound tasks (fetching articles). Lower this if you hit rate
	limits; increase for faster runs on beefy machines.
- `TI_HTTP_RETRIES_TOTAL`, `TI_HTTP_BACKOFF_FACTOR` — retry policy for HTTP
	requests. Increase retries for flaky networks; increase backoff factor to
	reduce request rate under transient errors.
- `TI_FUZZY_MATCHING_ENABLE` & `TI_FUZZY_MATCH_THRESHOLD` — enable fuzzy
	deduplication and control threshold (0-100). Helpful to collapse similar
	but not identical headlines; set threshold higher to be stricter.
- `TI_MIN_REPEAT_FOR_SHORT_MATCH` — controls whether short repeated snippets
	(e.g., "phishing. phishing.") count as evidence. Lower values make short
	repetitions more influential; default is `2`.
- `TI_EXCERPT_RADIUS` — number of characters around a matched snippet used to
	build excerpts. Increase for more context; decrease to keep excerpts short.
- `TI_HTML_STRIP_ELEMENTS` & `TI_BOILERPLATE_KEYWORDS` — control HTML cleaning
	and boilerplate removal. Extend these lists if outputs include unwanted
	navigation/footer content.
- `TI_PATTERNS_FILE`, `TI_MITRE_MAP_FILE`, `TI_MITRE_MITIGATIONS_FILE` — paths to
	auxiliary data files. Point these at updated mapping files if you maintain
	custom MITRE mappings or mitigation snippets.
- `TI_SIEM_ENABLED` and SIEM-related vars (`TI_ELASTIC_*`) — control whether
	results are shipped to a SIEM (Elastic) and where. Use `TI_SIEM_DRY_RUN=true`
	to test SIEM integration without sending data.
- `TI_CRITICAL`, `TI_INTERESTING_MIN`, `TI_INTERESTING_MAX` — numeric thresholds
	used by scoring and thresholds for what is considered critical/interesting.
	Tune these to your operational appetite for alerts.
- `TI_ENABLE_UA_ROTATION` and `TI_FALLBACK_USER_AGENTS` — enable rotating UAs
	from a fallback list when fetching articles; useful to reduce blocking by
	some providers.

Tip: you can set any of the above via environment variables before running the
collector, for example:

```bash
export TI_MAX_WORKERS=4
export TI_FUZZY_MATCH_THRESHOLD=90
.venv/bin/python3 -m collector.main --unstructured-rss --hours 24
```


## Running unit tests

- Run the full test suite (using the project's venv Python):

```bash
.venv/bin/python3 -m pytest -q
```

- Run a single test file:

```bash
.venv/bin/python3 -m pytest tests/test_unstructured.py -q
```

- Run a single test nodeid (collected name) — useful when iterating quickly:

```bash
.venv/bin/python3 -m pytest tests/test_unstructured.py::TestUnstructuredExtraction::test_short_nav_reject -q
```

Notes
- Tests are compatible with running from the repo root using the venv python so
	imports resolve correctly (e.g. the `collector` package).

## Formatting and code style

- This project uses Black. Reformat the repository with the venv python:

```bash
.venv/bin/python3 -m black .
```

Black is listed in `requirements.txt` so running the `pip install -r requirements.txt`
step should install it into the venv.

## Useful helper scripts (project-local)

The `scripts/` directory contains a few project-relevant utility scripts (not all
scripts are intended for production automation):

- `scripts/sanitize_results.py` — sanitize NDJSON/rawtext JSON files in a results
	directory (removes `text`, `raw_text`, `summary_text`, and prunes provenance).

Usage (default looks for latest 2025-11-14 folder shown in earlier runs):

```bash
.venv/bin/python3 scripts/sanitize_results.py /path/to/collector/results/20251114
# or run without args to use the default results path used by the project
.venv/bin/python3 scripts/sanitize_results.py
```

- `scripts/build_mitre_map.py`, `scripts/build_mitre_mitigations.py`, and
	`scripts/build_mitre_mitigations_compact.py` are helper scripts used to
	generate/transform MITRE mapping artifacts in the `data/` folder.

Note: During repository housekeeping some temporary analysis/maintenance scripts
were removed. If you need a previously-created helper (for coverage or dedupe
analysis), they may exist in your local backups or the `backups/` directory.

## Outputs and conventions

	article text; `text`/`raw_text`/`excerpt` fields are removed from the
	serialized NDJSON. Full bodies live in `rawtext-<date>.json`.
	filenames like `UnstructuredRSSIntel_<date>.ndjson` and
	`UnstructuredRSSReport_<date>.md`.

## Development tips

	unit tests under `tests/` to assert the absence/presence of fields.

## Troubleshooting

	that you installed dependencies: `python3 -m venv .venv && .venv/bin/pip install -r requirements.txt`.
	edits should not change logic but can surface whitespace-related issues in
	generated artifacts.

## Short log & result examples

Below are brief examples of the kinds of log lines and result records you will see when running the collector.

Example log lines (from `collector/logs/threat_intel_collector.log`):

```
2025-11-14 15:10:02 [INFO] Fetching RSS feed https://gbhackers.com/feed/
2025-11-14 15:10:05 [INFO] Found 12 new entries in feed: gbhackers
2025-11-14 15:10:07 [INFO] Fetching article https://gbhackers.com/some-article
2025-11-14 15:10:09 [INFO] Extracted 3 iocs, 1 mitre technique, score=7.8 -> writing record
2025-11-14 15:10:09 [INFO] Wrote 30 records -> collector/results/20251114/UnstructuredRSSIntel_20251114.ndjson
```

Example NDJSON record (sanitized; full article text is NOT included in NDJSON):

```json
{ "id": "u-20251114-0001", "source": "gbhackers", "title": "Phishing campaign targets X", "published": "2025-11-14T14:02:00Z", "threat": { "technique": { "id": "T1566", "name": "Phishing" }, "mitre_details": [{"id":"T1566","priority_score":70}] , "mitre_priority": {"score": 72} }, "iocs": [{"type":"domain","value":"bad.example.com"}], "provenance": [{"source_name":"GBHackers","source_url":"https://gbhackers.com/some-article","confidence":0.8}] }
```

Example Markdown report excerpt (`UnstructuredRSSReport_<date>.md`):

```
## Unstructured RSS Report — 2025-11-14

1. Entry: Phishing campaign targets X

   - Date: 2025-11-14T14:02:00Z
   - Technique: Phishing (T1566)
   - Priority score: 72
   - IOCs: bad.example.com
   - Provenance: GBHackers — https://gbhackers.com/some-article

```

## Architectural structure (high level)

The pipeline is intentionally modular. Key components:

- `collector/main.py` — CLI entrypoint coordinating runs (structured/unstructured).
- `collector/config.py` — central configuration and environment-variable mapping.
- `collector/unstructured.py` — orchestration for the RSS/article pipeline: fetch feeds, fetch article HTML/PDFs, call enrichment and dedupe, and write outputs.
- `collector/unstructured_core.py` — enrichment logic: text extraction, IOC detection/normalization, MITRE mapping, scoring, excerpt extraction, and markdown generation.
- `collector/unstructured_pdf.py` — PDF-specific pipeline and extraction helpers (handles PDF download, extraction, and OCR fallbacks where available) and returns extracted text to the main unstructured pipeline.
- `collector/structured.py` — structured CVE/KEV collection and normalization.
- `collector/enablers.py` — helper routines for extracting enabler keywords and excerpting context.
- `collector/delivery.py` — optional delivery/export to SIEM (Elastic) or other sinks.
- `collector/progress.py` — terminal-friendly progress reporting used during runs.

Typical runtime flow:

1. `main` parses CLI flags and populates runtime config.
2. `unstructured` fetches feeds, collects candidate entries.
3. For each entry: fetch article, extract main text (or PDF text), prune boilerplate.
	- When an entry points to a PDF, the `unstructured_pdf` module downloads and extracts text (using the configured PDF extractor and optional OCR fallback) and supplies it to the enrichment pipeline.
4. `unstructured_core` runs detectors (IOCs, MITRE signals), computes relevance & priority scores, and deduplicates similar records.
5. Writers serialize sanitized NDJSON (no full bodies), write `rawtext-<date>.json` for bodies, and generate the Markdown report.
6. Optionally, `delivery` ships artifacts to configured SIEMs or APIs.

Design notes
- Writer-side normalization and pruning ensure produced NDJSON matches the canonical schema and never includes full article text.
- Raw article bodies are intentionally kept separate to reduce risk and keep NDJSON small and shareable.

---