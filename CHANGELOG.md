# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [2.0.0] — 2026-02-28

### Added

- **Compliance & Governance** audit category with 3 new checks:
  - Patch Level — verifies QRadar version against supported release trains
  - License Compliance — evaluates EPS utilization vs licensed capacity
  - Audit Trail — reviews admin login activity and dormant accounts
- **Performance & Tuning** audit category with 3 new checks:
  - EPS Capacity — estimates event processing headroom per deployment
  - Ariel Disk Usage — monitors Ariel partition utilization and compression
  - Flow Dedup Ratio — measures flow deduplication effectiveness
- **Severity scoring** system (1–10 per check) with overall audit score (0–100)
- **PDF export** format (`--export pdf`) via `fpdf2`
- **Audit comparison** mode (`--compare <old.json>`) to diff two audit runs
- Severity column in CSV and HTML exports
- Overall score display in console, HTML, and PDF reports
- GitHub community files: `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`
- GitHub templates: bug report, feature request, pull request
- `.gitignore` for Python projects
- `requirements.txt` with pinned dependencies

### Changed

- HTML report redesigned with improved styling, score badge, and severity column
- Console report now displays severity per check and overall score
- CLI `--export` choices expanded to include `pdf`
- Total audit checks increased from 23 to 29 across 8 categories

---

## [1.0.0] — 2025-08-20

### Added

- Initial release with 23 audit checks across 6 categories
- Robust HTTP layer with retries, exponential backoff, and Range/Content-Range pagination
- Ariel search polling with configurable window (`--ariel-window`)
- CLI filters: `--include-category`, `--exclude-category`, `--include-check`, `--exclude-check`
- Multi-format exports: Console, JSON, CSV, HTML
- Debug logging (`--debug`, `--log-file`)
- Dry-run mode (`--dry-run`)
- `--list-checks` discovery command
- Environment variable support via `.env` (QRADAR_URL, QRADAR_TOKEN, VERIFY_SSL)
