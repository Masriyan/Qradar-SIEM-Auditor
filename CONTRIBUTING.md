# Contributing to QRadar SIEM Auditor

Thank you for your interest in contributing! This guide will help you get started.

## Development Setup

1. **Fork & clone** the repository
2. Create a virtual environment:
   ```bash
   python3 -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   ```
3. Copy the environment template:
   ```bash
   cp .env.example .env   # fill in your QRadar URL and token
   ```

## How to Contribute

### Reporting Bugs

- Use the [Bug Report](.github/ISSUE_TEMPLATE/bug_report.md) template
- Include QRadar version, Python version, and full error output

### Requesting Features

- Use the [Feature Request](.github/ISSUE_TEMPLATE/feature_request.md) template
- Explain the use case and how it improves SIEM auditing

### Submitting Code

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/my-new-check
   ```
2. Follow existing code patterns (see `_check_*` methods)
3. Test with `--dry-run` and verify all export formats
4. Commit with clear messages:

   ```
   Add log source latency check

   - New check: _check_log_source_latency
   - Registered in Data Collection category
   - Added severity weight
   ```

5. Open a Pull Request against `main`

## Adding a New Audit Check

1. Add a `_check_your_name(self) -> Dict[str, Any]` method
2. Register it in `self.audit_categories` under the appropriate category
3. Add a severity weight in the `SEVERITY_MAP` dict (1–10)
4. Return a dict with keys: `status`, `findings`, `recommendations`, `details`
5. Update `README.md` with the new check description

## Code Style

- **Python 3.8+** compatibility
- Type hints on all public methods
- Docstrings for complex logic
- Keep lines ≤ 120 characters
- Use `self.logger` for debug/info messages, not raw `print`

## Pull Request Checklist

- [ ] Code follows existing patterns
- [ ] `--dry-run` passes without errors
- [ ] `--list-checks` shows the new check
- [ ] All export formats generate valid output
- [ ] README updated if adding user-facing features
- [ ] CHANGELOG updated

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). Be respectful and constructive.

---

Thank you for contributing! 🛡️
