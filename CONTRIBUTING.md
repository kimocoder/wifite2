# Contributing to wifite2

Thank you for your interest in contributing. Please follow these guidelines to keep the project consistent and maintainable.

---

## Development Environment

```bash
# Clone your fork
git clone https://github.com/<your-username>/wifite2.git
cd wifite2

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in editable mode with all dependencies
pip install -e .
pip install -r requirements.txt
```

---

## Running the Test Suite

```bash
pytest tests/ -v
```

All tests must pass before submitting a pull request. If you add new functionality, add corresponding tests in `tests/`.

Some tests require external tools (`tshark`, `aircrack-ng`, `cowpatty`). Install them on your system or mock them in your test fixtures.

---

## Code Style

- Follow **PEP 8** for all Python code.
- Use the existing `Color` and `Output` utilities (`wifite/util/color.py`) for any user-facing output. Do not use bare `print()` calls.
- Use `log_debug()` / `log_info()` from `wifite/util/logger.py` for internal diagnostic messages.
- Keep functions focused. Refactor large blocks into helper methods rather than adding deeply nested logic.
- Type hints are welcome but not required for existing modules; new modules should include them where practical.

---

## Submitting a Pull Request

1. **Fork** the repository and create a feature branch off `master`:
   ```bash
   git checkout -b feature/my-improvement
   ```
2. Make your changes, following the style guidelines above.
3. Run the test suite and confirm it passes.
4. Commit with a clear, concise message describing *what* changed and *why*.
5. Push your branch to your fork and open a **Pull Request against `master`**.
6. Fill in the PR description: what problem it solves, how it was tested, and any known limitations.

PRs that break existing tests or lack a description will not be merged.

---

## Testing Requirements

Contributions that touch attack logic, capture parsing, or tool integrations **must** be tested on real hardware or with mocked interfaces. Specifically:

- Use `.cap` / `.pcapng` fixture files in `tests/files/` for capture-related changes.
- Mock external process calls (`aircrack-ng`, `tshark`, etc.) using `unittest.mock` where live hardware is not available.
- Document in your PR description how you verified the change (hardware model, driver, OS, or mock strategy).

---

## Responsible Disclosure

If you discover a security vulnerability in wifite2 itself (not a vulnerability in a third-party tool it wraps), **do not open a public GitHub issue**.

Instead, email the maintainer directly. Provide a clear description of the issue, reproduction steps, and potential impact. Allow reasonable time for a fix before any public disclosure.

Public issues are appropriate for bugs, feature requests, and usage questions, not for 0-day disclosures.
