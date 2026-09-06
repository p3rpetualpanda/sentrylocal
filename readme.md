# SentryLocal

A local, privacy-preserving security scanner for Python code. SentryLocal scans a directory for common vulnerability patterns without sending any code to external services — everything runs on your own machine.

## What it does

SentryLocal walks a target directory, scans every `.py` file it finds, and flags lines matching known-risky patterns:

- **`eval()` usage** — arbitrary code execution risk
- **Hard-coded secrets** — API keys, passwords, tokens left in source
- **Unsafe SQL query construction** — potential SQL injection
- **`os.system()` usage** — command injection risk
- **Insecure imports** — modules flagged as risky in `rules.json`, with a suggested alternative

## Installation

```bash
git clone https://github.com/p3rpetualpanda/sentrylocal.git
cd sentrylocal
python -m venv venv
venv\Scripts\activate      # Windows
source venv/bin/activate   # macOS/Linux
pip install -r requirements.txt
```

## Usage

Run against any directory:

```bash
python main.py <path_to_scan>
```

Example — scan the current project:

```bash
python main.py .
```

Output lists each finding with its severity, rule ID, file, line number, and the offending code:

```
[HIGH] eval-use - .\example.py:12
    result = eval(user_input)
    Use of eval() is dangerous and should be avoided.
```

## Running the tests

SentryLocal has a pytest suite that checks detection against known vulnerable and clean code samples:

```bash
pip install pytest
pytest tests/ -v
```

Test fixtures live in `tests/fixtures/` and are excluded from pytest's own test collection (via `tests/conftest.py`), since they're sample code for the scanner to analyze — not tests to be executed themselves.

## Known limitations

Detection is currently **substring/regex-based**, not context-aware. This means:

- Comments or string literals that happen to contain a flagged pattern (e.g. a comment saying `# Rule to detect use of eval()`) can trigger false positives.
- The scanner does not distinguish between a real `eval()` call and one appearing inside a string, docstring, or comment.

This is a known and accepted limitation of the current version, documented rather than hidden — including in the test suite (`TestSecureCode` in `tests/test_scanner.py` explicitly records this behaviour).

## Roadmap

- [ ] Move from substring matching to AST-based detection (using Python's `ast` module) to eliminate comment/string false positives
- [ ] Expand `rules.json` with more patterns and severities
- [ ] Optional local LLM-assisted analysis for more nuanced findings
- [ ] HTML/JSON report export

## Project structure

```
sentrylocal/
├── sentrylocal/
│   ├── scanner.py      # Core scanning logic
│   ├── rules.py         # Rule definitions
│   ├── rules.json        # Rule data (secrets, unsafe queries, insecure imports)
│   └── report.py
├── tests/
│   ├── fixtures/         # Sample vulnerable/clean code for testing
│   └── test_scanner.py
├── main.py                # CLI entry point
└── config.yaml
```

## Why this project exists

This is a personal portfolio project exploring local, privacy-preserving static analysis — built and maintained as part of ongoing computing studies.