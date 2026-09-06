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

By default, this prints a text report straight to the terminal:

```
[HIGH] eval-use - .\example.py:12
    result = eval(user_input)
    Use of eval() is dangerous and should be avoided.
```

### Exporting reports

Use `--format` with `--output` to save a report as JSON or a standalone HTML page instead:

```bash
python main.py . --format json --output report.json
python main.py . --format html --output report.html
```

The HTML report is self-contained (no external dependencies) and color-codes findings by severity — open it directly in a browser.

## Running the tests

SentryLocal has a pytest suite that checks detection against known vulnerable and clean code samples:

```bash
pip install pytest
pytest tests/ -v
```

Test fixtures live in `tests/fixtures/` and are excluded from pytest's own test collection (via `tests/conftest.py`), since they're sample code for the scanner to analyze — not tests to be executed themselves.

## Known limitations

Detection uses Python's `ast` module, so it operates on parsed syntax rather than raw text. This means comments and docstrings can never trigger false positives (they aren't part of the AST at all), and string literals only match when they're genuinely being used — e.g. assigned to a variable or passed as an argument.

That said, detection is still deliberately conservative in a few ways:

- `eval()` calls are flagged regardless of whether the input is provably harmless (e.g. `eval("1 + 2")`) — static analysis can't know intent, so any real call is treated as a risk.
- SQL injection detection currently only catches **static** query strings matching known-risky patterns; it does not yet detect dynamically built queries (f-strings or string concatenation).
- Secret detection matches against a fixed list of variable names in `rules.json` (e.g. `API_KEY`, `PASSWORD`) rather than inspecting value formats.

These are documented tradeoffs, not oversights — see the Roadmap below for planned improvements.

## Roadmap

- [x] Move from substring matching to AST-based detection (using Python's `ast` module) to eliminate comment/string false positives
- [x] HTML/JSON report export
- [ ] Detect dynamically constructed SQL queries (f-strings, string concatenation), not just static query strings
- [ ] Expand `rules.json` with more patterns and severities
- [ ] Optional local LLM-assisted analysis for more nuanced findings

## Project structure

```
sentrylocal/
├── sentrylocal/
│   ├── scanner.py      # Core scanning logic (AST-based detection)
│   ├── rules.json        # Rule data (secrets, unsafe queries, insecure imports)
│   └── report.py         # Text/JSON/HTML report generation
├── tests/
│   ├── fixtures/         # Sample vulnerable/clean code for testing
│   └── test_scanner.py
├── main.py                # CLI entry point
└── config.yaml
```

## Why this project exists

This is a personal portfolio project exploring local, privacy-preserving static analysis — built and maintained as part of ongoing computing studies.