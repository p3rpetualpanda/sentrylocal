# SentryLocal

A local, privacy-preserving security scanner for Python code. SentryLocal scans a directory for common vulnerability patterns without sending any code to external services — everything runs on your own machine.

## What it does

SentryLocal walks a target directory, scans every `.py` file it finds, and flags lines matching known-risky patterns:

- **`eval()` usage** — arbitrary code execution risk
- **Hard-coded secrets** — API keys, passwords, tokens left in source
- **Unsafe SQL query construction** — potential SQL injection, including dynamically built queries (f-strings and string concatenation)
- **`os.system()` usage** — command injection risk
- **Insecure imports** — modules flagged as risky in `rules.json`, with a suggested alternative
- **`pickle.loads` / `pickle.load`** — deserialization of untrusted data
- **`subprocess` with `shell=True`** — shell injection risk
- **Weak hashing (`md5`, `sha1`)** — use of cryptographically weak hash functions

Every finding is mapped to a [CWE](https://cwe.mitre.org/) identifier, and reports can be exported in SARIF for use in CI pipelines and code-scanning tools.

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

Use `--format` with `--output` to save a report as JSON, a standalone HTML page, or SARIF:

```bash
python main.py . --format json --output report.json
python main.py . --format html --output report.html
python main.py . --format sarif --output report.sarif
```

The HTML report is self-contained (no external dependencies) and color-codes findings by severity — open it directly in a browser. The SARIF report follows the [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) spec and can be dropped straight into CI code-scanning tools (GitHub code scanning, Azure DevOps, etc.).

### Running with LLM triage

SentryLocal can optionally pass each finding to a local LLM for a second, more nuanced opinion — a `true_positive` / `false_positive` / `needs_review` verdict with a short explanation. This is fully optional and runs entirely on your machine; if the backend is unreachable the finding simply falls back to `needs_review` and the scan never crashes.

```bash
python main.py . --llm
python main.py . --llm --llm-threshold MEDIUM   # triage MEDIUM and above
```

The triage verdict is shown in the text/HTML reports and included in JSON/SARIF output.

**Setting up a local backend.** SentryLocal speaks the OpenAI-compatible chat API, so any local server that exposes it works. Two supported options:

- **llama.cpp** — start the server with `llama serve` (it listens on `http://localhost:8080/v1/chat/completions` by default).
- **Ollama** — start a model with `ollama serve` (it listens on `http://localhost:11434/api/generate`).

The backend URL and model name are configured in `sentrylocal/llm.py` (`LLAMA_URL`, `OLLAMA_URL`, `MODEL`).

## v2 features

SentryLocal v2 layers three capabilities on top of the original rule engine:

- **Local LLM triage** — an optional second pass that asks a local model to classify each finding as `true_positive`, `false_positive`, or `needs_review`, with a short explanation. It uses only the Python standard library (`urllib`) and degrades gracefully when no backend is running.
- **CWE mapping** — every rule carries a [CWE](https://cwe.mitre.org/) identifier (e.g. `eval` → CWE-94, unsafe SQL → CWE-89, `os.system` → CWE-78), so findings can be correlated with industry-standard weakness catalogs.
- **SARIF export** — findings can be emitted as [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html), the standard interchange format for code-scanning results, ready for CI and code-hosting integrations.

Together these turn a fast, deterministic scanner into a two-stage analysis: the rule engine catches candidates quickly, and the optional LLM pass adds nuance where it matters.

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
- SQL injection detection flags dynamically built queries (f-strings and string concatenation) that contain a known-risky pattern, but it still relies on pattern matching rather than full data-flow analysis.
- Secret detection matches against a fixed list of variable names in `rules.json` (e.g. `API_KEY`, `PASSWORD`) rather than inspecting value formats.

These are documented tradeoffs, not oversights — see the Roadmap below for planned improvements.

## Roadmap

- [x] Move from substring matching to AST-based detection (using Python's `ast` module) to eliminate comment/string false positives
- [x] HTML/JSON report export
- [x] Detect dynamically constructed SQL queries (f-strings, string concatenation), not just static query strings
- [x] Expand `rules.json` with more patterns and severities
- [x] Optional local LLM-assisted analysis for more nuanced findings
- [x] Map findings to CWE identifiers
- [x] SARIF report export

## Project structure

```
sentrylocal/
├── sentrylocal/
│   ├── scanner.py      # Core scanning logic (AST-based detection)
│   ├── rules.json        # Rule data (secrets, unsafe queries, insecure imports, ...)
│   ├── llm.py            # Optional local LLM triage layer (llama.cpp / Ollama)
│   └── report.py         # Text/JSON/HTML/SARIF report generation
├── tests/
│   ├── fixtures/         # Sample vulnerable/clean code for testing
│   ├── test_scanner.py
│   └── test_llm.py
├── main.py                # CLI entry point
├── benchmark.py           # Rule-only vs rule+LLM benchmark
└── config.yaml
```

## Why this project exists

This is a personal portfolio project exploring local, privacy-preserving static analysis — built and maintained as part of ongoing computing studies.