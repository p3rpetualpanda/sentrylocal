# SentryLocal v2 — Step-by-Step Build Plan

A teaching plan for taking SentryLocal from its current state (a working AST-based scanner) to **v2**: a two-stage pipeline where a fast deterministic rule engine does the heavy lifting, and an optional **local LLM triage** layer explains, prioritises, and de-duplicates findings.

This plan is grounded in the code that already exists in `sentrylocal/`. Each phase ends with a **checkpoint** — a command you can run to prove the phase works before moving on.

> **How to use this plan.** Work through the phases in order. Each phase is small enough to finish in a sitting. If a phase feels large, that's a sign to split it into smaller commits. The checkpoints are your safety net — don't skip them.

---

## Where you are now

Before you start, make sure you understand the current architecture. Read these files top to bottom:

| File | What it does |
|------|-------------|
| `main.py` | CLI entry point. Parses args, calls `scan_directory`, writes a report. |
| `sentrylocal/scanner.py` | The core. `SecurityVisitor` (an `ast.NodeVisitor`) walks each file's AST and collects findings. `scan_file` / `scan_directory` orchestrate it. `load_rules` reads `rules.json`. |
| `sentrylocal/rules.json` | Rule data: secret variable names, unsafe SQL patterns, insecure imports. |
| `sentrylocal/report.py` | Turns findings into text / JSON / HTML. |
| `sentrylocal/llm.py` | **Empty.** This is where the v2 LLM triage layer will live. |
| `tests/test_scanner.py` | The pytest suite. Fixtures in `tests/fixtures/`. |

Run the existing suite to confirm your baseline is green:

```powershell
cd sentrylocal
python -m pytest tests/ -v
```

> **Checkpoint 0:** All existing tests pass. If they don't, fix that first — you don't want to build on a broken foundation.

---

## Phase 1 — Dynamic SQL detection (close the documented gap)

**Why first.** This is pure scanner work (no LLM, no new dependencies), it's the gap called out in the readme roadmap, and it teaches you the AST patterns you'll need for the rest of the project.

### The problem

Right now, `visit_Assign` in `scanner.py` only flags SQL when the value is an `ast.Constant` string:

```python
def visit_Assign(self, node):
    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
        value = node.value.value
        ...
        for query_pattern in self.rules.get("unsafe_queries", []):
            if query_pattern in value and "?" not in value:
                self._add_finding(node.lineno, "unsafe_queries")
```

This catches `query = "SELECT * FROM users WHERE username = " + user` only if the literal part matches a pattern. It does **not** catch:

```python
query = f"SELECT * FROM users WHERE username = {user}"   # f-string
query = "SELECT * FROM users WHERE username = " + user    # concatenation
```

### Step 1.1 — Add an `f-string` branch

An f-string is an `ast.JoinedStr` node. Add a branch in `visit_Assign` (or a helper it calls) that:

1. Checks `isinstance(node.value, ast.JoinedStr)`.
2. Walks `node.value.values` — each element is either an `ast.Constant` (literal text) or an `ast.FormattedValue` (the `{user}` part).
3. Concatenates the `ast.Constant` parts into a string and checks it against `unsafe_queries` patterns.
4. If any `ast.FormattedValue` is present **and** a pattern matches, flag it (the interpolation is the injection vector).

```python
def _check_fstring_sql(self, node, lineno):
    if not isinstance(node.value, ast.JoinedStr):
        return
    literal_parts = []
    has_interpolation = False
    for value in node.value.values:
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            literal_parts.append(value.value)
        elif isinstance(value, ast.FormattedValue):
            has_interpolation = True
    literal = "".join(literal_parts)
    for pattern in self.rules.get("unsafe_queries", []):
        if pattern in literal and has_interpolation:
            self._add_finding(lineno, "unsafe_queries")
```

Call `_check_fstring_sql(node, node.lineno)` from `visit_Assign` alongside the existing constant check.

### Step 1.2 — Add a string-concatenation branch

A `"..." + user` expression is an `ast.BinOp` with `op=ast.Add()`. Add a similar helper that:

1. Checks `isinstance(node.value, ast.BinOp)` and `isinstance(node.value.op, ast.Add)`.
2. Recursively extracts string constants from the left/right operands.
3. Flags if a pattern matches and at least one operand is a non-constant (a variable, a call, etc.).

### Step 1.3 — Add test fixtures

Create `tests/fixtures/test_dynamic_sql.py`:

```python
user = input("username: ")
# f-string — should be flagged
query = f"SELECT * FROM users WHERE username = {user}"
# concatenation — should be flagged
query2 = "SELECT * FROM users WHERE username = " + user
# parameterised — should NOT be flagged
query3 = "SELECT * FROM users WHERE username = ?"
```

Add a test class in `test_scanner.py`:

```python
class TestDynamicSQL:
    def test_flags_fstring_sql(self):
        ids = rule_ids(get_findings("test_dynamic_sql.py"))
        assert "sql-injection" in ids

    def test_parameterised_query_not_flagged(self):
        # query3 uses "?" so it should not appear as a finding
        findings = get_findings("test_dynamic_sql.py")
        sql_findings = [f for f in findings if f["rule"]["id"] == "sql-injection"]
        # only the f-string and concatenation lines should be flagged, not the "?" one
        assert len(sql_findings) == 2
```

> **Checkpoint 1:** `python -m pytest tests/ -v` passes, including the new `TestDynamicSQL` class. The old tests still pass (you didn't break the static detection).

---

## Phase 2 — Expand the rule engine

**Why.** A richer rule set makes the scanner more useful and gives the LLM triage layer more to work with. It also teaches you how to structure rules as data (in `rules.json`) rather than hard-coded logic.

### Step 2.1 — Add new rules to `rules.json`

Add entries for:

- **`pickle` deserialisation** — `pickle.loads(user_input)` is a code-execution risk. Add a new rule key `pickle_loads` with severity `HIGH`.
- **`subprocess` with `shell=True`** — `subprocess.run(cmd, shell=True)` is a command-injection risk. Add `subprocess_shell` with severity `HIGH`.
- **Weak hashing** — `hashlib.md5(...)` or `hashlib.sha1(...)` used for security purposes. Add `weak_hash` with severity `MEDIUM`.

Example `rules.json` additions:

```json
{
  "pickle_loads": ["pickle.loads", "pickle.load"],
  "subprocess_shell": ["shell=True"],
  "weak_hash": ["md5", "sha1"]
}
```

### Step 2.2 — Add corresponding `RULE_METADATA` entries in `scanner.py`

```python
"pickle_loads": {
    "id": "pickle-loads",
    "severity": "HIGH",
    "description": "Deserialising untrusted data with pickle can execute arbitrary code."
},
"subprocess_shell": {
    "id": "subprocess-shell",
    "severity": "HIGH",
    "description": "subprocess with shell=True is vulnerable to command injection."
},
"weak_hash": {
    "id": "weak-hash",
    "severity": "MEDIUM",
    "description": "MD5/SHA1 are not suitable for security purposes. Use SHA-256 or better."
}
```

### Step 2.3 — Add visitor methods

- `visit_Call`: check for `pickle.loads` / `pickle.load` (an `ast.Attribute` where `attr == "loads"` and the value resolves to `pickle`).
- `visit_Call`: check for `subprocess.run` / `subprocess.call` with a `shell=True` keyword argument.
- `visit_Call`: check for `hashlib.md5` / `hashlib.sha1`.

Each follows the same pattern as the existing `eval` and `os.system` checks in `visit_Call`.

### Step 2.4 — Add fixtures and tests

Create `tests/fixtures/test_new_rules.py` with one line per new rule, plus a clean variant. Add a test class asserting each new rule id appears (or doesn't, for the clean variant).

> **Checkpoint 2:** All tests pass. The scanner now flags `pickle.loads`, `subprocess shell=True`, and weak hashing. The old rules still work.

---

## Phase 3 — CWE mapping

**Why.** Mapping findings to [CWE](https://cwe.mitre.org/) identifiers makes the report standardised and interoperable with other security tooling. It's a small change with a big professional payoff.

### Step 3.1 — Add a `cwe` field to `RULE_METADATA`

```python
"eval": {
    "id": "eval-use",
    "severity": "HIGH",
    "description": "Use of eval() is dangerous and should be avoided.",
    "cwe": "CWE-94"          # Improper Control of Generation of Code
},
"secrets": {
    "id": "hardcoded-secret",
    "severity": "HIGH",
    "description": "Hard-coded secret detected.",
    "cwe": "CWE-798"         # Use of Hard-coded Credentials
},
"unsafe_queries": {
    "id": "sql-injection",
    "severity": "HIGH",
    "description": "Potential SQL injection vulnerability detected.",
    "cwe": "CWE-89"          # SQL Injection
},
"os_system": {
    "id": "os-system-use",
    "severity": "MEDIUM",
    "description": "Use of os.system() is dangerous and can lead to command injection.",
    "cwe": "CWE-78"          # OS Command Injection
},
"insecure_imports": {
    "id": "insecure-import",
    "severity": "MEDIUM",
    "description": "Insecure or risky module imported.",
    "cwe": "CWE-248"         # Uncaught Exception (or a more specific CWE per import)
},
"pickle_loads": {
    "id": "pickle-loads",
    "severity": "HIGH",
    "description": "Deserialising untrusted data with pickle can execute arbitrary code.",
    "cwe": "CWE-502"         # Deserialization of Untrusted Data
},
"subprocess_shell": {
    "id": "subprocess-shell",
    "severity": "HIGH",
    "description": "subprocess with shell=True is vulnerable to command injection.",
    "cwe": "CWE-78"
},
"weak_hash": {
    "id": "weak-hash",
    "severity": "MEDIUM",
    "description": "MD5/SHA1 are not suitable for security purposes.",
    "cwe": "CWE-328"         # Use of Weak Hash
}
```

### Step 3.2 — Surface the CWE in reports

In `report.py`, add a `CWE` column to the HTML table and include `cwe` in the JSON output. The text report can append it to the description line:

```
[HIGH] sql-injection (CWE-89) - file.py:12
```

### Step 3.3 — Update tests

Add an assertion in `test_scanner.py` that every finding's `rule` dict contains a `cwe` key:

```python
def test_findings_have_cwe(self):
    for finding in self.findings:
        assert "cwe" in finding["rule"]
```

> **Checkpoint 3:** All tests pass. The HTML report shows a CWE column. The JSON report includes `cwe` per finding.

---

## Phase 4 — The LLM triage layer (the core of v2)

**Why.** This is the headline feature. The deterministic scanner is fast but conservative — it flags `eval("1 + 2")` the same as `eval(user_input)`. The LLM layer adds nuance: it can say "this is probably a false positive" or "this is high-risk because the input comes from user input."

### Architecture

```
scan_directory()
    │
    ▼
findings (list of dicts)
    │
    ├──► report.py  (existing: text / json / html)
    │
    └──► llm.py     (new: triage each finding)
              │
              ▼
         triaged_findings (findings + LLM verdict + explanation)
              │
              ▼
         report.py  (updated: shows triage verdict)
```

The LLM layer is **optional** (gated behind a `--llm` flag) and **local** (no code leaves the machine — that's the whole point of SentryLocal).

### Step 4.1 — Set up the local LLM

You have two local backends to choose from. Both keep everything on your machine (no API keys, no telemetry), which is the whole point of SentryLocal.

**Option A — llama.cpp (`llama serve`)** — the [llama.app](https://llama.app/) project. Recommended: it exposes an OpenAI-compatible API and supports **structured JSON output**, which makes the triage parsing more reliable.

```powershell
# install llama.cpp (see llama.app/docs/installation), then serve a small model:
llama serve -hf ggml-org/gemma-4-e4b-it-GGUF:Q4_0
```

Verify it runs:

```powershell
curl http://localhost:8080/v1/chat/completions -H "Content-Type: application/json" -d '{
  "model": "local-model",
  "messages": [{"role": "user", "content": "Say hello in one word."}]
}'
```

**Option B — Ollama** — a simpler install, but its native API (`/api/generate`) has no structured-output guarantee, so you rely on the model returning clean JSON.

```powershell
ollama pull llama3.2:3b
ollama run llama3.2:3b "Say hello in one word."
```

> **Why a small model?** A 3–4B model runs on a laptop CPU and is fast enough for triage. You can swap in a larger model later, but the architecture shouldn't depend on one. The code below is written to work with **either** backend — you just change the URL and the request/response shape.

### Step 4.2 — Implement `llm.py`

Create the triage function. The key design decisions:

1. **One finding at a time** — send a single finding (file, line, code, rule) to the LLM with a focused prompt. This keeps prompts short and responses reliable.
2. **Structured output** — ask the LLM to return JSON: `{"verdict": "true_positive" | "false_positive" | "needs_review", "confidence": 0.0-1.0, "explanation": "..."}`. With llama.cpp you can *guarantee* valid JSON via `response_format`; with Ollama you ask for it and parse defensively.
3. **Graceful fallback** — if the backend isn't running or the model errors, return `{"verdict": "needs_review", "confidence": 0.0, "explanation": "LLM unavailable"}` so the scanner never crashes because of the LLM.
4. **Backend-agnostic** — the only thing that differs between llama.cpp and Ollama is the URL, the request body, and where the text lives in the response. Keep that in one small function so swapping backends is a one-line change.

```python
# sentrylocal/llm.py
import json
import urllib.request
import urllib.error

# --- Backend config: pick ONE -------------------------------
# llama.cpp (llama.app) — OpenAI-compatible, supports structured JSON
BACKEND = "llama_cpp"          # or "ollama"
LLAMA_URL = "http://localhost:8080/v1/chat/completions"
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "local-model"          # llama.cpp: set --alias when serving; Ollama: e.g. "llama3.2:3b"
# -------------------------------------------------------------

TRIAGE_PROMPT = """You are a security analyst reviewing a static-analysis finding.
Classify it as true_positive, false_positive, or needs_review.

Finding:
- File: {file}
- Line: {line}
- Code: {code}
- Rule: {rule_id} ({severity})
- Description: {description}

Respond with ONLY a JSON object:
{{"verdict": "true_positive"|"false_positive"|"needs_review", "confidence": 0.0, "explanation": "one sentence"}}
"""


def _build_payload(prompt):
    """Return (url, payload_bytes) for the configured backend."""
    if BACKEND == "llama_cpp":
        payload = {
            "model": MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "response_format": {"type": "json_object"},   # guarantees valid JSON
        }
        return LLAMA_URL, json.dumps(payload).encode("utf-8")
    else:  # ollama
        payload = {"model": MODEL, "prompt": prompt, "stream": False}
        return OLLAMA_URL, json.dumps(payload).encode("utf-8")


def _extract_text(data):
    """Pull the model's text out of a backend response."""
    if BACKEND == "llama_cpp":
        return data["choices"][0]["message"]["content"].strip()
    return data.get("response", "").strip()


def triage_finding(finding):
    """Send a single finding to the local LLM and return a triage dict."""
    rule = finding["rule"]
    prompt = TRIAGE_PROMPT.format(
        file=finding["file"],
        line=finding["line"],
        code=finding["code"],
        rule_id=rule["id"],
        severity=rule["severity"],
        description=rule["description"],
    )
    url, body = _build_payload(prompt)

    try:
        req = urllib.request.Request(url, data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        text = _extract_text(data)
        # With llama.cpp + response_format this is already clean JSON;
        # with Ollama the model may add prose, so slice out the object.
        start, end = text.find("{"), text.rfind("}") + 1
        if start == -1 or end == 0:
            raise ValueError("No JSON in LLM response")
        return json.loads(text[start:end])
    except (urllib.error.URLError, ValueError, json.JSONDecodeError) as e:
        return {
            "verdict": "needs_review",
            "confidence": 0.0,
            "explanation": f"LLM unavailable: {e}",
        }


def triage_findings(findings, threshold="HIGH"):
    """Triage findings at or above the given severity. Returns a new list."""
    severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    min_level = severity_order.get(threshold, 0)
    triaged = []
    for f in findings:
        if severity_order.get(f["rule"]["severity"], 0) >= min_level:
            triage = triage_finding(f)
            f = dict(f)  # don't mutate the original
            f["triage"] = triage
        triaged.append(f)
    return triaged
```

> **Design note:** Using `urllib` (stdlib) keeps the dependency footprint small — no `ollama` or `openai` package required. If you prefer a package, `pip install openai` and point `openai.OpenAI(base_url="http://localhost:8080/v1", api_key="no-key-required")` at llama.cpp; the rest of the logic is unchanged.

### Step 4.3 — Wire it into `main.py`

Add a `--llm` flag and a `--llm-threshold` option:

```python
parser.add_argument(
    "--llm",
    action="store_true",
    help="Run LLM triage on findings (requires a local LLM backend: llama.cpp or Ollama)"
)
parser.add_argument(
    "--llm-threshold",
    choices=["LOW", "MEDIUM", "HIGH"],
    default="HIGH",
    help="Minimum severity to triage with the LLM (default: HIGH)"
)
```

After `findings = scan_directory(args.directory)`:

```python
if args.llm:
    from sentrylocal.llm import triage_findings
    findings = triage_findings(findings, threshold=args.llm_threshold)
```

### Step 4.4 — Show triage in the report

In `report.py`, update `generate_text_report` and `generate_html_report` to display the triage verdict when present:

```python
# in generate_text_report, after the description line:
if "triage" in f:
    t = f["triage"]
    lines.append(f"    LLM: {t['verdict']} (confidence {t['confidence']:.0%}) — {t['explanation']}")
```

In the HTML report, add a "Triage" column that shows the verdict colour-coded (green = true positive, grey = false positive, amber = needs review).

### Step 4.5 — Test the LLM layer

You can't unit-test the LLM deterministically, but you **can** test the plumbing:

```python
# tests/test_llm.py
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sentrylocal.llm import triage_finding
from sentrylocal.scanner import scan_file, load_rules

def test_triage_finding_returns_valid_verdict():
    rules = load_rules()
    findings = scan_file(os.path.join("tests", "fixtures", "test_vulnerable.py"), rules)
    assert findings, "expected at least one finding"
    result = triage_finding(findings[0])
    assert result["verdict"] in ("true_positive", "false_positive", "needs_review")
    assert "confidence" in result
    assert "explanation" in result

def test_triage_finding_falls_back_when_backend_down():
    # Point at a port that's not listening, regardless of backend
    import sentrylocal.llm as llm
    url_attr = "LLAMA_URL" if llm.BACKEND == "llama_cpp" else "OLLAMA_URL"
    original = getattr(llm, url_attr)
    setattr(llm, url_attr, "http://localhost:9999/v1/chat/completions")
    try:
        result = llm.triage_finding({"file": "x.py", "line": 1, "code": "eval(x)",
                                     "rule": {"id": "eval-use", "severity": "HIGH",
                                              "description": "test"}})
        assert result["verdict"] == "needs_review"
        assert "LLM unavailable" in result["explanation"]
    finally:
        setattr(llm, url_attr, original)
```

> **Checkpoint 4:**
> 1. `python -m pytest tests/ -v` passes (including the new `test_llm.py`).
> 2. With your local backend running (llama.cpp `llama serve` or Ollama): `python main.py tests/fixtures --llm` shows LLM verdicts in the output.
> 3. With the backend **not** running: the same command still works, showing "LLM unavailable" fallbacks. The scanner never crashes.

---

## Phase 5 — SARIF export (stretch goal)

**Why.** SARIF is the standard format for static-analysis results. Exporting it means SentryLocal findings can appear in GitHub code scanning, VS Code's problem panel, and any other SARIF-aware tool.

### Step 5.1 — Add a `sarif` format to `report.py`

```python
def generate_sarif_report(findings):
    """Return findings as a SARIF 2.1.0 JSON string."""
    results = []
    for f in findings:
        rule = f["rule"]
        result = {
            "ruleId": rule["id"],
            "level": {"HIGH": "error", "MEDIUM": "warning", "LOW": "note"}.get(rule["severity"], "warning"),
            "message": {"text": rule["description"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file"]},
                    "region": {"startLine": f["line"]},
                }
            }],
        }
        if "cwe" in rule:
            result["ruleId"] += f" ({rule['cwe']})"
        results.append(result)

    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SentryLocal",
                    "version": "2.0.0",
                    "rules": [
                        {"id": r["id"], "shortDescription": {"text": r["description"]}}
                        for r in {f["rule"]["id"]: f["rule"] for f in findings}.values()
                    ]
                }
            },
            "results": results,
        }]
    }
    return json.dumps(sarif, indent=2)
```

Add `"sarif"` to the `--format` choices in `main.py` and to the `generators` dict in `write_report`.

### Step 5.2 — Test it

```python
def test_sarif_output_is_valid_json():
    from sentrylocal.report import generate_sarif_report
    rules = load_rules()
    findings = scan_file(os.path.join(FIXTURES_DIR, "test_vulnerable_code.py"), rules)
    sarif = json.loads(generate_sarif_report(findings))
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == len(findings)
```

> **Checkpoint 5:** `python main.py tests/fixtures --format sarif --output report.sarif` produces a valid SARIF file. Open it in VS Code or validate it against the SARIF schema.

---

## Phase 6 — Benchmark & documentation (stretch goal)

**Why.** A small benchmark table and an updated readme make the project feel finished and give you material for a write-up.

### Step 6.1 — Benchmark script

Create `benchmark.py` at the project root:

```python
"""Compare rule-only vs rule+LLM triage on the fixture set."""
import time
from sentrylocal.scanner import scan_directory
from sentrylocal.llm import triage_findings

FIXTURES = "tests/fixtures"

t0 = time.perf_counter()
findings = scan_directory(FIXTURES)
t_scan = time.perf_counter() - t0

t0 = time.perf_counter()
triaged = triage_findings(findings, threshold="HIGH")
t_llm = time.perf_counter() - t0

tp = sum(1 for f in triaged if f.get("triage", {}).get("verdict") == "true_positive")
fp = sum(1 for f in triaged if f.get("triage", {}).get("verdict") == "false_positive")
nr = sum(1 for f in triaged if f.get("triage", {}).get("verdict") == "needs_review")

print(f"Findings: {len(findings)}")
print(f"Scan time: {t_scan:.3f}s")
print(f"LLM triage time: {t_llm:.3f}s")
print(f"True positive: {tp}, False positive: {fp}, Needs review: {nr}")
```

### Step 6.2 — Update the readme

- Update the **Roadmap** section: check off "Detect dynamically constructed SQL queries" and "Optional local LLM-assisted analysis."
- Add a **v2 features** section describing the LLM triage, CWE mapping, and SARIF export.
- Add a **Running with LLM triage** section with the `--llm` flag and the local LLM backend setup (llama.cpp `llama serve` or Ollama).

> **Checkpoint 6:** `python benchmark.py` runs and prints a sensible table. The readme reflects the new features.

---

## Suggested commit order

Each phase maps to one or two commits. This keeps your git history clean and makes it easy to review or revert:

1. `feat: detect dynamic SQL (f-strings and concatenation)`
2. `feat: add pickle, subprocess-shell, and weak-hash rules`
3. `feat: map findings to CWE identifiers`
4. `feat: add local LLM triage layer (llama.cpp / Ollama backend)`
5. `feat: add SARIF report export`
6. `docs: update readme and add benchmark script`

---

## What you'll have learned

By the end of this plan you'll have hands-on experience with:

- **AST manipulation** — walking Python's syntax tree, handling `JoinedStr`, `BinOp`, `Call`, `Assign` nodes
- **Rule-based static analysis** — structuring rules as data, extending a visitor pattern
- **Local LLM integration** — calling a model over HTTP, parsing structured output, graceful fallback
- **Security standards** — CWE identifiers, SARIF format
- **Testing** — fixtures, unit tests, testing fallback paths, benchmarking
- **Two-stage analysis** — the pattern of combining a fast deterministic engine with a slower, nuanced model (a pattern that appears across ML systems and security tooling)
