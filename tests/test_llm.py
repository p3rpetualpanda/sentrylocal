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
