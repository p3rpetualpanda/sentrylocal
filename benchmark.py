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
