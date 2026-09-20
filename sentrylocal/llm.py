# llm.py
"""Optional local LLM triage layer for SentryLocal.

Sends each finding to a local LLM backend (llama.cpp or Ollama) and asks it to
classify the finding as true_positive / false_positive / needs_review.

Design decisions:
- One finding at a time, with a focused prompt (short prompts, reliable output).
- Structured JSON output: {"verdict", "confidence", "explanation"}.
- Graceful fallback: if the backend is down or errors, return a "needs_review"
  verdict so the scanner never crashes because of the LLM.
- Backend-agnostic: only the URL, request body, and response shape differ.

Uses stdlib urllib so no extra dependency is required.
"""
import json
import http.client
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
    except (OSError, http.client.HTTPException, ValueError) as e:
        # OSError covers URLError and socket.timeout; ValueError covers
        # json.JSONDecodeError and the "No JSON in LLM response" case.
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
