# scanner.py
import os
import json

RULE_METADATA = {
    "eval": {
        "id": "eval-use",
        "severity": "HIGH",
        "description": "Use of eval() is dangerous and should be avoided."
    },
    "secrets": {
        "id": "hardcoded-secret",
        "severity": "HIGH",
        "description": "Hard-coded secret detected."
    },
    "unsafe_queries": {
        "id": "sql-injection",
        "severity": "HIGH",
        "description": "Potential SQL injection vulnerability detected."
    },
    "os_system": {
        "id": "os-system-use",
        "severity": "MEDIUM",
        "description": "Use of os.system() is dangerous and can lead to command injection."
    },
    "insecure_imports": {
        "id": "insecure-import",
        "severity": "MEDIUM",
        "description": "Insecure or risky module imported."
    },
}


def load_rules():
    try:
        with open('sentrylocal/rules.json', 'r') as file:
            rules = json.load(file)
        return rules
    except Exception as e:
        print(f"Error loading rules: {e}")
        return {}


def scan_file(filepath, rules):
    """Scan a single file and return a list of finding dicts."""
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
            lines = file.readlines()

        imported_modules = set()

        for i, line in enumerate(lines, start=1):
            stripped = line.strip()

            # eval()
            if "eval(" in line:
                findings.append({
                    "file": filepath,
                    "line": i,
                    "code": stripped,
                    "rule": RULE_METADATA["eval"],
                })

            # hard-coded secrets
            for secret in rules.get("secrets", []):
                if secret in line and f'{secret} = ""' not in line:
                    findings.append({
                        "file": filepath,
                        "line": i,
                        "code": stripped,
                        "rule": RULE_METADATA["secrets"],
                    })

            # unsafe queries
            for query in rules.get("unsafe_queries", []):
                if query in line and '?' not in line:
                    findings.append({
                        "file": filepath,
                        "line": i,
                        "code": stripped,
                        "rule": RULE_METADATA["unsafe_queries"],
                    })

            # os.system()
            if "os.system(" in line:
                findings.append({
                    "file": filepath,
                    "line": i,
                    "code": stripped,
                    "rule": RULE_METADATA["os_system"],
                })

            # insecure imports
            for import_rule in rules.get("insecure_imports", []):
                module = import_rule.get("module", "")
                if f"import {module}" in line and module not in imported_modules:
                    imported_modules.add(module)
                    meta = dict(RULE_METADATA["insecure_imports"])
                    meta["description"] = import_rule.get("reason", meta["description"])
                    findings.append({
                        "file": filepath,
                        "line": i,
                        "code": stripped,
                        "rule": meta,
                    })

    except Exception as e:
        print(f"Error scanning file {filepath}: {e}")

    return findings


def scan_directory(directory):
    """Walk a directory, scan every .py file, and return combined findings."""
    rules = load_rules()
    if not rules:
        print("No rules loaded. Exiting.")
        return []

    EXCLUDED_DIRS = {'venv', '.venv', 'env', '.git', '__pycache__', 'node_modules', '.continue'}

    all_findings = []
    for root, dirs, files in os.walk(directory):
        # Modify dirs in-place so os.walk skips descending into excluded folders
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]

        for f in files:
            if f.endswith('.py'):
                filepath = os.path.join(root, f)
                all_findings.extend(scan_file(filepath, rules))

    return all_findings