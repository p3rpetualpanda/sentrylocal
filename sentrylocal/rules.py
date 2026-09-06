import json
import os

def load_rules():
    # Ensure the script can find rules.json in the same directory as rules.py
    current_dir = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(current_dir, 'rules.json'), 'r') as file:
        return json.load(file)

RULES = load_rules()

def check_line(line):
    findings = []
    
    # Rule to detect use of eval()
    for rule in RULES.get("eval", []):
        if "eval(" in line:
            findings.append(rule)
    
    # Rule to detect hard-coded secrets
    for secret in RULES.get("secrets", []):
        if secret in line:
            findings.append(f"Hard-coded secret '{secret}' detected.")
    
    # Rule to detect unsafe database queries
    for query in RULES.get("unsafe_queries", []):
        if any(q in line for q in RULES["unsafe_queries"]):
            findings.append("Potential SQL injection vulnerability detected.")
    
    # Rule to detect use of os.system()
    for rule in RULES.get("os_system", []):
        if "os.system(" in line:
            findings.append(rule)
    
    # Rule to detect insecure imports
    for import_rule in RULES.get("insecure_imports", []):
        module = import_rule.get("module")
        reason = import_rule.get("reason")
        if f"import {module}" in line or f"from {module} import" in line:
            findings.append(f"Insecure import of '{module}'. {reason}")
    
    return findings 