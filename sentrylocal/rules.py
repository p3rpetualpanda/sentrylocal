import re

# Each rule is a dict: id, description, severity, and a regex pattern to match
RULES = [
    {
        "id": "PY-EVAL-001",
        "description": "Use of eval() can allow arbitrary code execution if input is not trusted",
        "severity": "HIGH",
        "pattern": re.compile(r"\beval\s*\(")
    }
]


def check_line(line):
    """
    Check a single line of code against all rules.
    Returns a list of matched rule dicts (empty if no matches).
    """
    matches = []
    for rule in RULES:
        if rule["pattern"].search(line):
            matches.append(rule)
    return matches