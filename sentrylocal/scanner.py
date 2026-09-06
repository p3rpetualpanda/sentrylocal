# scanner.py
import os
import ast
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


class SecurityVisitor(ast.NodeVisitor):
    """
    Walks the AST of a Python file and collects findings.
    Because this operates on parsed syntax rather than raw text, it never
    matches comments (they aren't part of the AST at all) and only matches
    string literals when they're actually being used - e.g. assigned to a
    variable or passed as an argument - not when merely described in a
    docstring or comment.
    """

    def __init__(self, filepath, source_lines, rules):
        self.filepath = filepath
        self.source_lines = source_lines
        self.rules = rules
        self.findings = []
        self._imported_modules = set()

    def _code_line(self, lineno):
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def _add_finding(self, lineno, rule_key, rule_override=None):
        self.findings.append({
            "file": self.filepath,
            "line": lineno,
            "code": self._code_line(lineno),
            "rule": rule_override or RULE_METADATA[rule_key],
        })

    def visit_Call(self, node):
        # eval(...)
        if isinstance(node.func, ast.Name) and node.func.id == "eval":
            self._add_finding(node.lineno, "eval")

        # os.system(...)
        if (isinstance(node.func, ast.Attribute)
                and node.func.attr == "system"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os"):
            self._add_finding(node.lineno, "os_system")

        self.generic_visit(node)

    def visit_Import(self, node):
        for alias in node.names:
            self._check_insecure_import(alias.name, node.lineno)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            self._check_insecure_import(node.module, node.lineno)
        self.generic_visit(node)

    def _check_insecure_import(self, module_name, lineno):
        for import_rule in self.rules.get("insecure_imports", []):
            target = import_rule.get("module", "")
            if module_name == target and target not in self._imported_modules:
                self._imported_modules.add(target)
                meta = dict(RULE_METADATA["insecure_imports"])
                meta["description"] = import_rule.get("reason", meta["description"])
                self._add_finding(lineno, "insecure_imports", rule_override=meta)

    def visit_Assign(self, node):
        # Hard-coded secrets: NAME = "some non-empty string"
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            value = node.value.value
            for target in node.targets:
                if isinstance(target, ast.Name):
                    for secret_name in self.rules.get("secrets", []):
                        if target.id == secret_name and value != "":
                            self._add_finding(node.lineno, "secrets")

            # Unsafe SQL query construction: flag static query strings
            # containing risky patterns. Parameterized queries (built with
            # a "?" placeholder) are treated as safe.
            for query_pattern in self.rules.get("unsafe_queries", []):
                if query_pattern in value and "?" not in value:
                    self._add_finding(node.lineno, "unsafe_queries")

        self.generic_visit(node)


def scan_file(filepath, rules):
    """Scan a single file and return a list of finding dicts."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
            source = file.read()
    except Exception as e:
        print(f"Error scanning file {filepath}: {e}")
        return []

    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError as e:
        print(f"Skipping {filepath}: could not parse ({e})")
        return []

    source_lines = source.splitlines()
    visitor = SecurityVisitor(filepath, source_lines, rules)
    visitor.visit(tree)
    return visitor.findings


def scan_directory(directory):
    """Walk a directory, scan every .py file, and return combined findings."""
    rules = load_rules()
    if not rules:
        print("No rules loaded. Exiting.")
        return []

    EXCLUDED_DIRS = {'venv', '.venv', 'env', '.git', '__pycache__', 'node_modules', '.continue'}

    all_findings = []
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]

        for f in files:
            if f.endswith('.py'):
                filepath = os.path.join(root, f)
                all_findings.extend(scan_file(filepath, rules))

    return all_findings