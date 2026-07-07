import os
from sentrylocal.rules import check_line


EXCLUDED_DIRS = {"venv", ".venv", "env", "__pycache__", ".git", "site-packages", "node_modules"}


def find_python_files(directory):
    """
    Walk a directory and yield paths to all .py files found,
    skipping common non-project directories.
    """
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        for file in files:
            if file.endswith(".py"):
                yield os.path.join(root, file)

def scan_file(filepath):
    """
    Scan a single file line by line, returning a list of findings.
    """
    findings = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line_number, line in enumerate(f, start=1):
            matches = check_line(line)
            for rule in matches:
                findings.append({
                    "file": filepath,
                    "line": line_number,
                    "code": line.strip(),
                    "rule": rule
                })
    return findings


def scan_directory(directory):
    """
    Scan every .py file in a directory tree, returning all findings.
    """
    all_findings = []
    for filepath in find_python_files(directory):
        all_findings.extend(scan_file(filepath))
    return all_findings