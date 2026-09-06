# tests/test_scanner.py
import os
import sys

# Allow imports from the project root when running pytest from anywhere
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sentrylocal.scanner import scan_file, load_rules

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), 'fixtures')


def get_findings(filename):
    """Helper: run scan_file on a fixture and return its findings."""
    rules = load_rules()
    filepath = os.path.join(FIXTURES_DIR, filename)
    return scan_file(filepath, rules)


def rule_ids(findings):
    """Helper: extract just the rule ids from a findings list, for easy assertions."""
    return [f["rule"]["id"] for f in findings]


class TestVulnerableCode:
    """test_vulnerable_code.py should trigger multiple known rules."""

    def setup_method(self):
        self.findings = get_findings("test_vulnerable_code.py")
        self.ids = rule_ids(self.findings)

    def test_detects_eval(self):
        assert "eval-use" in self.ids

    def test_detects_hardcoded_secret(self):
        assert "hardcoded-secret" in self.ids

    def test_detects_sql_injection(self):
        assert "sql-injection" in self.ids

    def test_detects_os_system(self):
        assert "os-system-use" in self.ids

    def test_findings_have_required_fields(self):
        for finding in self.findings:
            assert "file" in finding
            assert "line" in finding
            assert "code" in finding
            assert "rule" in finding
            assert "severity" in finding["rule"]
            assert "description" in finding["rule"]


class TestVulnerable:
    """test_vulnerable.py — simpler fixture, just eval() on user input."""

    def test_detects_eval_on_user_input(self):
        ids = rule_ids(get_findings("test_vulnerable.py"))
        assert "eval-use" in ids


class TestCleanCode:
    """test_clean_code.py should trigger NO findings at all."""

    def test_no_findings_in_clean_code(self):
        findings = get_findings("test_clean_code.py")
        assert findings == []


class TestSecureCode:
    """
    test_secure_code.py contains a genuine eval() call on a hardcoded,
    harmless string (eval("1 + 2")). Detection is AST-based, so it
    correctly identifies this as a real eval() call - static analysis
    has no way to know the input is safe, so flagging it is the correct,
    conservative behaviour rather than a false positive.
    """

    def test_correctly_flags_eval_regardless_of_safe_input(self):
        ids = rule_ids(get_findings("test_secure_code.py"))
        assert "eval-use" in ids


def test_scan_missing_file_returns_no_findings():
    """Scanning a file that doesn't exist should fail gracefully, not crash."""
    rules = load_rules()
    findings = scan_file(os.path.join(FIXTURES_DIR, "does_not_exist.py"), rules)
    assert findings == []