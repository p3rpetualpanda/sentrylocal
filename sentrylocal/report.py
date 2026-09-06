# report.py
import json
from datetime import datetime


def generate_text_report(findings):
    """Return the plain-text report as a string (same format as the original CLI output)."""
    if not findings:
        return "No issues found."

    lines = [f"Found {len(findings)} issue(s):\n"]
    for f in findings:
        rule = f["rule"]
        lines.append(f"[{rule['severity']}] {rule['id']} - {f['file']}:{f['line']}")
        lines.append(f"    {f['code']}")
        lines.append(f"    {rule['description']}\n")

    return "\n".join(lines)


def generate_json_report(findings):
    """Return the findings as a formatted JSON string."""
    report = {
        "generated_at": datetime.now().isoformat(),
        "issue_count": len(findings),
        "findings": findings,
    }
    return json.dumps(report, indent=2)


def generate_html_report(findings):
    """Return a standalone HTML report as a string."""
    severity_colors = {
        "HIGH": "#d32f2f",
        "MEDIUM": "#f57c00",
        "LOW": "#fbc02d",
    }

    rows = []
    for f in findings:
        rule = f["rule"]
        color = severity_colors.get(rule["severity"], "#666")
        rows.append(f"""
        <tr>
            <td><span style="color:{color}; font-weight:bold;">{rule['severity']}</span></td>
            <td>{rule['id']}</td>
            <td>{f['file']}</td>
            <td>{f['line']}</td>
            <td><code>{_escape(f['code'])}</code></td>
            <td>{rule['description']}</td>
        </tr>""")

    rows_html = "".join(rows) if rows else "<tr><td colspan='6'>No issues found.</td></tr>"

    return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>SentryLocal Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 2rem; background: #1e1e1e; color: #ddd; }}
        h1 {{ color: #fff; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
        th, td {{ border: 1px solid #444; padding: 8px 12px; text-align: left; }}
        th {{ background: #2a2a2a; }}
        code {{ background: #2a2a2a; padding: 2px 4px; border-radius: 3px; }}
        .summary {{ color: #aaa; margin-bottom: 1rem; }}
    </style>
</head>
<body>
    <h1>SentryLocal Scan Report</h1>
    <p class="summary">Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &mdash; {len(findings)} issue(s) found</p>
    <table>
        <thead>
            <tr><th>Severity</th><th>Rule</th><th>File</th><th>Line</th><th>Code</th><th>Description</th></tr>
        </thead>
        <tbody>{rows_html}</tbody>
    </table>
</body>
</html>"""


def _escape(text):
    """Minimal HTML escaping for code snippets."""
    return (text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;"))


def write_report(findings, output_format, output_path):
    """Generate a report in the given format and write it to output_path."""
    generators = {
        "text": generate_text_report,
        "json": generate_json_report,
        "html": generate_html_report,
    }

    if output_format not in generators:
        raise ValueError(f"Unknown format '{output_format}'. Choose from: {list(generators.keys())}")

    content = generators[output_format](findings)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)

    return output_path