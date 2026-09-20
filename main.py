import argparse
import sys

from sentrylocal.scanner import scan_directory
from sentrylocal.report import generate_text_report, write_report


def main():
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="SentryLocal - local, privacy-preserving Python code security scanner"
    )
    parser.add_argument("directory", help="Directory to scan")
    parser.add_argument(
        "--format",
        choices=["text", "json", "html", "sarif"],
        default="text",
        help="Report format (default: text, printed to terminal)"
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Write the report to FILE instead of printing to the terminal. "
             "Required for json/html/sarif formats."
    )
    parser.add_argument(
        "--llm",
        action="store_true",
        help="Run LLM triage on findings (requires a local LLM backend: llama.cpp or Ollama)"
    )
    parser.add_argument(
        "--llm-threshold",
        choices=["LOW", "MEDIUM", "HIGH"],
        default="HIGH",
        help="Minimum severity to triage with the LLM (default: HIGH)"
    )

    args = parser.parse_args()

    findings = scan_directory(args.directory)

    if args.llm:
        from sentrylocal.llm import triage_findings
        findings = triage_findings(findings, threshold=args.llm_threshold)

    if args.format == "text" and not args.output:
        # Default behaviour: print straight to the terminal
        print(generate_text_report(findings))
        return

    if not args.output:
        print(f"Error: --format {args.format} requires --output <file>", file=sys.stderr)
        sys.exit(1)

    write_report(findings, args.format, args.output)
    print(f"Report written to {args.output} ({len(findings)} issue(s) found)")


if __name__ == "__main__":
    main()