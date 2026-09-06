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
        choices=["text", "json", "html"],
        default="text",
        help="Report format (default: text, printed to terminal)"
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Write the report to FILE instead of printing to the terminal. "
             "Required for json/html formats."
    )

    args = parser.parse_args()

    findings = scan_directory(args.directory)

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