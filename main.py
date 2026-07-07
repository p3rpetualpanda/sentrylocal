import sys
from sentrylocal.scanner import scan_directory


def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <directory_to_scan>")
        sys.exit(1)

    target_dir = sys.argv[1]
    findings = scan_directory(target_dir)

    if not findings:
        print("No issues found.")
        return

    print(f"Found {len(findings)} issue(s):\n")
    for f in findings:
        rule = f["rule"]
        print(f"[{rule['severity']}] {rule['id']} - {f['file']}:{f['line']}")
        print(f"    {f['code']}")
        print(f"    {rule['description']}\n")


if __name__ == "__main__":
    main()