#!/usr/bin/env python3
"""SafeAlter CLI \u2014 catch backward-incompatible schema changes before deploy."""
import argparse
import sys
from pathlib import Path
from safealter import parse_migrations, find_violations, format_results

CODE_EXTS = {".py", ".sql", ".go", ".java", ".ts", ".js", ".rb", ".kt", ".rs"}


def collect(paths, exts=None):
    """Recursively collect file contents from paths."""
    files = {}
    for p in paths:
        pp = Path(p)
        targets = pp.rglob("*") if pp.is_dir() else [pp]
        for f in targets:
            if f.is_file() and (exts is None or f.suffix in exts):
                files[str(f)] = f.read_text(errors="ignore")
    return files


def main(argv=None):
    """Entry point for the SafeAlter CLI."""
    ap = argparse.ArgumentParser(prog="safealter",
        description="Zero-downtime migration cross-validator")
    ap.add_argument("-m", "--migrations", nargs="+", required=True,
        help="SQL migration files or directories")
    ap.add_argument("-c", "--code", nargs="+", required=True,
        help="Application code files or directories to scan")
    ap.add_argument("-f", "--format", choices=["text", "json", "sarif"], default="text",
        help="Output format (default: text)")
    ap.add_argument("-o", "--output", default=None,
        help="Write output to file instead of stdout")
    ap.add_argument("--fail-on-warning", action="store_true",
        help="Exit 1 on warnings too, not just errors")
    args = ap.parse_args(argv)

    sqls = collect(args.migrations, {".sql"})
    codes = collect(args.code, CODE_EXTS)

    changes = []
    for fname, content in sqls.items():
        changes.extend(parse_migrations(content, fname))

    violations = find_violations(changes, codes)

    output = format_results(violations, args.format)

    if args.output:
        Path(args.output).write_text(output + "\n")
    else:
        print(output)

    has_errors = any(v.severity == "error" for v in violations)
    has_warnings = any(v.severity == "warning" for v in violations)

    if has_errors or (args.fail_on_warning and has_warnings):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
