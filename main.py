#!/usr/bin/env python3
"""SafeAlter CLI — catch backward-incompatible schema changes before deploy."""
import argparse
import json
import sys
from pathlib import Path
from safealter import parse_migrations, find_violations, to_sarif, to_json

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
    ap.add_argument("--fail-on-warning", action="store_true",
        help="Exit 1 on warnings too, not just errors")
    args = ap.parse_args(argv)

    sqls = collect(args.migrations, {".sql"})
    codes = collect(args.code, CODE_EXTS)

    changes = []
    for fname, content in sqls.items():
        changes.extend(parse_migrations(content, fname))

    violations = find_violations(changes, codes)

    if args.format == "json":
        print(to_json(violations))
    elif args.format == "sarif":
        print(json.dumps(to_sarif(violations), indent=2))
    else:
        for v in violations:
            icon = "\u274c" if v.severity == "error" else "\u26a0\ufe0f"
            print(f"{icon} [{v.kind}] {v.table}.{v.column or '*'}")
            print(f"   migration: {v.migration_file}:{v.migration_line}")
            print(f"   code ref:  {v.code_file}:{v.code_line} \u2192 {v.snippet}")
        if not violations:
            print("\u2705 No backward-incompatible references found.")

    errs = sum(1 for v in violations if v.severity == "error")
    warns = len(violations) - errs
    if errs:
        print(f"\n\U0001f4a5 {errs} error(s), {warns} warning(s)", file=sys.stderr)
        return 1
    if warns and args.fail_on_warning:
        print(f"\n\u26a0\ufe0f {warns} warning(s) (--fail-on-warning)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
