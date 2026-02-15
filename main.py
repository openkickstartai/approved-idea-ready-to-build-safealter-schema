#!/usr/bin/env python3
"""SafeAlter CLI — catch backward-incompatible schema changes before deploy."""
import argparse
import fnmatch
import json
import sys
from pathlib import Path
from safealter import (
    parse_migrations, find_violations, to_sarif, to_json,
    Config, filter_violations,
)

CODE_EXTS = {".py", ".sql", ".go", ".java", ".ts", ".js", ".rb", ".kt", ".rs"}


def collect(paths, exts=None, exclude_patterns=None):
    """Recursively collect file contents from paths."""
    files = {}
    for p in paths:
        pp = Path(p)
        targets = pp.rglob("*") if pp.is_dir() else [pp]
        for f in targets:
            if f.is_file() and (exts is None or f.suffix in exts):
                if exclude_patterns and any(
                    fnmatch.fnmatch(str(f), pat) or fnmatch.fnmatch(f.name, pat)
                    for pat in exclude_patterns
                ):
                    continue
                files[str(f)] = f.read_text(errors="ignore")
    return files


def _find_config():
    """Auto-detect .safealter.json in current or parent directories."""
    cwd = Path.cwd()
    for d in [cwd, *cwd.parents]:
        candidate = d / ".safealter.json"
        if candidate.exists():
            return str(candidate)
    return None


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
    ap.add_argument("--config", default=None,
        help="Path to .safealter.json config file (auto-detected if not specified)")
    args = ap.parse_args(argv)

    # Load configuration
    config_path = args.config or _find_config()
    config = Config.load(config_path) if config_path else Config.default()

    sqls = collect(args.migrations, {".sql"}, config.exclude_patterns)
    codes = collect(args.code, CODE_EXTS, config.exclude_patterns)

    changes = []
    for fname, content in sqls.items():
        changes.extend(parse_migrations(content, fname))

    violations = find_violations(changes, codes)
    violations = filter_violations(violations, config)

    if args.format == "json":
        print(to_json(violations))
    elif args.format == "sarif":
        print(json.dumps(to_sarif(violations), indent=2))
    else:
        for v in violations:
            icon = "\u274c" if v.severity == "error" else "\u26a0\ufe0f"
            loc = f"{v.table}.{v.column}" if v.column else v.table
            print(f"{icon} [{v.kind}] {loc}")
            print(f"   Migration: {v.migration_file}:{v.migration_line}")
            print(f"   Code:      {v.code_file}:{v.code_line}")
            print(f"   Snippet:   {v.snippet.strip()}")
            print()
        errs = sum(1 for v in violations if v.severity == "error")
        warns = sum(1 for v in violations if v.severity == "warning")
        print(f"\U0001f4a5 {errs} error(s), {warns} warning(s)")

    has_errors = any(v.severity == "error" for v in violations)
    has_warnings = any(v.severity == "warning" for v in violations)
    if has_errors or (args.fail_on_warning and has_warnings):
        sys.exit(1)


if __name__ == "__main__":
    main()
