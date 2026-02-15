"""SafeAlter \u2014 zero-downtime migration cross-validator engine."""
import re
import json
from dataclasses import dataclass
from typing import List, Dict


@dataclass
class SchemaChange:
    kind: str
    table: str
    column: str = ""
    file: str = ""
    line: int = 0
    severity: str = "error"


@dataclass
class Violation:
    kind: str
    table: str
    column: str
    migration_file: str
    migration_line: int
    code_file: str
    code_line: int
    snippet: str
    severity: str = "error"


DDL_RULES = [
    ("drop_column", "error", re.compile(
        r"ALTER\s+TABLE\s+[`\"']?(\w+)[`\"']?\s+DROP\s+(?:COLUMN\s+)?[`\"']?(\w+)", re.I)),
    ("rename_column", "error", re.compile(
        r"ALTER\s+TABLE\s+[`\"']?(\w+)[`\"']?\s+RENAME\s+COLUMN\s+[`\"']?(\w+)", re.I)),
    ("drop_table", "error", re.compile(
        r"DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?[`\"']?(\w+)", re.I)),
    ("not_null_no_default", "warning", re.compile(
        r"ALTER\s+TABLE\s+[`\"']?(\w+)[`\"']?\s+ADD\s+(?:COLUMN\s+)?[`\"']?(\w+)[`\"']?\s+\w+[^;]*?NOT\s+NULL(?![^;]*?DEFAULT)", re.I)),
    ("change_type", "warning", re.compile(
        r"ALTER\s+TABLE\s+[`\"']?(\w+)[`\"']?\s+ALTER\s+COLUMN\s+[`\"']?(\w+)[`\"']?\s+(?:SET\s+DATA\s+)?TYPE", re.I)),
]
_SQL_KW = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|FROM|JOIN|WHERE)\b", re.I)


def parse_migrations(sql: str, filename: str = "migration.sql") -> List[SchemaChange]:
    """Extract backward-incompatible schema changes from SQL DDL text."""
    changes = []
    for lineno, line in enumerate(sql.splitlines(), 1):
        for kind, sev, pat in DDL_RULES:
            for m in pat.finditer(line):
                col = m.group(2) if m.lastindex and m.lastindex >= 2 else ""
                changes.append(SchemaChange(kind, m.group(1), col, filename, lineno, sev))
    return changes


def find_violations(changes: List[SchemaChange], code_files: Dict[str, str]) -> List[Violation]:
    """Cross-validate schema changes against application code to find broken references."""
    violations = []
    for ch in changes:
        target = ch.column if ch.column else ch.table
        for fpath, content in code_files.items():
            for lineno, line in enumerate(content.splitlines(), 1):
                if not _SQL_KW.search(line):
                    continue
                if re.search(r'\b' + re.escape(target) + r'\b', line, re.I):
                    violations.append(Violation(
                        kind=ch.kind, table=ch.table, column=ch.column,
                        migration_file=ch.file, migration_line=ch.line,
                        code_file=fpath, code_line=lineno,
                        snippet=line.strip(), severity=ch.severity,
                    ))
    return violations


def to_json(violations: List[Violation]) -> str:
    """Format violations as JSON output matching the SafeAlter schema."""
    findings = []
    for v in violations:
        ref = f"{v.table}.{v.column}" if v.column else v.table
        findings.append({
            "rule": v.kind,
            "severity": v.severity,
            "location": {
                "file": v.code_file,
                "line": v.code_line,
            },
            "message": f"{v.kind}: {ref} referenced in {v.code_file}:{v.code_line}",
            "migration_statement": f"{v.migration_file}:{v.migration_line}",
        })
    return json.dumps({"version": "0.1", "findings": findings}, indent=2)


def to_sarif(violations: List[Violation]) -> dict:
    """Format violations as SARIF v2.1.0 output for GitHub Code Scanning."""
    rules_map: Dict[str, dict] = {}
    results = []
    for v in violations:
        rule_id = v.kind
        if rule_id not in rules_map:
            rules_map[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": rule_id.replace("_", " ").title()},
                "defaultConfiguration": {
                    "level": "error" if v.severity == "error" else "warning"
                },
            }
        ref = f"{v.table}.{v.column}" if v.column else v.table
        results.append({
            "ruleId": rule_id,
            "level": "error" if v.severity == "error" else "warning",
            "message": {
                "text": f"{v.kind}: {ref} referenced in {v.code_file}:{v.code_line}"
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": v.code_file},
                    "region": {"startLine": v.code_line},
                }
            }],
        })
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SafeAlter",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/safealter/safealter",
                    "rules": list(rules_map.values()),
                }
            },
            "results": results,
        }],
    }


def format_results(violations: List[Violation], fmt: str = "text") -> str:
    """Format violations in the requested output format: text, json, or sarif."""
    if fmt == "json":
        return to_json(violations)
    if fmt == "sarif":
        return json.dumps(to_sarif(violations), indent=2)
    # Default: human-readable text
    lines = []
    errors = sum(1 for v in violations if v.severity == "error")
    warnings = sum(1 for v in violations if v.severity == "warning")
    for v in violations:
        icon = "\u274c" if v.severity == "error" else "\u26a0\ufe0f"
        ref = f"{v.table}.{v.column}" if v.column else v.table
        lines.append(f"{icon} [{v.kind}] {ref}")
        lines.append(f"  Migration: {v.migration_file}:{v.migration_line}")
        lines.append(f"  Code ref:  {v.code_file}:{v.code_line}: {v.snippet}")
    lines.append(f"")
    lines.append(f"\U0001f4a5 {errors} error(s), {warnings} warning(s)")
    return "\n".join(lines)
