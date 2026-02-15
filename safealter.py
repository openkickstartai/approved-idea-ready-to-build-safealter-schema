"""SafeAlter — zero-downtime migration cross-validator engine."""
import re
import json
from dataclasses import dataclass, field
from pathlib import Path
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
        r"ALTER\s+TABLE\s+[`\"]?(\w+)[`\"]?\s+DROP\s+(?:COLUMN\s+)?[`\"]?(\w+)", re.I)),
    ("rename_column", "error", re.compile(
        r"ALTER\s+TABLE\s+[`\"]?(\w+)[`\"]?\s+RENAME\s+COLUMN\s+[`\"]?(\w+)", re.I)),
    ("drop_table", "error", re.compile(
        r"DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?[`\"]?(\w+)", re.I)),
    ("not_null_no_default", "warning", re.compile(
        r"ALTER\s+TABLE\s+[`\"]?(\w+)[`\"]?\s+ADD\s+(?:COLUMN\s+)?[`\"]?(\w+)[`\"]?\s+\w+[^;]*?NOT\s+NULL(?![^;]*?DEFAULT)", re.I)),
    ("change_type", "warning", re.compile(
        r"ALTER\s+TABLE\s+[`\"]?(\w+)[`\"]?\s+ALTER\s+COLUMN\s+[`\"]?(\w+)[`\"]?\s+(?:SET\s+DATA\s+)?TYPE", re.I)),
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
    """Cross-validate schema changes against application code to find broken refs."""
    violations = []
    for ch in changes:
        for fpath, content in code_files.items():
            for ln, line in enumerate(content.splitlines(), 1):
                if not (fpath.endswith(".sql") or _SQL_KW.search(line) or "'" in line or '"' in line):
                    continue
                if ch.kind == "drop_table" and re.search(r"\b" + re.escape(ch.table) + r"\b", line):
                    violations.append(Violation(
                        ch.kind, ch.table, "", ch.file, ch.line, fpath, ln, line.strip(), ch.severity))
                elif ch.column and re.search(r"\b" + re.escape(ch.column) + r"\b", line):
                    if re.search(r"\b" + re.escape(ch.table) + r"\b", content):
                        violations.append(Violation(
                            ch.kind, ch.table, ch.column, ch.file, ch.line, fpath, ln, line.strip(), ch.severity))
    return violations


def to_sarif(violations: List[Violation]) -> dict:
    """Convert violations to SARIF 2.1.0 format for GitHub Security integration."""
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "SafeAlter", "version": "1.0.0"}}, "results": [{
                "ruleId": f"safealter/{v.kind}", "level": "error" if v.severity == "error" else "warning",
                "message": {"text": f"{v.kind}: {v.table}.{v.column or '*'} still referenced at {v.code_file}:{v.code_line}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": v.code_file},
                    "region": {"startLine": v.code_line}}}],
            } for v in violations]}]}


def to_json(violations: List[Violation]) -> str:
    """Convert violations to a flat JSON array."""
    return json.dumps([{"kind": v.kind, "table": v.table, "column": v.column,
        "migration": f"{v.migration_file}:{v.migration_line}",
        "reference": f"{v.code_file}:{v.code_line}", "snippet": v.snippet,
        "severity": v.severity} for v in violations], indent=2)


@dataclass
class Config:
    """SafeAlter configuration loaded from .safealter.json."""
    rules_disabled: List[str] = field(default_factory=list)
    severity_override: Dict[str, str] = field(default_factory=dict)
    scan_paths: List[str] = field(default_factory=lambda: ["."])
    exclude_patterns: List[str] = field(default_factory=list)
    dialect: str = "postgresql"

    @classmethod
    def default(cls) -> "Config":
        """Return a Config with all default values."""
        return cls()

    @classmethod
    def load(cls, path: str) -> "Config":
        """Load configuration from a .safealter.json file."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        with open(p, "r") as f:
            data = json.load(f)
        rules = data.get("rules", {})
        return cls(
            rules_disabled=rules.get("disabled", []),
            severity_override=data.get("severity_override", {}),
            scan_paths=data.get("scan_paths", ["."]),
            exclude_patterns=data.get("exclude_patterns", []),
            dialect=data.get("dialect", "postgresql"),
        )


def filter_violations(violations: List[Violation], config: Config) -> List[Violation]:
    """Filter violations based on config: remove disabled rules, apply severity overrides."""
    result = []
    for v in violations:
        if v.kind in config.rules_disabled:
            continue
        if v.kind in config.severity_override:
            v = Violation(
                kind=v.kind,
                table=v.table,
                column=v.column,
                migration_file=v.migration_file,
                migration_line=v.migration_line,
                code_file=v.code_file,
                code_line=v.code_line,
                snippet=v.snippet,
                severity=config.severity_override[v.kind],
            )
        result.append(v)
    return result
