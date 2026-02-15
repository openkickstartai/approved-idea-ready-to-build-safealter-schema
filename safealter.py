"""SafeAlter \u2014 zero-downtime migration cross-validator engine."""
import re
import os
import json
from dataclasses import dataclass, asdict
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


@dataclass
class CodeReference:
    """A reference to a table or column name found in application code."""
    file_path: str
    line_number: int
    line_content: str
    ref_type: str   # "raw_sql" | "sqlalchemy_column" | "orm_attribute" | "table_name"
    name: str       # the column or table name referenced


@dataclass
class CrossValidationResult:
    """Result of cross-validating a migration change against a code reference."""
    affected_file: str
    line_number: int
    column_name: str
    table_name: str
    migration_statement: str
    risk_level: str   # "high" | "medium" | "low"


# ---------------------------------------------------------------------------
# DDL parsing
# ---------------------------------------------------------------------------

DDL_RULES = [
    ("drop_column", "error", re.compile(
        r"ALTER\s+TABLE\s+[`\"\']?(\w+)[`\"\']?\s+DROP\s+(?:COLUMN\s+)?[`\"\']?(\w+)", re.I)),
    ("rename_column", "error", re.compile(
        r"ALTER\s+TABLE\s+[`\"\']?(\w+)[`\"\']?\s+RENAME\s+COLUMN\s+[`\"\']?(\w+)", re.I)),
    ("drop_table", "error", re.compile(
        r"DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?[`\"\']?(\w+)", re.I)),
    ("not_null_no_default", "warning", re.compile(
        r"ALTER\s+TABLE\s+[`\"\']?(\w+)[`\"\']?\s+ADD\s+(?:COLUMN\s+)?[`\"\']?(\w+)[`\"\']?\s+\w+[^;]*?NOT\s+NULL(?![^;]*?DEFAULT)", re.I)),
    ("change_type", "warning", re.compile(
        r"ALTER\s+TABLE\s+[`\"\']?(\w+)[`\"\']?\s+ALTER\s+COLUMN\s+[`\"\']?(\w+)[`\"\']?\s+(?:SET\s+DATA\s+)?TYPE", re.I)),
]
_SQL_KW = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|FROM|JOIN|WHERE)\b", re.I)


def parse_migrations(sql: str, filename: str = "migration.sql") -> List[SchemaChange]:
    """Extract backward-incompatible schema changes from SQL DDL text."""
    changes: List[SchemaChange] = []
    for lineno, line in enumerate(sql.splitlines(), 1):
        for kind, sev, pat in DDL_RULES:
            for m in pat.finditer(line):
                col = m.group(2) if m.lastindex and m.lastindex >= 2 else ""
                changes.append(SchemaChange(kind, m.group(1), col, filename, lineno, sev))
    return changes


# ---------------------------------------------------------------------------
# Legacy cross-validation (dict-based, used by CLI / existing tests)
# ---------------------------------------------------------------------------

def find_violations(changes: List[SchemaChange], code_files: Dict[str, str]) -> List[Violation]:
    """Find code lines that reference columns/tables affected by *changes*."""
    violations: List[Violation] = []
    for change in changes:
        target = change.column if change.column else change.table
        if not target:
            continue
        pat = re.compile(r'\b' + re.escape(target) + r'\b', re.I)
        for fname, content in code_files.items():
            for lineno, line in enumerate(content.splitlines(), 1):
                if pat.search(line):
                    violations.append(Violation(
                        kind=change.kind,
                        table=change.table,
                        column=change.column,
                        migration_file=change.file,
                        migration_line=change.line,
                        code_file=fname,
                        code_line=lineno,
                        snippet=line.strip(),
                        severity=change.severity,
                    ))
    return violations


def to_json(violations: List[Violation]) -> str:
    """Serialize violations to a JSON string."""
    return json.dumps([asdict(v) for v in violations], indent=2)


def to_sarif(violations: List[Violation]) -> dict:
    """Serialize violations to SARIF 2.1.0 format."""
    results = []
    for v in violations:
        results.append({
            "ruleId": v.kind,
            "level": "error" if v.severity == "error" else "warning",
            "message": {
                "text": f"{v.kind}: {v.table}.{v.column} referenced in {v.code_file}:{v.code_line}"
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
            "tool": {"driver": {"name": "SafeAlter", "version": "0.1.0"}},
            "results": results,
        }],
    }


# ---------------------------------------------------------------------------
# CodeScanner — regex-based reference scanner for .py / .sql files
# ---------------------------------------------------------------------------

_RE_SQLA_COLUMN = re.compile(r"""Column\s*\(\s*['"]([\w]+)['"]""")
_RE_TABLENAME = re.compile(r"""__tablename__\s*=\s*['"]([\w]+)['"]""")
_RE_SQL_SELECT_COLS = re.compile(r'\bSELECT\s+([\w\s,.*`"\']+?)\s+FROM\b', re.I)
_RE_SQL_FROM = re.compile(r'\b(?:FROM|JOIN)\s+[`"\'\[]?(\w+)[`"\'\]]?', re.I)
_RE_SQL_WHERE_COL = re.compile(r'\b(?:WHERE|AND|OR)\s+[`"\'\[]?(\w+)[`"\'\]]?\s*[=<>!]', re.I)
_RE_SQL_INSERT = re.compile(r'\bINSERT\s+INTO\s+[`"\'\[]?(\w+)[`"\'\]]?', re.I)
_RE_SQL_UPDATE = re.compile(r'\bUPDATE\s+[`"\'\[]?(\w+)[`"\'\]]?\s+SET\b', re.I)
_RE_SQL_SET_COL = re.compile(r'\bSET\s+[`"\'\[]?(\w+)[`"\'\]]?\s*=', re.I)
_RE_SQL_ORDERBY = re.compile(r'\b(?:ORDER|GROUP)\s+BY\s+[`"\'\[]?(\w+)[`"\'\]]?', re.I)
_RE_ORM_ATTR = re.compile(r'\b\w+\.(\w+)\b')

_SQL_KEYWORDS = frozenset({
    'select', 'insert', 'update', 'delete', 'from', 'where', 'set',
    'into', 'table', 'column', 'and', 'or', 'not', 'null', 'values',
    'join', 'on', 'as', 'distinct', 'all', 'order', 'by', 'group',
    'having', 'limit', 'offset', 'create', 'alter', 'drop', 'index',
    'primary', 'key', 'foreign', 'references', 'constraint', 'if',
    'exists', 'cascade', 'int', 'integer', 'varchar', 'text', 'boolean',
    'bigint', 'serial', 'timestamp', 'date', 'float', 'double', 'default',
    'true', 'false', 'in', 'is', 'like', 'between', 'case', 'when', 'then',
    'else', 'end', 'asc', 'desc', 'inner', 'outer', 'left', 'right', 'cross',
    'union', 'except', 'intersect', 'with', 'recursive', 'returning', 'type',
    'add', 'rename', 'to', 'using', 'unique', 'check', 'no', 'action',
})

_PY_COMMON_ATTRS = frozenset({
    'append', 'extend', 'items', 'keys', 'values', 'get', 'pop', 'clear',
    'format', 'strip', 'split', 'join', 'replace', 'lower', 'upper',
    'encode', 'decode', 'startswith', 'endswith', 'find', 'count', 'index',
    'read', 'write', 'close', 'open', 'path', 'name', 'parent', 'stem',
    'group', 'match', 'search', 'finditer', 'compile', 'sub', 'subn',
    'add', 'commit', 'rollback', 'query', 'filter', 'all', 'first', 'one',
    'delete', 'update', 'execute', 'fetchone', 'fetchall', 'fetchmany',
    'session', 'metadata', 'create_all', 'drop_all', 'begin', 'flush',
    'isinstance', 'type', 'len', 'str', 'int', 'float', 'bool', 'list',
    'dict', 'set', 'tuple', 'print', 'range', 'enumerate', 'zip', 'map',
    'sort', 'sorted', 'reverse', 'copy', 'deepcopy',
    'dumps', 'loads', 'dump', 'load', 'result', 'row',
})


def _is_noise(name: str) -> bool:
    """Return True if *name* is a SQL keyword or common Python attr."""
    low = name.lower()
    return low in _SQL_KEYWORDS or low in _PY_COMMON_ATTRS or name.startswith('_')


@dataclass
class CodeScanner:
    """Scan project .py / .sql files for table and column name references.

    Uses only ``re`` and ``os`` from the stdlib — no AST parsing.
    """
    scan_paths: List[str]

    # -- public API -----------------------------------------------------------

    def scan_file(self, file_path: str, content: str) -> List[CodeReference]:
        """Return every table/column reference found in *content*."""
        refs: List[CodeReference] = []
        is_sql_file = file_path.endswith('.sql')

        for lineno, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()

            # 1) SQLAlchemy Column('xxx')
            for m in _RE_SQLA_COLUMN.finditer(line):
                refs.append(CodeReference(
                    file_path, lineno, stripped, "sqlalchemy_column", m.group(1)))

            # 2) __tablename__ = 'xxx'
            for m in _RE_TABLENAME.finditer(line):
                refs.append(CodeReference(
                    file_path, lineno, stripped, "table_name", m.group(1)))

            # 3) Raw SQL (inside string literals for .py, whole line for .sql)
            line_has_sql = is_sql_file or bool(re.search(
                r"""['\"].*\b(?:SELECT|INSERT|UPDATE|DELETE|FROM|JOIN|WHERE)\b""",
                line, re.I))
            if line_has_sql:
                refs.extend(self._extract_sql_refs(file_path, lineno, stripped, line))

            # 4) ORM attribute access  (only in .py files)
            if not is_sql_file:
                for m in _RE_ORM_ATTR.finditer(line):
                    attr = m.group(1)
                    if _is_noise(attr):
                        continue
                    refs.append(CodeReference(
                        file_path, lineno, stripped, "orm_attribute", attr))

        return refs

    def scan_all(self) -> List[CodeReference]:
        """Walk *scan_paths* and scan every .py / .sql file found."""
        all_refs: List[CodeReference] = []
        for base in self.scan_paths:
            if os.path.isfile(base):
                if base.endswith(('.py', '.sql')):
                    all_refs.extend(self._read_and_scan(base))
            elif os.path.isdir(base):
                for root, _dirs, files in os.walk(base):
                    for fname in sorted(files):
                        if fname.endswith(('.py', '.sql')):
                            all_refs.extend(
                                self._read_and_scan(os.path.join(root, fname)))
        return all_refs

    # -- private helpers ------------------------------------------------------

    def _read_and_scan(self, fpath: str) -> List[CodeReference]:
        try:
            with open(fpath, 'r', errors='ignore') as fh:
                return self.scan_file(fpath, fh.read())
        except (OSError, IOError):
            return []

    @staticmethod
    def _extract_sql_refs(file_path: str, lineno: int, stripped: str,
                          raw_line: str) -> List[CodeReference]:
        """Pull identifiers out of a line that contains SQL."""
        refs: List[CodeReference] = []
        extractors = [
            (_RE_SQL_SELECT_COLS, True),
            (_RE_SQL_FROM, False),
            (_RE_SQL_WHERE_COL, False),
            (_RE_SQL_INSERT, False),
            (_RE_SQL_UPDATE, False),
            (_RE_SQL_SET_COL, False),
            (_RE_SQL_ORDERBY, False),
        ]
        for pat, is_col_list in extractors:
            for m in pat.finditer(raw_line):
                val = m.group(1).strip()
                if is_col_list:
                    for col_tok in val.split(','):
                        col = col_tok.strip().split('.')[-1].strip()
                        col = re.sub(r'[`"\'\[\]]', '', col)
                        if col and col != '*' and not _is_noise(col):
                            refs.append(CodeReference(
                                file_path, lineno, stripped, "raw_sql", col))
                else:
                    name = re.sub(r'[`"\'\[\]]', '', val)
                    if name and not _is_noise(name):
                        refs.append(CodeReference(
                            file_path, lineno, stripped, "raw_sql", name))
        return refs


# ---------------------------------------------------------------------------
# cross_validate — match migration findings against code references
# ---------------------------------------------------------------------------

def cross_validate(
    migration_findings: List[SchemaChange],
    code_references: List[CodeReference],
) -> List[CrossValidationResult]:
    """Return a *CrossValidationResult* for every code reference broken by a
    migration change."""
    results: List[CrossValidationResult] = []
    for change in migration_findings:
        for ref in code_references:
            matched = False
            ref_lower = ref.name.lower()

            if change.kind in ("drop_column", "rename_column",
                               "change_type", "not_null_no_default"):
                if change.column and ref_lower == change.column.lower():
                    matched = True

            if change.kind == "drop_table":
                if ref_lower == change.table.lower():
                    matched = True

            if matched:
                risk = "high" if change.severity == "error" else "medium"
                stmt = f"{change.kind}: {change.table}"
                if change.column:
                    stmt += f".{change.column}"
                stmt += f" ({change.file}:{change.line})"
                results.append(CrossValidationResult(
                    affected_file=ref.file_path,
                    line_number=ref.line_number,
                    column_name=change.column,
                    table_name=change.table,
                    migration_statement=stmt,
                    risk_level=risk,
                ))
    return results
