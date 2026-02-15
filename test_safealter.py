"""Tests for SafeAlter — 13 test cases covering parse, cross-validate, and output."""
import json
from safealter import (
    parse_migrations, find_violations, to_sarif, to_json,
    Config, filter_violations, Violation,
)



def test_detect_drop_column():
    changes = parse_migrations("ALTER TABLE users DROP COLUMN email;", "V1.sql")
    assert len(changes) == 1
    assert changes[0].kind == "drop_column"
    assert changes[0].table == "users"
    assert changes[0].column == "email"
    assert changes[0].severity == "error"


def test_detect_drop_table():
    changes = parse_migrations("DROP TABLE IF EXISTS sessions;", "V2.sql")
    assert len(changes) == 1
    assert changes[0].kind == "drop_table"
    assert changes[0].table == "sessions"


def test_detect_rename_column():
    changes = parse_migrations("ALTER TABLE products RENAME COLUMN price TO cost;", "V3.sql")
    assert len(changes) == 1
    assert changes[0].kind == "rename_column"
    assert changes[0].column == "price"


def test_detect_not_null_without_default():
    changes = parse_migrations("ALTER TABLE users ADD COLUMN age INT NOT NULL;", "V4.sql")
    assert len(changes) == 1
    assert changes[0].kind == "not_null_no_default"
    assert changes[0].severity == "warning"


def test_not_null_with_default_is_safe():
    sql = "ALTER TABLE users ADD COLUMN age INT NOT NULL DEFAULT 0;"
    changes = parse_migrations(sql, "V5.sql")
    assert len(changes) == 0


def test_detect_type_change():
    changes = parse_migrations("ALTER TABLE users ALTER COLUMN age TYPE BIGINT;", "V6.sql")
    assert len(changes) == 1
    assert changes[0].kind == "change_type"
    assert changes[0].severity == "warning"


def test_cross_validate_drop_column_finds_broken_ref():
    changes = parse_migrations("ALTER TABLE users DROP COLUMN email;", "V1.sql")
    code = {"app.py": "row = db.execute('SELECT email FROM users WHERE id=1')"}
    violations = find_violations(changes, code)
    assert len(violations) == 1
    assert violations[0].kind == "drop_column"
    assert violations[0].code_file == "app.py"
    assert violations[0].code_line == 1


def test_cross_validate_drop_table_finds_broken_ref():
    changes = parse_migrations("DROP TABLE orders;", "V2.sql")
    code = {"queries.sql": "SELECT total FROM orders WHERE status='open';"}
    violations = find_violations(changes, code)
    assert len(violations) == 1
    assert violations[0].kind == "drop_table"


def test_no_false_positive_on_unrelated_code():
    changes = parse_migrations("ALTER TABLE users DROP COLUMN email;", "V1.sql")
    code = {"utils.py": "def add(a, b):\n    return a + b"}
    violations = find_violations(changes, code)
    assert len(violations) == 0


def test_sarif_output_format():
    changes = parse_migrations("ALTER TABLE users DROP COLUMN email;", "V1.sql")
    code = {"app.py": "q = 'SELECT email FROM users'"}
    sarif = to_sarif(find_violations(changes, code))
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 1
    assert sarif["runs"][0]["results"][0]["ruleId"] == "safealter/drop_column"


def test_json_output_format():
    changes = parse_migrations("DROP TABLE orders;", "V2.sql")
    code = {"q.sql": "SELECT * FROM orders;"}
    data = json.loads(to_json(find_violations(changes, code)))
    assert len(data) == 1
    assert data[0]["kind"] == "drop_table"
    assert data[0]["table"] == "orders"


def test_multiple_changes_parsed():
    sql = "ALTER TABLE t DROP COLUMN a;\nALTER TABLE t DROP COLUMN b;\nDROP TABLE x;"
    changes = parse_migrations(sql, "V7.sql")
    assert len(changes) == 3
    assert {c.kind for c in changes} == {"drop_column", "drop_table"}


def test_quoted_identifiers():
    sql = 'ALTER TABLE \"users\" DROP COLUMN \"email\";'
    changes = parse_migrations(sql, "V8.sql")
    assert len(changes) == 1
    assert changes[0].table == "users"
    assert changes[0].column == "email"


# ── Config & filter tests ─────────────────────────────────────────────

def test_config_default_values():
    """Config.default() returns sensible defaults."""
    cfg = Config.default()
    assert cfg.rules_disabled == []
    assert cfg.severity_override == {}
    assert cfg.scan_paths == ["."]
    assert cfg.exclude_patterns == []
    assert cfg.dialect == "postgresql"


def test_config_load_from_json(tmp_path):
    """Config.load() parses a .safealter.json correctly."""
    config_file = tmp_path / ".safealter.json"
    config_file.write_text(json.dumps({
        "rules": {"disabled": ["drop_column", "rename_column"]},
        "severity_override": {"not_null_no_default": "error"},
        "scan_paths": ["src/", "lib/"],
        "exclude_patterns": ["*_test.py", "vendor/*"],
        "dialect": "mysql"
    }))
    cfg = Config.load(str(config_file))
    assert cfg.rules_disabled == ["drop_column", "rename_column"]
    assert cfg.severity_override == {"not_null_no_default": "error"}
    assert cfg.scan_paths == ["src/", "lib/"]
    assert cfg.exclude_patterns == ["*_test.py", "vendor/*"]
    assert cfg.dialect == "mysql"


def test_config_load_file_not_found():
    """Config.load() raises FileNotFoundError for missing file."""
    import pytest
    with pytest.raises(FileNotFoundError):
        Config.load("/nonexistent/path/.safealter.json")


def test_disabled_rule_filters_out_violations():
    """Disabling drop_column removes those violations from results."""
    changes = parse_migrations("ALTER TABLE users DROP COLUMN email;", "V1.sql")
    code = {"app.py": "SELECT email FROM users;"}
    violations = find_violations(changes, code)
    assert len(violations) >= 1
    assert any(v.kind == "drop_column" for v in violations)

    cfg = Config(rules_disabled=["drop_column"])
    filtered = filter_violations(violations, cfg)
    assert all(v.kind != "drop_column" for v in filtered)


def test_severity_override_changes_level():
    """severity_override changes a warning to an error."""
    v = Violation(
        kind="not_null_no_default", table="users", column="age",
        migration_file="V1.sql", migration_line=1,
        code_file="app.py", code_line=5,
        snippet="INSERT INTO users (age) VALUES (1)", severity="warning"
    )
    cfg = Config(severity_override={"not_null_no_default": "error"})
    filtered = filter_violations([v], cfg)
    assert len(filtered) == 1
    assert filtered[0].severity == "error"
    assert filtered[0].kind == "not_null_no_default"


def test_exclude_patterns_skips_matching_files(tmp_path):
    """exclude_patterns in collect() skips files matching glob patterns."""
    from main import collect

    (tmp_path / "app.py").write_text("SELECT email FROM users;")
    (tmp_path / "app_test.py").write_text("SELECT email FROM users;")
    (tmp_path / "utils.py").write_text("SELECT name FROM users;")

    # Without exclude — all 3 files collected
    all_files = collect([str(tmp_path)], {".py"})
    assert len(all_files) == 3

    # With exclude — *_test.py should be skipped
    filtered_files = collect([str(tmp_path)], {".py"}, ["*_test.py"])
    assert len(filtered_files) == 2
    assert not any("app_test.py" in k for k in filtered_files)
    assert any("app.py" in k for k in filtered_files)
    assert any("utils.py" in k for k in filtered_files)


def test_config_load_partial_json(tmp_path):
    """Config.load() fills missing keys with defaults."""
    config_file = tmp_path / ".safealter.json"
    config_file.write_text(json.dumps({"dialect": "sqlite"}))
    cfg = Config.load(str(config_file))
    assert cfg.dialect == "sqlite"
    assert cfg.rules_disabled == []
    assert cfg.severity_override == {}
    assert cfg.scan_paths == ["."]
    assert cfg.exclude_patterns == []
