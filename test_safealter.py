"""Tests for SafeAlter \u2014 covering parse, cross-validate, and structured output."""
import json
from safealter import (
    parse_migrations, find_violations,
    to_sarif, to_json, format_results,
)


# ---- Parse tests ----

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


# ---- Cross-validation tests ----

def test_cross_validate_drop_column_finds_broken_ref():
    changes = parse_migrations("ALTER TABLE users DROP COLUMN email;", "V1.sql")
    code = {"app.py": 'query = "SELECT email FROM users"'}
    violations = find_violations(changes, code)
    assert len(violations) == 1
    assert violations[0].kind == "drop_column"
    assert violations[0].code_file == "app.py"


def test_cross_validate_no_ref_means_no_violation():
    changes = parse_migrations("ALTER TABLE users DROP COLUMN email;", "V1.sql")
    code = {"app.py": "x = 1 + 2"}
    violations = find_violations(changes, code)
    assert len(violations) == 0


def test_cross_validate_drop_table_finds_broken_ref():
    changes = parse_migrations("DROP TABLE sessions;", "V2.sql")
    code = {"dao.py": 'cursor.execute("DELETE FROM sessions WHERE expired")'}
    violations = find_violations(changes, code)
    assert len(violations) == 1
    assert violations[0].kind == "drop_table"


# ---- JSON output tests ----

def _make_violations():
    """Helper: create a sample violation list for output tests."""
    changes = parse_migrations("ALTER TABLE users DROP COLUMN email;", "V1.sql")
    code = {"app.py": 'query = "SELECT email FROM users"'}
    return find_violations(changes, code)


def test_to_json_valid_output():
    """JSON output must be parseable and match the specified schema."""
    violations = _make_violations()
    raw = to_json(violations)
    data = json.loads(raw)
    assert data["version"] == "0.1"
    assert isinstance(data["findings"], list)
    assert len(data["findings"]) == 1
    f = data["findings"][0]
    assert f["rule"] == "drop_column"
    assert f["severity"] == "error"
    assert f["location"]["file"] == "app.py"
    assert f["location"]["line"] == 1
    assert "message" in f
    assert "migration_statement" in f


def test_to_json_empty_findings():
    """JSON output with no violations should still be valid JSON."""
    raw = to_json([])
    data = json.loads(raw)
    assert data["version"] == "0.1"
    assert data["findings"] == []


def test_json_multiple_findings():
    """JSON output with multiple violations lists all findings."""
    sql = "ALTER TABLE users DROP COLUMN email;\nALTER TABLE users DROP COLUMN name;"
    changes = parse_migrations(sql, "V1.sql")
    code = {"app.py": 'q = "SELECT email, name FROM users"'}
    violations = find_violations(changes, code)
    raw = to_json(violations)
    data = json.loads(raw)
    assert len(data["findings"]) == 2
    rules = {f["rule"] for f in data["findings"]}
    assert "drop_column" in rules


# ---- SARIF output tests ----

def test_to_sarif_valid_structure():
    """SARIF output must conform to v2.1.0 schema structure."""
    violations = _make_violations()
    sarif = to_sarif(violations)
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "SafeAlter"
    assert len(run["results"]) == 1
    result = run["results"][0]
    assert result["ruleId"] == "drop_column"
    assert result["level"] == "error"
    loc = result["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "app.py"
    assert loc["region"]["startLine"] == 1
    # Rules populated
    assert len(run["tool"]["driver"]["rules"]) >= 1
    assert run["tool"]["driver"]["rules"][0]["id"] == "drop_column"


def test_to_sarif_serializable():
    """SARIF output must be JSON-serializable."""
    violations = _make_violations()
    sarif = to_sarif(violations)
    raw = json.dumps(sarif)
    reparsed = json.loads(raw)
    assert reparsed["version"] == "2.1.0"


def test_to_sarif_empty():
    """SARIF output with no violations should have empty results and rules."""
    sarif = to_sarif([])
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []


def test_sarif_warning_level():
    """SARIF output should map warning severity correctly."""
    changes = parse_migrations("ALTER TABLE users ADD COLUMN age INT NOT NULL;", "V4.sql")
    code = {"app.py": 'db.execute("INSERT INTO users (age) VALUES (1)")'}
    violations = find_violations(changes, code)
    assert len(violations) >= 1
    sarif = to_sarif(violations)
    result = sarif["runs"][0]["results"][0]
    assert result["level"] == "warning"


# ---- format_results dispatch tests ----

def test_format_results_json():
    """format_results with fmt='json' returns valid JSON."""
    violations = _make_violations()
    output = format_results(violations, "json")
    data = json.loads(output)
    assert data["version"] == "0.1"
    assert len(data["findings"]) == 1


def test_format_results_sarif():
    """format_results with fmt='sarif' returns valid SARIF JSON string."""
    violations = _make_violations()
    output = format_results(violations, "sarif")
    data = json.loads(output)
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1


def test_format_results_text():
    """format_results with fmt='text' returns human-readable output."""
    violations = _make_violations()
    output = format_results(violations, "text")
    assert "drop_column" in output
    assert "users.email" in output
    assert "error" in output.lower() or "\u274c" in output
