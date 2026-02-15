"""Tests for SafeAlter — 13 test cases covering parse, cross-validate, and output."""
import json
from safealter import parse_migrations, find_violations, to_sarif, to_json


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
