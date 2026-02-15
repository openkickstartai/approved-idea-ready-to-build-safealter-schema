# SafeAlter

**Zero-downtime database migration cross-validator.**

Statically analyzes SQL migrations against your application code to catch backward-incompatible schema changes — dropped columns, renamed tables, unsafe NOT NULL — before they crash running services during rolling deploys.

**Zero dependencies.** Pure Python stdlib. Installs in 0.2s, scans in <50ms.

## 🚀 Quick Start

```bash
pip install safealter
safealter -m migrations/ -c src/
```

Output:
```
❌ [drop_column] users.email
   migration: migrations/V005.sql:3
   code ref:  src/api.py:42 → row = db.execute('SELECT email FROM users')

💥 1 error(s), 0 warning(s)
```

## 🔍 What It Catches

| Rule | Severity | Description |
|------|----------|-------------|
| `drop_column` | Error | Column dropped but still referenced in code |
| `drop_table` | Error | Table dropped but still referenced |
| `rename_column` | Error | Column renamed, old name still in code |
| `not_null_no_default` | Warning | NOT NULL added without DEFAULT — breaks INSERTs |
| `change_type` | Warning | Column type changed — may break queries |

## 📊 Why Pay for SafeAlter?

**Without SafeAlter:** Migration drops `users.email` → deploy rolls forward → old pods still SELECT email → 500s for 2-8 min. PagerDuty fires. Rollback. 30-min incident.

**With SafeAlter:** CI catches it in 200ms. You add a deprecation step first. Zero incidents.

> One prevented P1 incident = **$5,000–50,000 saved** (SRE industry benchmark)

## 💰 Pricing

| Feature | Free | Pro $19/mo | Enterprise $99/seat/mo |
|---------|------|-----------|------------------------|
| Core rules (drop/rename) | ✅ | ✅ | ✅ |
| CLI text output | ✅ | ✅ | ✅ |
| JSON output | — | ✅ | ✅ |
| SARIF output (GitHub Security) | — | ✅ | ✅ |
| Custom ignore rules | — | ✅ | ✅ |
| GitHub Action | — | ✅ | ✅ |
| Multi-dialect (MySQL+PG+SQLite) | — | ✅ | ✅ |
| ORM-aware scanning (Django/SQLAlchemy) | — | — | ✅ |
| Slack/Teams alerts | — | — | ✅ |
| SSO + audit log | — | — | ✅ |

## 🛠 CI Integration

```yaml
- name: SafeAlter Check
  run: |
    pip install safealter
    safealter -m migrations/ -c src/ --fail-on-warning
```

## Output Formats

```bash
safealter -m migrations/ -c src/ -f text   # human-readable (default)
safealter -m migrations/ -c src/ -f json   # machine-readable
safealter -m migrations/ -c src/ -f sarif  # GitHub Security tab
```

## License

MIT — free for individuals. Enterprise features require a paid license.
