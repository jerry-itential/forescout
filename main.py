#!/usr/bin/env python3
"""Forescout eyeExtend Web API passthrough service for gateway 5.

Single generic action: request. Caller supplies method/path/query/body; this script
handles Forescout's login step itself and forwards the call, returning the raw response.

Host/username/password are read from environment variables, injected by gateway 5 as
secrets (FORESCOUT_HOST / FORESCOUT_USERNAME / FORESCOUT_PASSWORD) -- nothing
connection-specific is a decorator param, so the same service definition is portable
across Forescout instances just by swapping the gateway5 secret values.
FORESCOUT_HOST may optionally include a ":port" suffix (default 443 otherwise).

Forescout's Web API uses session-token auth: POST /api/login with a form-urlencoded
username/password body returns the JWT as a RAW TEXT body (not JSON). That token is
sent as "Authorization: Bearer <token>" on every subsequent call (confirmed against a
live instance -- the vendor's own example clients send the bare token with no prefix,
which is wrong for at least this instance/version). This script performs that login
itself on every invocation -- no token is persisted between gateway 5 service calls.

CLI flags override environment values -- useful for local testing.
"""

import argparse
import json
import os
import sys

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ---------------------------------------------------------------------------
# Session / HTTP helpers
# ---------------------------------------------------------------------------

def _base(conn):
    return f"https://{conn['host']}:{conn['port']}"


def _login(conn):
    resp = requests.post(
        f"{_base(conn)}/api/login",
        data={"username": conn["user"], "password": conn["password"]},
        verify=conn["verify_ssl"],
        timeout=conn["timeout"],
    )
    if resp.status_code != 200:
        raise RuntimeError(f"login failed: HTTP {resp.status_code}: {resp.text}")
    token = resp.text.strip()
    if not token:
        raise RuntimeError("login returned an empty token")
    return token


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

def request(conn, args):
    try:
        token = _login(conn)
    except Exception as e:
        return {"success": False, "host": conn["host"], "device_name": conn["device_name"],
                "error": f"login failed: {e}", "error_type": type(e).__name__}

    # TEMPORARY diagnostic for the signature-mismatch investigation -- remove once resolved.
    token_debug = {
        "token_len": len(token),
        "token_first_15": token[:15],
        "token_last_15": token[-15:],
        "token_starts_with_quote": token.startswith('"') or token.startswith("'"),
        "token_ends_with_quote": token.endswith('"') or token.endswith("'"),
    }

    method = (args.method or "GET").upper()
    path = args.path or ""
    if not path.startswith("/"):
        path = f"/{path}"

    query = None
    if args.query:
        try:
            query = json.loads(args.query)
        except json.JSONDecodeError as e:
            return {"success": False, "host": conn["host"], "device_name": conn["device_name"],
                    "error": f"--query is not valid JSON: {e}", "error_type": "ValueError"}

    body = None
    if args.body:
        try:
            body = json.loads(args.body)
        except json.JSONDecodeError as e:
            return {"success": False, "host": conn["host"], "device_name": conn["device_name"],
                    "error": f"--body is not valid JSON: {e}", "error_type": "ValueError"}

    try:
        resp = requests.request(
            method,
            f"{_base(conn)}{path}",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/x-www-form-urlencoded"},
            params=query,
            data=body,
            verify=conn["verify_ssl"],
            timeout=conn["timeout"],
        )
    except Exception as e:
        return {"success": False, "host": conn["host"], "device_name": conn["device_name"],
                "error": str(e), "error_type": type(e).__name__}

    result = _result(resp, conn)
    result["token_debug"] = token_debug
    return result


def _ok(resp):
    return 200 <= resp.status_code < 300


def _result(resp, conn):
    try:
        body = resp.json() if resp.text else None
    except Exception:
        body = resp.text
    out = {
        "success": _ok(resp),
        "host": conn["host"],
        "device_name": conn["device_name"],
        "http_status": resp.status_code,
    }
    if _ok(resp):
        out["results"] = body
    else:
        out["error"] = body if body is not None else resp.text
    return out


_DISPATCH = {
    "request": request,
}


# ---------------------------------------------------------------------------
# connection resolution
# ---------------------------------------------------------------------------

def _resolve_connection(args):
    host     = args.host or os.environ.get("FORESCOUT_HOST")
    user     = args.user or os.environ.get("FORESCOUT_USERNAME")
    password = args.password or os.environ.get("FORESCOUT_PASSWORD")
    timeout    = args.timeout if args.timeout is not None else 30
    verify_ssl = args.verify_ssl if args.verify_ssl is not None else False

    # FORESCOUT_HOST may optionally carry a ":port" suffix (e.g. for pointing at a
    # non-standard port during testing) -- a bare hostname defaults to 443 as normal.
    port = args.port
    if host and port is None and ":" in host:
        host, _, port_str = host.rpartition(":")
        port = port_str
    if port is None:
        port = 443

    missing = [n for n, v in [("host", host), ("user", user), ("password", password)] if not v]
    if missing:
        return None, {
            "success": False,
            "host": host,
            "error": f"missing required connection field(s): {', '.join(missing)} "
                     f"(via FORESCOUT_HOST/FORESCOUT_USERNAME/FORESCOUT_PASSWORD secrets, "
                     f"or --host/--user/--password for local testing)",
            "error_type": "ConfigurationError",
        }

    return {
        "host":        host,
        "port":        int(port),
        "user":        user,
        "password":    password,
        "timeout":     int(timeout),
        "verify_ssl":  bool(verify_ssl) if not isinstance(verify_ssl, str) else verify_ssl.lower() == "true",
        "device_name": host,
    }, None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(description="Forescout Web API passthrough for gateway 5")
    p.add_argument("--op", default="request", help="Action (only 'request' is supported)")

    p.add_argument("--host",     default=None, help="Forescout appliance host/IP (overrides FORESCOUT_HOST secret)")
    p.add_argument("--user",     default=None, help="Web API username (overrides FORESCOUT_USERNAME secret)")
    p.add_argument("--password", default=None, help="Web API password (overrides FORESCOUT_PASSWORD secret)")
    p.add_argument("--port",     default=None, help="HTTPS port (default 443)")
    p.add_argument("--timeout",  default=None, help="Request timeout in seconds (default 30)")
    p.add_argument("--verify_ssl", default=None, help="Verify TLS cert (default false)")

    p.add_argument("--method", default=None, help="HTTP method, e.g. GET, POST (default GET)")
    p.add_argument("--path",   default=None, help="Request path, e.g. /api/hosts/ip/10.0.1.20")
    p.add_argument("--query",  default=None, help="JSON object of query params, e.g. '{\"matchRuleId\": \"123\"}'")
    p.add_argument("--body",   default=None, help="JSON object of form-urlencoded body fields")

    return p


def _normalize_args(args):
    for attr, val in list(vars(args).items()):
        if val == "":
            setattr(args, attr, None)


def main():
    args = build_parser().parse_args()
    _normalize_args(args)
    conn, err = _resolve_connection(args)
    if err:
        print(json.dumps(err, indent=2, default=str))
        return 1
    result = _DISPATCH[args.op](conn, args)
    print(json.dumps(result, indent=2, default=str))
    return 0 if result.get("success") else 1


if __name__ == "__main__":
    sys.exit(main())
