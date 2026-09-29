#!/usr/bin/env python3
"""Forescout DEX (Data Exchange) passthrough service for gateway 5.

Single generic action: request. Caller supplies method/path/body (raw FSAPI XML);
this script forwards it to the DEX web service with HTTP Basic auth and returns the
raw response.

Equivalent curl:

  curl --fail-with-body --silent --show-error --request POST \
    "https://<host>/fsapi/niCore/Lists" --user "<user>@<account>:<password>" \
    --header "Content-Type: application/xml" --header "Accept: application/xml" \
    --data-binary "@update_lists.xml"

Host/username/password are read from environment variables, injected by gateway 5
as secrets (FORESCOUT_HOST / FORESCOUT_DEX_USERNAME / FORESCOUT_DEX_PASSWORD).
The username is the full DEX account login, including "@<account>".
FORESCOUT_HOST may optionally include a ":port" suffix (default 443 otherwise).

CLI flags override environment values -- useful for local testing.
"""

import argparse
import json
import os
import sys

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def _base(conn):
    return f"https://{conn['host']}:{conn['port']}"


def _ok(resp):
    return 200 <= resp.status_code < 300


def request(conn, args):
    method = (args.method or "POST").upper()
    path = args.path or "/fsapi/niCore/Lists"
    if not path.startswith("/"):
        path = f"/{path}"

    try:
        resp = requests.request(
            method,
            f"{_base(conn)}{path}",
            data=args.body.encode("utf-8") if args.body else None,
            headers={"Accept": "application/xml", "Content-Type": "application/xml"},
            auth=(conn["user"], conn["password"]),
            verify=conn["verify_ssl"],
            timeout=conn["timeout"],
        )
    except Exception as e:
        return {"success": False, "host": conn["host"], "device_name": conn["device_name"],
                "error": str(e), "error_type": type(e).__name__}

    out = {
        "success": _ok(resp),
        "host": conn["host"],
        "device_name": conn["device_name"],
        "http_status": resp.status_code,
    }
    out["results" if _ok(resp) else "error"] = resp.text
    return out


_DISPATCH = {
    "request": request,
}


# ---------------------------------------------------------------------------
# connection resolution
# ---------------------------------------------------------------------------

def _resolve_connection(args):
    host     = args.host or os.environ.get("FORESCOUT_HOST")
    user     = args.user or os.environ.get("FORESCOUT_DEX_USERNAME")
    password = args.password or os.environ.get("FORESCOUT_DEX_PASSWORD")
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
                     f"(via FORESCOUT_HOST/FORESCOUT_DEX_USERNAME/FORESCOUT_DEX_PASSWORD secrets, "
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
    p = argparse.ArgumentParser(description="Forescout DEX passthrough for gateway 5")
    p.add_argument("--op", default="request", help="Action (only 'request' is supported)")

    p.add_argument("--host",     default=None, help="Forescout appliance host/IP (overrides FORESCOUT_HOST secret)")
    p.add_argument("--user",     default=None, help="DEX service account username (overrides FORESCOUT_DEX_USERNAME secret)")
    p.add_argument("--password", default=None, help="DEX service account password (overrides FORESCOUT_DEX_PASSWORD secret)")
    p.add_argument("--port",     default=None, help="HTTPS port (default 443)")
    p.add_argument("--timeout",  default=None, help="Request timeout in seconds (default 30)")
    p.add_argument("--verify_ssl", default=None, help="Verify TLS cert (default false)")

    p.add_argument("--method", default=None, help="HTTP method (default POST)")
    p.add_argument("--path",   default=None, help="Request path (default /fsapi/niCore/Lists)")
    p.add_argument("--body",   default=None, help="Raw FSAPI XML request body")

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
