#!/usr/bin/env python3
"""
Forward ERADICATE3 stdout to an addr-finder collector.

Usage:
    ./ERADICATE2.x64 -D <deployer> -r 10 | python3 tools/post_hits.py

Environment:
    COLLECTOR_URL    (required)  e.g., https://collector.example.com
    COLLECTOR_TOKEN  (optional)  bearer token for the collector
    CLIENT_ID        (required)  unique per worker instance
    DEPLOYER         (required)  40-hex deployer / factory address
    INIT_CODE_HASH   (required)  64-hex proxy bytecode hash
"""
import json
import os
import re
import sys
import time
from urllib import error, request

HIT_RE = re.compile(
    r"Time:\s*(\d+)s\s+Score:\s*(\d+)\s+Salt:\s*0x([0-9a-fA-F]{64})\s+Address:\s*(0x[0-9a-fA-F]{40})"
)


def strip_prefix(s: str, prefix: str) -> str:
    return s[len(prefix):] if s.startswith(prefix) else s


def envreq(name: str) -> str:
    v = os.environ.get(name, "").strip()
    if not v:
        print(f"post_hits: env {name} is required", file=sys.stderr)
        sys.exit(1)
    return v


URL = envreq("COLLECTOR_URL").rstrip("/")
CLIENT_ID = envreq("CLIENT_ID")
DEPLOYER = strip_prefix(envreq("DEPLOYER").lower(), "0x")
INIT_HASH = strip_prefix(envreq("INIT_CODE_HASH").lower(), "0x")
TOKEN = os.environ.get("COLLECTOR_TOKEN", "").strip()

print(
    f"post_hits: url={URL} client_id={CLIENT_ID} deployer=0x{DEPLOYER[:10]}...",
    file=sys.stderr,
    flush=True,
)


def post(score: int, salt: str, addr: str, retries: int = 4) -> None:
    body = json.dumps(
        {
            "deployer": DEPLOYER,
            "init_code_hash": INIT_HASH,
            "salt": salt,
            "addr": addr,
            "score": score,
            "client_id": CLIENT_ID,
        }
    ).encode()

    req = request.Request(
        f"{URL}/hit",
        data=body,
        headers={"content-type": "application/json"},
        method="POST",
    )
    if TOKEN:
        req.add_header("authorization", f"Bearer {TOKEN}")

    last_err = None
    for attempt in range(retries):
        try:
            with request.urlopen(req, timeout=10) as resp:
                return  # success
        except error.HTTPError as e:
            # 4xx: client error, no point retrying (e.g., CREATE3 mismatch)
            msg = e.read().decode(errors="replace") if e.fp else ""
            if 400 <= e.code < 500:
                print(
                    f"post_hits: rejected {e.code} {msg} (score={score} addr={addr})",
                    file=sys.stderr,
                    flush=True,
                )
                return
            last_err = f"{e.code} {msg}"
        except (error.URLError, TimeoutError, OSError) as e:
            last_err = str(e)

        time.sleep(min(2 ** attempt, 30))

    print(
        f"post_hits: gave up after {retries} retries: {last_err} (score={score} addr={addr})",
        file=sys.stderr,
        flush=True,
    )


def main() -> None:
    for raw in sys.stdin:
        # forward to our stdout for logging
        sys.stdout.write(raw)
        sys.stdout.flush()

        m = HIT_RE.search(raw)
        if not m:
            continue
        _, score, salt, addr = m.groups()
        post(int(score), salt.lower(), addr.lower())


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
