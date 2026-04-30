#!/usr/bin/env python3
"""Extract Naver 2FA timeline from a HAR file.

Usage:
  python analyze_har_timeline.py ProxyPin4-29_20_04_48.har
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

KEYS = (
    "m=viewGuide",
    "m=actionCheckPasswd",
    "m=showDeviceList",
    "m=sendPushMessageToRegist",
    "m=checkPushStatus",
    "m=setUp",
    "m=viewManageSettings",
    "m=createApplicationPassword",
)


def _load_har(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _extract_text(entry: dict) -> str:
    return (entry.get("response", {}).get("content", {}) or {}).get("text", "") or ""


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python analyze_har_timeline.py <file.har>")
        return 1

    har_path = Path(sys.argv[1])
    if not har_path.exists():
        print(f"HAR not found: {har_path}")
        return 1

    data = _load_har(har_path)
    entries = data.get("log", {}).get("entries", [])
    if not entries:
        print("No entries found in HAR.")
        return 1

    print(f"HAR: {har_path}")
    print(f"Total entries: {len(entries)}")
    print("\n=== 2FA timeline (oldest -> newest) ===")

    filtered = []
    for e in sorted(entries, key=lambda x: x.get("startedDateTime", "")):
        url = (e.get("request", {}) or {}).get("url", "")
        if any(k in url for k in KEYS):
            filtered.append(e)
            print(f"{e.get('startedDateTime')}  {e.get('request', {}).get('method', '?')}  {url}")

            if "m=checkPushStatus" in url:
                body = _extract_text(e).replace("\n", " ").strip()
                print(f"    response: {body[:220]}")

    print("\n=== WebSocket-ish endpoints scan ===")
    ws_hits = []
    for e in entries:
        url = (e.get("request", {}) or {}).get("url", "")
        lo = url.lower()
        if any(x in lo for x in ("socket.io", "websocket", "wss://", "engine.io")):
            ws_hits.append((e.get("startedDateTime"), e.get("request", {}).get("method"), url))

    if not ws_hits:
        print("No socket.io/websocket/wss/engine.io URLs found in this HAR.")
    else:
        for ts, method, url in sorted(ws_hits):
            print(f"{ts}  {method}  {url}")

    if filtered:
        last_cps = [e for e in filtered if "m=checkPushStatus" in (e.get("request", {}).get("url", ""))]
        if last_cps:
            final = _extract_text(last_cps[-1]).strip()
            print("\n=== Last checkPushStatus ===")
            print(final[:300])

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
