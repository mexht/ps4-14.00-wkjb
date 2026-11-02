#!/usr/bin/env python3
"""Self-contained HTTP test for lab/server.py.

Starts a throwaway server on a free port with a temporary state directory,
then exercises the session/queue/probe/mark/result/log/admin path the way the
page and the driver do. No browser and no console needed.

    python3 lab/test_lab.py
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
MANIFEST = (REPO / "probes" /
            "array_iterator_short_control_v1.json")

failures = 0


def check(name: str, cond: bool, extra: str = "") -> None:
    global failures
    print(("PASS " if cond else "FAIL ") + name + (("  " + extra) if extra else ""))
    if not cond:
        failures += 1


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def call(base, method, path, value=None, headers=None):
    data = None if value is None else json.dumps(value).encode()
    hdrs = {"Accept": "application/json"}
    if data is not None:
        hdrs["Content-Type"] = "application/json"
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(base + path, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.status, response.read(), dict(response.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers)


def main() -> int:
    port = free_port()
    base = "http://127.0.0.1:%d" % port
    tmp = Path(tempfile.mkdtemp(prefix="ps4lab-"))
    log = open(tmp / "server.log", "w")
    server = subprocess.Popen(
        [sys.executable, str(HERE / "server.py"), "serve", "--host", "127.0.0.1",
         "--port", str(port), "--state", str(tmp / "state.json"),
         "--results", str(tmp / "results"), "--dumps", str(tmp / "dumps")],
        stdout=log, stderr=subprocess.STDOUT)
    try:
        for _ in range(50):
            try:
                if call(base, "GET", "/api/health")[0] == 200:
                    break
            except OSError:
                pass
            time.sleep(0.1)
        else:
            print("server did not start; see " + str(tmp / "server.log"))
            return 1

        status, body, _ = call(base, "GET", "/")
        check("index served", status == 200 and b"PS4 14.00 webkit jb" in body)
        status, body, _ = call(base, "GET", "/app.js")
        check("page script served", status == 200 and b"XMLHttpRequest" in body)
        status, body, _ = call(base, "GET", "/sha256.js")
        check("digest helper served", status == 200 and b"FW14_SHA256" in body)

        status, body, headers = call(base, "GET", "/hen.bin")
        hen_path = REPO / "artifacts" / "hen.bin"
        if hen_path.exists():
            check("hen.bin served",
                  status == 200 and hashlib.sha256(body).hexdigest() ==
                  headers.get("X-FW14-Hen-SHA256"), str(status))
        else:
            check("missing hen.bin is reported", status == 404, str(status))

        status, body, headers = call(base, "GET", "/goldhen.bin")
        goldhen_path = REPO / "artifacts" / "goldhen.bin"
        if goldhen_path.exists():
            check("goldhen.bin served",
                  status == 200 and hashlib.sha256(body).hexdigest() ==
                  headers.get("X-FW14-GoldHEN-SHA256"), str(status))
        else:
            check("missing goldhen.bin is reported", status == 404, str(status))

        status, body, _ = call(base, "POST", "/api/sessions", {
            "firmware_label": "14.00",
            "user_agent": "Mozilla/5.0 (PlayStation 4/14.00) AppleWebKit/605.1.15",
            "runner_version": 1,
        })
        session = json.loads(body)
        check("register", status == 201 and len(session["session_id"]) == 32, str(status))
        sid, secret = session["session_id"], session["session_secret"]
        hdr = {"X-FW14-Session": secret}

        status, body, _ = call(base, "POST", "/api/sessions", {
            "firmware_label": "", "user_agent": "x", "runner_version": 1})
        check("bad firmware rejected", status == 400, str(status))

        status, body, _ = call(base, "POST", "/api/admin/enqueue-probe",
                               {"session_id": sid, "manifest": str(MANIFEST)})
        check("enqueue", status == 201, str(status))
        cid = json.loads(body)["command_id"]

        status, body, _ = call(base, "POST", "/api/commands/claim",
                               {"session_id": sid}, hdr)
        cmd = json.loads(body)["command"]
        check("claim", status == 200 and cmd["command_id"] == cid and cmd["attempt"] == 1)

        status, body, headers = call(
            base, "GET", "/api/commands/%s/probe" % cid,
            headers={"X-FW14-Session": secret, "X-FW14-Attempt": cmd["attempt_token"]})
        sha = hashlib.sha256(body).hexdigest()
        check("probe fetch", status == 200 and sha == cmd["source_sha256"] and
              headers.get("X-FW14-Source-SHA256") == sha, sha[:12])

        status, body, _ = call(base, "GET", "/api/commands/%s/probe" % cid,
                               headers={"X-FW14-Session": "wrong"})
        check("probe needs the secret", status == 403, str(status))

        status, body, _ = call(base, "POST", "/api/commands/claim",
                               {"session_id": sid}, hdr)
        check("empty claim", status == 200 and json.loads(body)["command"] is None)

        mark = {"session_id": sid, "command_id": cid, "attempt": cmd["attempt"],
                "attempt_token": cmd["attempt_token"], "phase": "groom"}
        status, body, _ = call(base, "POST", "/api/commands/mark", mark, hdr)
        check("mark", status == 201 and json.loads(body)["phase"] == "groom", str(status))
        status, _, _ = call(base, "POST", "/api/commands/mark", mark, hdr)
        check("duplicate mark tolerated", status == 201, str(status))

        result = {"session_id": sid, "command_id": cid, "attempt": cmd["attempt"],
                  "attempt_token": cmd["attempt_token"],
                  "started_at": "2026-11-01T00:00:00Z",
                  "completed_at": "2026-11-01T00:00:01Z",
                  "checks": [{"id": "short_iterator", "status": "pass",
                              "details": {"iterations": 3}}]}
        status, body, _ = call(base, "POST", "/api/commands/result", result, hdr)
        check("result", status == 201 and json.loads(body)["status"] == "completed",
              str(status))
        check("result file written", (tmp / "results" / (cid + ".json")).exists())

        status, body, _ = call(base, "GET",
                               "/api/admin/wait?command_id=%s&timeout=5" % cid)
        check("wait", status == 200 and json.loads(body)["status"] == "completed")

        status, body, _ = call(base, "POST", "/api/admin/enqueue-probe",
                               {"session_id": sid, "manifest": str(MANIFEST)})
        cid2 = json.loads(body)["command_id"]
        status, body, _ = call(base, "POST", "/api/commands/claim",
                               {"session_id": sid}, hdr)
        cmd2 = json.loads(body)["command"]
        bad = dict(result, command_id=cid2, attempt=cmd2["attempt"] + 1,
                   attempt_token=cmd2["attempt_token"],
                   checks=[{"id": "short_iterator", "status": "pass", "details": {}}])
        status, _, _ = call(base, "POST", "/api/commands/result", bad, hdr)
        check("wrong attempt rejected", status == 400, str(status))
        bad["attempt"] = cmd2["attempt"]
        bad["attempt_token"] = "x"
        status, _, _ = call(base, "POST", "/api/commands/result", bad, hdr)
        check("bad token rejected", status == 400, str(status))
        err = dict(bad, attempt_token=cmd2["attempt_token"],
                   checks=[{"id": "probe_error", "status": "error",
                            "details": {"error": "probe threw"}}])
        status, _, _ = call(base, "POST", "/api/commands/result", err, hdr)
        check("probe_error accepted", status == 201, str(status))

        status, body, _ = call(base, "GET", "/api/log?since=0")
        lines = json.loads(body)["lines"]
        levels = {line["level"] for line in lines}
        check("log covers queue/run/mark/ok/error",
              {"queue", "run", "mark", "ok", "error"} <= levels,
              ",".join(sorted(levels)))
        since = lines[-1]["seq"]
        status, body, _ = call(base, "GET", "/api/log?since=%d" % since)
        check("log since is empty", json.loads(body)["lines"] == [])

        status, body, _ = call(base, "POST", "/api/admin/note",
                               {"text": "chain: storage ok", "level": "stage"})
        check("note", status == 201 and json.loads(body)["level"] == "stage")
        status, body, _ = call(base, "GET", "/api/log?since=%d" % since)
        check("note visible", json.loads(body)["lines"][-1]["text"] == "chain: storage ok")

        status, body, _ = call(base, "GET", "/api/admin/sessions")
        check("sessions listed", status == 200 and len(json.loads(body)) == 1)
        status, body, _ = call(base, "GET", "/api/admin/commands")
        check("commands listed", status == 200 and len(json.loads(body)) == 2,
              str(len(json.loads(body))))

        status, body, _ = call(base, "GET", "/api/health")
        check("health", status == 200 and json.loads(body)["status"] == "ok")

        status, _, _ = call(base, "GET", "/api/admin/sessions",
                            headers={"Origin": "http://evil.example"})
        check("cross-origin rejected", status == 403, str(status))
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
        log.close()

    print("\nALL OK" if failures == 0 else "\n%d FAILURES" % failures)
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
