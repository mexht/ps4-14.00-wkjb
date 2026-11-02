#!/usr/bin/env python3
"""Minimal PS4 14.00 browser lab: collector, queue and live log.

One file, standard library only. It replaces an older research collector (SQLite +
capture pipeline) with:

  * sessions, a probe queue, attempt tokens, phase marks and results;
  * a verbose event log that the console page renders while the chain runs;
  * a CLI the driver uses instead of shelling into a module.

Run the server (serves the page and the API):

    python3 lab/server.py serve --host 0.0.0.0 --port 8765

Drive it from the PC:

    python3 lab/server.py sessions
    python3 lab/server.py enqueue-probe --session <id> --manifest probes/x.json
    python3 lab/server.py wait --command-id <id> --timeout 120
    python3 lab/server.py note "chain: storage ok" --level ok
    python3 lab/server.py commands
    python3 lab/server.py log --since 0

State lives in `lab/state.json` (atomic writes) and results in
`lab/results/<command>.json`. No database, no build step.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen

HERE = Path(__file__).resolve().parent
WEB = HERE / "web"
DEFAULT_STATE = HERE / "state.json"
DEFAULT_RESULTS = HERE / "results"
DEFAULT_DUMPS = HERE / "dumps"
DEFAULT_PROBES = HERE.parent / "probes"
DEFAULT_URL = os.environ.get("FW14_LAB_URL", "http://127.0.0.1:8765")

HEX32 = re.compile(r"[0-9a-f]{32}\Z")
CHECK_ID = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
STATUSES = ("pass", "fail", "unsupported", "error")
MAX_BODY = 1 << 20
MAX_LOG = 2000


def now() -> str:
    return (datetime.now(timezone.utc)
            .isoformat(timespec="milliseconds").replace("+00:00", "Z"))


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class LabError(ValueError):
    pass


# --------------------------------------------------------------------------- store

class Store:
    def __init__(self, state_path: Path, probes: Path, results: Path, dumps: Path):
        self.lock = threading.RLock()
        self.state_path = state_path
        self.probes = probes
        self.results = results
        self.dumps = dumps
        self.sessions: dict[str, dict] = {}
        self.commands: dict[str, dict] = {}
        self.log: list[dict] = []
        self.seq = 0
        self._dirty = False
        self._load()

    # -- persistence

    def _load(self) -> None:
        try:
            doc = json.loads(self.state_path.read_text("utf-8"))
        except (OSError, ValueError):
            return
        self.sessions = doc.get("sessions") or {}
        self.commands = doc.get("commands") or {}
        self.log = doc.get("log") or []
        self.seq = doc.get("seq") or 0

    def _save(self) -> None:
        doc = {
            "sessions": self.sessions,
            "commands": self.commands,
            "log": self.log[-500:],
            "seq": self.seq,
        }
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(doc, sort_keys=True), "utf-8")
        os.replace(tmp, self.state_path)

    # -- log

    def event(self, level: str, text: str, source: str = "server") -> dict:
        with self.lock:
            self.seq += 1
            line = {"seq": self.seq, "ts": now(), "level": level,
                    "text": text[:2000], "source": source}
            self.log.append(line)
            if len(self.log) > MAX_LOG:
                self.log = self.log[-MAX_LOG:]
            self._save()
        print("%s %-5s %s" % (line["ts"][11:19], level.upper(), text), flush=True)
        return line

    def log_since(self, since: int) -> list[dict]:
        with self.lock:
            return [x for x in self.log if x["seq"] > since]

    # -- sessions

    def register(self, firmware: str, user_agent: str, runner: int, ip: str) -> dict:
        if type(firmware) is not str or not 1 <= len(firmware) <= 16:
            raise LabError("invalid firmware label")
        if type(user_agent) is not str or not 1 <= len(user_agent) <= 1024:
            raise LabError("invalid user agent")
        if type(runner) is not int or runner not in (0, 1):
            raise LabError("invalid runner version")
        sid = uuid.uuid4().hex
        secret = secrets.token_urlsafe(32)
        ts = now()
        with self.lock:
            self.sessions[sid] = {
                "id": sid, "secret_hash": digest(secret), "firmware": firmware,
                "user_agent": user_agent, "runner_version": runner, "ip": ip,
                "created_at": ts, "last_seen_at": ts,
            }
            self._save()
        ps4 = "PlayStation 4/14.00" in user_agent
        self.event("info", "session %s connected from %s%s" % (
            sid[:8], ip, "" if ps4 else "  (user agent is not the PS4 14.00 form)"),
            source=sid[:8])
        return {"session_id": sid, "session_secret": secret}

    def auth(self, sid: str, secret: str) -> dict:
        if type(sid) is not str or not HEX32.fullmatch(sid):
            raise LabError("invalid session id")
        row = self.sessions.get(sid)
        if row is None or not hmac.compare_digest(row["secret_hash"], digest(secret or "")):
            raise LabError("unknown session or secret")
        return row

    def touch(self, sid: str) -> None:
        with self.lock:
            if sid in self.sessions:
                self.sessions[sid]["last_seen_at"] = now()
                self._save()

    def list_sessions(self) -> list[dict]:
        with self.lock:
            rows = [dict(r) for r in self.sessions.values()]
        rows.sort(key=lambda r: r["last_seen_at"], reverse=True)
        return [{k: r[k] for k in ("id", "firmware", "user_agent", "ip",
                                   "created_at", "last_seen_at", "runner_version")}
                for r in rows[:20]]

    # -- commands

    def enqueue_probe(self, sid: str, manifest_path: Path) -> str:
        if type(sid) is not str or not HEX32.fullmatch(sid):
            raise LabError("invalid session id")
        with self.lock:
            if sid not in self.sessions:
                raise LabError("unknown session")
            try:
                manifest = json.loads(manifest_path.read_text("utf-8"))
            except (OSError, ValueError) as exc:
                raise LabError("cannot read manifest: %s" % exc)
            for key in ("probe_id", "script", "check_ids", "timeout_ms"):
                if key not in manifest:
                    raise LabError("manifest is missing %s" % key)
            if (type(manifest["probe_id"]) is not str or
                    not CHECK_ID.fullmatch(manifest["probe_id"])):
                raise LabError("invalid probe id")
            if (type(manifest["check_ids"]) is not list or
                    not 1 <= len(manifest["check_ids"]) <= 12 or
                    any(type(x) is not str or not CHECK_ID.fullmatch(x)
                        for x in manifest["check_ids"])):
                raise LabError("invalid check ids")
            if (type(manifest["timeout_ms"]) is not int or
                    not 1000 <= manifest["timeout_ms"] <= 30000):
                raise LabError("invalid timeout")
            script = (manifest_path.parent / manifest["script"]).resolve()
            try:
                source = script.read_bytes()
            except OSError as exc:
                raise LabError("cannot read script: %s" % exc)
            if len(source) > 32768:
                raise LabError("script is larger than 32768 bytes")
            canonical = json.dumps(
                {"probe_id": manifest["probe_id"], "script": manifest["script"],
                 "check_ids": manifest["check_ids"], "timeout_ms": manifest["timeout_ms"]},
                sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            cid = uuid.uuid4().hex
            self.commands[cid] = {
                "id": cid, "session_id": sid, "action": "run_probe_v1",
                "status": "queued", "attempt": 0, "token_hash": None,
                "probe_id": manifest["probe_id"], "script": str(script),
                "script_name": manifest["script"],
                "source_sha256": hashlib.sha256(source).hexdigest(),
                "manifest_sha256": hashlib.sha256(canonical).hexdigest(),
                "check_ids": manifest["check_ids"],
                "timeout_ms": manifest["timeout_ms"],
                "queued_at": now(), "claimed_at": None, "finished_at": None,
                "checks": None, "marks": [],
            }
            self._save()
        self.event("queue", "queued %s for %s (%.1f KiB, %d checks, timeout %d ms)" % (
            manifest["probe_id"], sid[:8], len(source) / 1024.0,
            len(manifest["check_ids"]), manifest["timeout_ms"]), source=sid[:8])
        return cid

    def claim(self, sid: str, secret: str) -> dict | None:
        with self.lock:
            self.auth(sid, secret)
            self.sessions[sid]["last_seen_at"] = now()
            queued = [c for c in self.commands.values()
                      if c["session_id"] == sid and c["status"] == "queued"]
            queued.sort(key=lambda c: (c["queued_at"], c["id"]))
            if not queued:
                self._save()
                return None
            cmd = queued[0]
            token = secrets.token_urlsafe(32)
            cmd["status"] = "claimed"
            cmd["attempt"] += 1
            cmd["token_hash"] = digest(token)
            cmd["claimed_at"] = now()
            self._save()
        self.event("run", "claimed %s (attempt %d)" % (cmd["probe_id"], cmd["attempt"]),
                   source=sid[:8])
        return {"command_id": cmd["id"], "action": cmd["action"],
                "attempt": cmd["attempt"], "attempt_token": token,
                "probe_id": cmd["probe_id"], "source_sha256": cmd["source_sha256"],
                "manifest_sha256": cmd["manifest_sha256"],
                "check_ids": cmd["check_ids"], "timeout_ms": cmd["timeout_ms"]}

    def _claimed(self, cid: str, sid: str, token: str) -> dict:
        cmd = self.commands.get(cid)
        if cmd is None or cmd["session_id"] != sid:
            raise LabError("unknown command")
        if cmd["status"] != "claimed":
            raise LabError("command is not claimed")
        if not hmac.compare_digest(cmd["token_hash"] or "", digest(token or "")):
            raise LabError("wrong attempt token")
        return cmd

    def probe_source(self, cid: str, secret: str, token: str) -> tuple[bytes, str]:
        with self.lock:
            cmd = self.commands.get(cid)
            if cmd is None:
                raise LabError("unknown command")
            self.auth(cmd["session_id"], secret)
            cmd = self._claimed(cid, cmd["session_id"], token)
            try:
                source = Path(cmd["script"]).read_bytes()
            except OSError as exc:
                raise LabError("cannot read probe source: %s" % exc)
            if hashlib.sha256(source).hexdigest() != cmd["source_sha256"]:
                raise LabError("probe source changed after it was queued")
            return source, cmd["source_sha256"]

    def mark(self, sid: str, secret: str, payload: dict) -> dict:
        with self.lock:
            self.auth(sid, secret)
            cid = payload.get("command_id")
            if type(cid) is not str or not HEX32.fullmatch(cid):
                raise LabError("invalid command id")
            cmd = self._claimed(cid, sid, payload.get("attempt_token", ""))
            if cmd["attempt"] != payload.get("attempt"):
                raise LabError("attempt mismatch")
            phase = payload.get("phase")
            if type(phase) is not str or not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", phase):
                raise LabError("invalid phase")
            if len(cmd["marks"]) >= 12:
                raise LabError("marker count exceeded")
            if phase not in cmd["marks"]:
                cmd["marks"].append(phase)
                self._save()
        self.event("mark", "%s: %s" % (cmd["probe_id"], phase), source=sid[:8])
        return {"phase": phase, "received_at": now()}

    def complete(self, sid: str, secret: str, payload: dict) -> dict:
        with self.lock:
            self.auth(sid, secret)
            cid = payload.get("command_id")
            if type(cid) is not str or not HEX32.fullmatch(cid):
                raise LabError("invalid command id")
            cmd = self._claimed(cid, sid, payload.get("attempt_token", ""))
            if cmd["attempt"] != payload.get("attempt"):
                raise LabError("attempt mismatch")
            checks = payload.get("checks")
            validate_checks(checks, cmd["check_ids"])
            cmd["status"] = "completed"
            cmd["checks"] = checks
            cmd["finished_at"] = now()
            cmd["started_at"] = payload.get("started_at")
            cmd["completed_at"] = payload.get("completed_at")
            self.sessions[sid]["last_seen_at"] = now()
            self._save()
            record = {"command_id": cid, "session_id": sid, "probe_id": cmd["probe_id"],
                      "attempt": cmd["attempt"], "received_at": now(),
                      "started_at": payload.get("started_at"),
                      "completed_at": payload.get("completed_at"),
                      "checks": checks}
            self.results.mkdir(parents=True, exist_ok=True)
            (self.results / (cid + ".json")).write_text(
                json.dumps(record, indent=2, sort_keys=True), "utf-8")
        self._summarise(cmd, checks)
        return {"command_id": cid, "status": "completed", "received_at": record["received_at"]}

    def _summarise(self, cmd: dict, checks: list) -> None:
        sid = cmd["session_id"][:8]
        for check in checks:
            level = "ok" if check["status"] == "pass" else (
                "warn" if check["status"] in ("fail", "unsupported") else "error")
            bits = []
            for key in sorted(check.get("details") or {}):
                value = check["details"][key]
                text = str(value)
                if len(text) > 60:
                    text = text[:57] + "..."
                bits.append("%s=%s" % (key, text))
                if len(bits) >= 8:
                    break
            self.event(level, "%s: %s%s" % (
                check["id"], check["status"],
                ("  " + " ".join(bits)) if bits else ""), source=sid)

    def list_commands(self) -> list[dict]:
        with self.lock:
            rows = [dict(c) for c in self.commands.values()]
        rows.sort(key=lambda c: c["queued_at"], reverse=True)
        out = []
        for c in rows[:40]:
            out.append({k: c.get(k) for k in (
                "id", "session_id", "status", "attempt", "probe_id", "queued_at",
                "claimed_at", "finished_at", "checks")})
        return out

    def wait(self, cid: str, timeout: float) -> dict:
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self.lock:
                cmd = self.commands.get(cid)
                if cmd is None:
                    raise LabError("unknown command")
                if cmd["status"] == "completed":
                    return {"command_id": cid, "status": "completed",
                            "probe_id": cmd["probe_id"], "checks": cmd["checks"]}
            time.sleep(0.25)
        return {"command_id": cid, "status": "timeout", "probe_id": None, "checks": None}

    def cancel(self, cid: str) -> dict:
        with self.lock:
            cmd = self.commands.get(cid)
            if cmd is None:
                raise LabError("unknown command")
            if cmd["status"] != "queued":
                raise LabError("only an unclaimed command can be cancelled")
            cmd["status"] = "cancelled"
            self._save()
        self.event("warn", "cancelled %s" % cmd["probe_id"])
        return {"command_id": cid, "status": "cancelled"}

    def chunk(self, sid: str, secret: str, payload: dict) -> dict:
        with self.lock:
            self.auth(sid, secret)
            cid = payload.get("command_id")
            if type(cid) is not str or not HEX32.fullmatch(cid):
                raise LabError("invalid command id")
            cmd = self.commands.get(cid)
            if cmd is None or cmd["session_id"] != sid:
                raise LabError("unknown command")
            if not hmac.compare_digest(cmd["token_hash"] or "",
                                       digest(payload.get("attempt_token", ""))):
                raise LabError("wrong attempt token")
            offset = payload.get("offset")
            data = payload.get("data_b64")
            if type(offset) is not int or offset < 0 or offset > 1 << 28 or type(data) is not str:
                raise LabError("invalid chunk")
            try:
                raw = base64.b64decode(data, validate=True)
            except Exception as exc:  # noqa: BLE001
                raise LabError("invalid base64: %s" % exc)
            if len(raw) > 1 << 18:
                raise LabError("chunk is larger than 256 KiB")
            self.dumps.mkdir(parents=True, exist_ok=True)
            path = self.dumps / (cid + ".bin")
            with path.open("r+b" if path.exists() else "wb") as fh:
                fh.seek(offset)
                fh.write(raw)
            return {"command_id": cid, "offset": offset, "size": len(raw)}


def validate_checks(checks, expected_ids) -> None:
    # A probe that could not run reports one synthetic error check; the page
    # sends it so the operator sees the failure instead of a stalled queue.
    if (type(checks) is list and len(checks) == 1 and
            type(checks[0]) is dict and
            set(checks[0]) == {"id", "status", "details"} and
            checks[0]["id"] == "probe_error" and
            checks[0]["status"] == "error"):
        details = checks[0]["details"]
        if type(details) is not dict or len(details) > 12:
            raise LabError("invalid probe error details")
        for key, value in details.items():
            if type(key) is not str or not CHECK_ID.fullmatch(key):
                raise LabError("invalid detail key")
            if value is not None and type(value) not in (str, int, float, bool):
                raise LabError("detail values must be scalar")
            if type(value) is str and len(value) > 512:
                raise LabError("detail string too long")
        return
    if type(checks) is not list or len(checks) != len(expected_ids):
        raise LabError("expected %d checks" % len(expected_ids))
    seen = []
    for check in checks:
        if type(check) is not dict or set(check) != {"id", "status", "details"}:
            raise LabError("unexpected check fields")
        if check["id"] not in expected_ids:
            raise LabError("unexpected check id")
        if check["status"] not in STATUSES:
            raise LabError("invalid check status")
        details = check["details"]
        if type(details) is not dict or len(details) > 12:
            raise LabError("invalid check details")
        for key, value in details.items():
            if type(key) is not str or not CHECK_ID.fullmatch(key):
                raise LabError("invalid detail key")
            if value is not None and type(value) not in (str, int, float, bool):
                raise LabError("detail values must be scalar")
            if type(value) is str and len(value) > 512:
                raise LabError("detail string too long")
        seen.append(check["id"])
    if seen != list(expected_ids):
        raise LabError("check ids out of order")
    if len(json.dumps(checks)) > 3600:
        raise LabError("checks are too large")


# --------------------------------------------------------------------------- http

def make_handler(store: Store):
    assets = {}
    for name in ("index.html", "app.js", "style.css", "sha256.js"):
        try:
            assets["/" if name == "index.html" else "/" + name] = (WEB / name).read_bytes()
        except OSError:
            pass
    try:
        hen_bytes = (HERE.parent / "artifacts" / "hen.bin").read_bytes()
    except OSError:
        hen_bytes = None
    build = hashlib.sha256(
        b"".join(assets[k] for k in sorted(assets)) +
        (b"/hen.bin\0" + hen_bytes if hen_bytes else b"")).hexdigest()
    hen_sha = hashlib.sha256(hen_bytes).hexdigest() if hen_bytes else None

    class Handler(BaseHTTPRequestHandler):
        server_version = "PS4Lab/1.0"

        def log_message(self, fmt, *args):  # quiet the default per-request log
            pass

        def json(self, status, value):
            body = json.dumps(value, allow_nan=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def trusted(self) -> bool:
            host = self.headers.get("Host", "")
            try:
                parsed = urlsplit("http://" + host)
                if not parsed.hostname or parsed.port not in (None, self.server.server_port):
                    raise ValueError
            except ValueError:
                self.json(400, {"error": "invalid Host header"})
                return False
            origin = self.headers.get("Origin")
            if origin is not None and origin != "http://" + host:
                self.json(403, {"error": "cross-origin request rejected"})
                return False
            return True

        def loopback(self) -> bool:
            return self.client_address[0] in ("127.0.0.1", "::1")

        def body(self):
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                raise LabError("Content-Length required")
            if not 1 <= length <= MAX_BODY:
                raise LabError("body size outside limit")
            try:
                return json.loads(self.rfile.read(length))
            except (UnicodeDecodeError, ValueError):
                raise LabError("invalid JSON")

        def do_GET(self):
            if not self.trusted():
                return
            path = urlsplit(self.path).path
            query = parse_qs(urlsplit(self.path).query)
            if path == "/api/health":
                self.json(200, {"status": "ok", "build": build, "hen_sha256": hen_sha,
                                "sessions": len(store.sessions)})
                return
            if path == "/hen.bin":
                if hen_bytes is None:
                    self.json(404, {"error": "artifacts/hen.bin is missing"})
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(hen_bytes)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-FW14-Hen-SHA256", hen_sha)
                self.end_headers()
                self.wfile.write(hen_bytes)
                return
            if path == "/api/log":
                try:
                    since = int((query.get("since") or ["0"])[0])
                except ValueError:
                    since = 0
                lines = store.log_since(since)
                self.json(200, {"seq": lines[-1]["seq"] if lines else since,
                                "lines": lines})
                return
            if path.startswith("/api/commands/") and path.endswith("/probe"):
                cid = path[len("/api/commands/"):-len("/probe")]
                try:
                    source, sha = store.probe_source(
                        cid, self.headers.get("X-FW14-Session", ""),
                        self.headers.get("X-FW14-Attempt", ""))
                except LabError as exc:
                    self.json(403, {"error": str(exc)})
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(source)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-FW14-Source-SHA256", sha)
                self.end_headers()
                self.wfile.write(source)
                return
            if path.startswith("/api/admin/"):
                if not self.loopback():
                    self.json(403, {"error": "admin routes are loopback only"})
                    return
                if path == "/api/admin/sessions":
                    self.json(200, store.list_sessions())
                    return
                if path == "/api/admin/commands":
                    self.json(200, store.list_commands())
                    return
                if path == "/api/admin/log":
                    try:
                        since = int((query.get("since") or ["0"])[0])
                    except ValueError:
                        since = 0
                    self.json(200, store.log_since(since))
                    return
                if path == "/api/admin/wait":
                    cid = (query.get("command_id") or [""])[0]
                    try:
                        timeout = float((query.get("timeout") or ["120"])[0])
                    except ValueError:
                        timeout = 120.0
                    try:
                        self.json(200, store.wait(cid, max(0.0, min(timeout, 600))))
                    except LabError as exc:
                        self.json(400, {"error": str(exc)})
                    return
                self.json(404, {"error": "unknown admin route"})
                return
            if path == "/api/state":
                self.json(200, {"sessions": store.list_sessions(),
                                "commands": store.list_commands()[:10],
                                "seq": store.seq})
                return
            asset = assets.get(path)
            if asset is None:
                if path == "/favicon.ico":
                    self.send_response(204)
                    self.end_headers()
                    return
                self.json(404, {"error": "not found"})
                return
            ctype = ("text/html; charset=utf-8" if path == "/" else
                     "text/javascript; charset=utf-8" if path.endswith(".js") else
                     "text/css; charset=utf-8")
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(asset)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(asset)

        def do_POST(self):
            if not self.trusted():
                return
            path = urlsplit(self.path).path
            try:
                value = self.body()
                if path == "/api/sessions":
                    session = store.register(
                        value.get("firmware_label"), value.get("user_agent"),
                        value.get("runner_version", 0), self.client_address[0])
                    self.json(201, session)
                    return
                if path.startswith("/api/admin/"):
                    if not self.loopback():
                        self.json(403, {"error": "admin routes are loopback only"})
                        return
                    if path == "/api/admin/enqueue-probe":
                        cid = store.enqueue_probe(
                            value.get("session_id"), Path(value.get("manifest", "")))
                        self.json(201, {"command_id": cid})
                        return
                    if path == "/api/admin/note":
                        line = store.event(value.get("level", "info"),
                                           str(value.get("text", ""))[:2000], "pc")
                        self.json(201, line)
                        return
                    if path == "/api/admin/cancel":
                        self.json(200, store.cancel(value.get("command_id")))
                        return
                    self.json(404, {"error": "unknown admin route"})
                    return
                sid = value.get("session_id")
                secret = self.headers.get("X-FW14-Session", "")
                if path == "/api/commands/claim":
                    command = store.claim(sid, secret)
                    self.json(200, {"command": command})
                    return
                if path == "/api/commands/mark":
                    payload = dict(value)
                    payload.pop("session_id", None)
                    self.json(201, store.mark(sid, secret, payload))
                    return
                if path == "/api/commands/result":
                    payload = dict(value)
                    payload.pop("session_id", None)
                    self.json(201, store.complete(sid, secret, payload))
                    return
                if path == "/api/log":
                    store.event(value.get("level", "info"),
                                str(value.get("text", ""))[:2000], sid[:8] if sid else "page")
                    self.json(201, {"ok": True})
                    return
                if path == "/api/dump/chunk":
                    self.json(201, store.chunk(sid, secret, value))
                    return
                self.json(404, {"error": "not found"})
            except LabError as exc:
                self.json(400, {"error": str(exc)})

    return Handler


# --------------------------------------------------------------------------- cli

def api(method: str, path: str, value=None, headers=None):
    url = DEFAULT_URL.rstrip("/") + path
    data = None
    hdrs = {"Accept": "application/json"}
    if value is not None:
        data = json.dumps(value).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    if headers:
        hdrs.update(headers)
    req = Request(url, data=data, headers=hdrs, method=method)
    try:
        with urlopen(req, timeout=700) as response:
            return json.loads(response.read())
    except HTTPError as exc:
        try:
            detail = json.loads(exc.read()).get("error")
        except Exception:  # noqa: BLE001
            detail = exc.reason
        raise LabError(str(detail))
    except URLError as exc:
        raise LabError("cannot reach %s: %s" % (DEFAULT_URL, exc.reason))


def main() -> int:
    parser = argparse.ArgumentParser(description="PS4 14.00 browser lab")
    sub = parser.add_subparsers(dest="cmd", required=True)

    serve = sub.add_parser("serve", help="run the HTTP server")
    serve.add_argument("--host", default="0.0.0.0")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--probes", type=Path, default=DEFAULT_PROBES)
    serve.add_argument("--state", type=Path, default=DEFAULT_STATE)
    serve.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    serve.add_argument("--dumps", type=Path, default=DEFAULT_DUMPS)

    sub.add_parser("sessions", help="list recent browser sessions")
    sub.add_parser("commands", help="list recent commands")
    enq = sub.add_parser("enqueue-probe", help="queue a probe manifest")
    enq.add_argument("--session", required=True)
    enq.add_argument("--manifest", type=Path, required=True)
    wait = sub.add_parser("wait", help="block until a command finishes")
    wait.add_argument("--command-id", required=True)
    wait.add_argument("--timeout", type=float, default=120.0)
    note = sub.add_parser("note", help="write a line to the browser log")
    note.add_argument("text")
    note.add_argument("--level", default="info")
    log = sub.add_parser("log", help="print the event log")
    log.add_argument("--since", type=int, default=0)
    cancel = sub.add_parser("cancel", help="cancel a queued command")
    cancel.add_argument("--command-id", required=True)

    args = parser.parse_args()
    try:
        if args.cmd == "serve":
            args.state.parent.mkdir(parents=True, exist_ok=True)
            store = Store(args.state, args.probes, args.results, args.dumps)
            server = ThreadingHTTPServer((args.host, args.port), make_handler(store))
            store.event("info", "server listening on http://%s:%d/  (probes: %s)" % (
                args.host, server.server_port, args.probes))
            hen = HERE.parent / "artifacts" / "hen.bin"
            if hen.exists():
                store.event("info", "serving /hen.bin from artifacts/ (%d bytes)" %
                            hen.stat().st_size)
            else:
                store.event("warn", "artifacts/hen.bin is missing: "
                                    "stage_hen_map_v1 will fail")
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                server.server_close()
            return 0
        if args.cmd == "sessions":
            print(json.dumps(api("GET", "/api/admin/sessions"), indent=2))
        elif args.cmd == "commands":
            print(json.dumps(api("GET", "/api/admin/commands"), indent=2))
        elif args.cmd == "enqueue-probe":
            out = api("POST", "/api/admin/enqueue-probe",
                      {"session_id": args.session, "manifest": str(args.manifest.resolve())})
            print(json.dumps(out, indent=2))
        elif args.cmd == "wait":
            out = api("GET", "/api/admin/wait?command_id=%s&timeout=%s" % (
                args.command_id, args.timeout))
            print(json.dumps(out, indent=2))
            return 0 if out.get("status") == "completed" else 1
        elif args.cmd == "note":
            api("POST", "/api/admin/note", {"text": args.text, "level": args.level})
        elif args.cmd == "log":
            for line in api("GET", "/api/admin/log?since=%d" % args.since):
                print("%s %-5s %s" % (line["ts"][11:19], line["level"], line["text"]))
        elif args.cmd == "cancel":
            print(json.dumps(api("POST", "/api/admin/cancel",
                                 {"command_id": args.command_id}), indent=2))
        return 0
    except LabError as exc:
        print("lab error: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
