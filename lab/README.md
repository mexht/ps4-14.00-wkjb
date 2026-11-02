# lab/ — the live harness

One stdlib-only Python file plus a small ES5 page. It has no third-party
dependencies and is the only harness this package needs.

```
lab/
  server.py     HTTP server, probe queue, attempt tokens, event log, CLI
  web/          what the console loads (index.html, app.js, style.css, sha256.js)
  test_lab.py   HTTP-level test: starts its own server, runs the full flow
  test_page.js  runs the real page code against a real server (DOM/XHR shim)
```

## Run

```bash
python3 lab/server.py serve --host 0.0.0.0 --port 8765
```

Open `http://<pc>:8765/` on the console. The page registers a session
automatically and then polls for work; nothing needs to be clicked.

State and output (all git-ignored):

- `lab/state.json` — sessions, commands, log tail, sequence counter (atomic write)
- `lab/results/<command-id>.json` — one completed result
- `lab/dumps/<command-id>.bin` — optional probe uploads

## CLI

Every command talks to `FW14_LAB_URL` (default `http://127.0.0.1:8765`):

```bash
python3 lab/server.py sessions
python3 lab/server.py commands
python3 lab/server.py enqueue-probe --session <id> --manifest probes/foo.json
python3 lab/server.py wait --command-id <id> --timeout 180
python3 lab/server.py note "stage: race" --level stage
python3 lab/server.py log --since 0
python3 lab/server.py cancel --command-id <id>
```

`wait` exits 0 when the probe completed and 1 on timeout, so it can gate a
shell script. `enqueue-probe` resolves the manifest on the PC, checks it against
the harness limits (≤12 checks, ≤12 scalar details, `timeout_ms` 1000–30000,
source ≤32768 B) and hashes the source; the page re-checks the digest before
running it.

## Protocol

| Route | Who | Purpose |
| --- | --- | --- |
| `POST /api/sessions` | page | register, returns `session_id` + `session_secret` |
| `POST /api/commands/claim` | page | take the oldest queued command (or `null`) |
| `GET /api/commands/<id>/probe` | page | probe source; needs `X-FW14-Session` (secret) and `X-FW14-Attempt` (token) |
| `POST /api/commands/mark` | page | phase marker (`markSync` uses the blocking XHR) |
| `POST /api/commands/result` | page | checks, validated against the manifest |
| `POST /api/log` | page | page-side log line |
| `GET /api/log?since=N` | page | verbose log poll (drives the live view) |
| `GET /api/health` | anyone | liveness + build hash + `hen.bin` / `goldhen.bin` digests |
| `GET /hen.bin` | page | bundled ps4-hen image from `artifacts/` |
| `GET /goldhen.bin` | page | bundled official GoldHEN image from `artifacts/` |
| `/api/admin/*` | loopback only | CLI: sessions, commands, enqueue, note, wait, cancel, log |

Results must match the manifest's `check_ids` in order; a probe that could not
run may instead report a single synthetic `probe_error` check so the failure is
visible rather than leaving the queue stalled.

`Origin` is checked when present, and admin routes are loopback-only, but this
is a trusted-LAN tool: do not expose it to the internet.

## Live progress

The driver mirrors each chain stage into the log:

```python
control("note", "stage: race", "--level", "stage")
```

The page polls `/api/log?since=` once a second and renders colour-coded lines
(`stage`, `ok`, `warn`, `error`, `run`, `queue`, `mark`), the newest stage in the
"Current stage" card, and a pass/fail summary of the last probe. That is what
makes the console screen useful while the chain runs, including the long race
retries.

## Tests

```bash
python3 lab/test_lab.py     # server: sessions, queue, probe, result, log, admin
node lab/test_page.js       # page code end to end (needs node; no browser)
```

Both start their own server on a free port with a temporary state directory and
exit non-zero on failure.
