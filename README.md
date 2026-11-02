# PS4 14.00 — Browser HEN Chain

A browser-only chain for a **retail PS4 on firmware 14.00**. From the system
browser it gains kernel read/write, applies a reviewed patch set, escapes the
sandbox, and loads the selected payload. The **default is official GoldHEN
v2.4b18.13**; `--payload hen` installs Scene-Collective ps4-hen 2.2.0 instead,
including the plugin PRX repair and `SceShellUI` restart that bring up the
**★ HEN Settings** menu.

> **Read [`RISKS.md`](RISKS.md) and [`COMPLIANCE.md`](COMPLIANCE.md) first.**
>
> The package ships both payload images and the 632-byte kernel patch blob,
> with credits in [`CREDITS.md`](CREDITS.md). Verify the hashes before running:
> a modified payload can damage the console.
>
> Use it only on a console **you own**, on a **trusted LAN**, and within the
> law where you live. Not for piracy, cheating, or resale of modified consoles.

## Requirements

| item | value |
| --- | --- |
| console | retail PS4, firmware **14.00 only** |
| entry point | system browser (WebKit), LAN page only |
| payload | **GoldHEN v2.4b18.13** (default) or Scene-Collective ps4-hen **2.2.0 BETA** (`--payload hen`) |
| PC | Linux, Python 3.8+ (standard library only) |
| network | console and PC on the same trusted LAN |
| validation | two consecutive cold boots, one-shot `--launch` |

Other firmware versions are unsupported: the 14.00 offsets, guard table, and
image patch offsets are pinned, and the tools reject any hash mismatch.

Before starting, back up saves you care about and use a stable power supply.
A failed run can power the console off without warning.

Verify the shipped payload hashes before the first run —
`sha256sum -c SHA256SUMS` ([details](#verify-the-payload)).

## Run

### Start the lab server

```bash
python3 lab/server.py serve --host 0.0.0.0 --port 8765
hostname -I        # find the PC's LAN address
```

Leave it running. Runtime data goes to `lab/state.json`, `lab/results/`, and
`lab/dumps/` (Git-ignored). Optional self-test, no console needed:

```bash
python3 lab/test_lab.py
node lab/test_page.js
```

### Open the page on the PS4

1. Open the **system browser**.
2. Go to `http://<HOST-LAN-IP>:8765/`.
3. Wait for **Connected** and a session id.

The page has two buttons: **Jailbreak** starts the GoldHEN chain (GoldHEN
v2.4b18.13, latest version by SiSTRo), and **ps4-hen** starts the ps4-hen
2.2.0 chain. Pressing either asks the server to run that chain for the session
(`POST /api/jailbreak`), so the server does the work and can run on any
always-on machine on the LAN. The server refuses to start a chain for a session
whose user agent is not a PS4, so a desktop browser on the LAN cannot trigger
it. `lab/ps4-lab.service` is a systemd user unit for that:

```bash
cp lab/ps4-lab.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now ps4-lab
```

The unit expects the tree at `~/ps4-14.00-wkjb` and serves port 8765. Keep the
page in the foreground while the chain runs. If it cannot connect, check the
host firewall and that both devices are on the same subnet.

The page can also start the chain by itself: add `?auto=goldhen` and it runs
as soon as the session registers, with no click at all. The PS4 browser
restores its last URL from
`/user/home/<uid>/webbrowser/endhistory.txt`, so opening the browser is then
the only step after a boot.

GoldHEN survives **rest mode** on 14.00: choose Enter Rest Mode instead of a
full shutdown and the payload, FTP 2121 and klog 3232 stay up across
suspend/resume. Only a full power-off needs the chain again.

### Run the chain

```bash
python3 chain-driver/chain.py --launch
```

That launches **GoldHEN v2.4b18.13**. To use ps4-hen instead:

```bash
python3 chain-driver/chain.py --launch --payload hen
```

The driver uses the newest live page automatically. To pin a session:

```bash
python3 chain-driver/chain.py <session-id> --launch [--payload hen]
```

| option | meaning |
| --- | --- |
| `--launch` | run the full install for the selected payload |
| `--payload goldhen` | **default**: GoldHEN v2.4b18.13 — patch, prison, `safedown`, map the installer and enter it through the kexec gate; klog 3232 comes up, FTP 2121 and binloader 9090 are toggled in GoldHEN's settings menu, and the ShellUI reload takes the browser page with it |
| `--payload hen` | ps4-hen 2.2.0: chain → install (`kill_ui=0`) → wait for the 594 hook → repair PRXs → disable `plugin_mono` in `plugins.ini` → `safedown` → verify → restart `ScePartyDaemon` → restart `SceShellUI` |
| `--wait-reload N` | seconds to wait for a reopened browser after a bad draw (default 240) |
| `--hen-diag` | read-only ps4-hen diagnostic install, no ShellUI restart (**requires `--payload hen`**) |
| `--server` | ps4-hen fallback: start HEN's plugin_server in the page (FTP 2121, klog 3232); no ShellUI/PartyDaemon restart, so the page and server stay up |
| `--stop-after STAGE` | stop before a named stage |
| `--resume-after STAGE` | resume after a named prefix stage |
| `--settle N` | idle N seconds after install, then ping |

Without `--launch`, the driver stops after the kernel patch and sandbox escape
(and `safedown` for GoldHEN); it does not start a payload. A run takes a few
minutes and can take longer while a heap draw is retried; watch the stage names
on the console page.

## Package layout

```
ps4-14.00-hen-public/
├── chain-driver/chain.py     chain driver (stages, gates, recovery)
├── lab/server.py             queue + page server (stdlib only)
├── lab/web/                  page loaded by the console
├── lab/ps4-lab.service       systemd user unit for an always-on host
├── artifacts/goldhen.bin     official GoldHEN v2.4b18.13 payload (default)
├── artifacts/hen.bin         pinned ps4-hen 2.2.0 image (--payload hen)
├── artifacts/pkb.bin         pinned 632-byte kernel patch blob
├── probes/                   browser-side stages and manifests
├── tools/                    payload preparation and HEN patchers
├── README.md  CHANGELOG.md  RISKS.md  COMPLIANCE.md  CREDITS.md
└── SHA256SUMS
```

The selected payload (`artifacts/goldhen.bin` by default, or
`artifacts/hen.bin` with `--payload hen`) and `probes/stage_patch_v1.js` are
required at runtime; the driver refuses to start without them. Recent changes
are listed in [`CHANGELOG.md`](CHANGELOG.md).

## Verify the payload

| file | sha256 | size | contents |
| --- | --- | --- | --- |
| `artifacts/goldhen.bin` | `39452f5e…09ea4d` | 297 496 | official GoldHEN v2.4b18.13 raw payload, unmodified |
| `artifacts/hen.bin` | `820f9bbe…cebae9` | 562 240 | ps4-hen 2.2.0 + Debug Settings patch + `td_name` gate NOP |
| `artifacts/pkb.bin` | `165d2ad9…a49c02` | 632 | reviewed 14.00 ring-0 patch blob |
| `probes/stage_patch_v1.js` | rendered locally | — | patch probe with the blob embedded |

From the package root:

```bash
sha256sum -c SHA256SUMS
python3 tools/prepare_operator_data.py --check
```

The first command verifies every shipped file, including both payload images.
The second validates the ps4-hen image and kernel blob and re-renders the
patch probe; it does not modify `goldhen.bin`. If a hash does not match,
**stop**. GoldHEN is the official GoldHEN project's payload; the ps4-hen image
is Scene-Collective/ps4-hen 2.2.0 work with this project's image patches
applied; the kernel blob derives from Hx1400 research material. See
[`CREDITS.md`](CREDITS.md).

## Rebuild the payload (optional)

The bundled files are already valid. `artifacts/goldhen.bin` is used exactly
as released by the GoldHEN project and is not modified by these tools.

To rebuild the ps4-hen image from your own copies:

```bash
python3 tools/prepare_operator_data.py --hen /path/to/hen.bin --blob /path/to/pkb.bin
```

Accepted HEN inputs:

| sha256 | action |
| --- | --- |
| `29ec095f…edec06` | pristine 2.2.0; applies both patches |
| `1c1cec9f…222bd` | 3-patch Debug Settings image; applies the gate NOP |
| `820f9bbe…cebae9` | shipped final image; used as-is |

The script validates the result and blob, writes `artifacts/hen.bin`, and
renders `probes/stage_patch_v1.js`. Use `--check` to validate without writing.

## Success

With the default payload the driver ends with:

```
CHAIN COMPLETE
```

GoldHEN shows its **GoldHEN v2.4b18.13 loaded!** notification and adds its
settings menu. Its FTP (2121), binloader (9090) and klog (3232) servers are
available on the console's LAN address.

With `--payload hen`, the driver also ends with `CHAIN COMPLETE`. Open
**Settings** and look for **★ HEN Settings**; it should open without crashing.
The Plugins Manager lists `/data/hen/plugins`; with no custom plugin installed
it shows only the built-in entry — expected. User plugins load when a game or
app starts, not into `SceShellUI`.

## Failure and recovery

Most failures are **per-WebProcess heap draws**, not kernel damage. Nothing is
written at those points, so a page reload is not enough — the browser process
must be replaced.

| message / symptom | action |
| --- | --- |
| `reloading page (bad heap draw)` | automatic; no action |
| `push_v2 absent; trying push_v9` | automatic; no action |
| `STOP: bad groom/race/fake-plant draw` | fully **close and reopen** the PS4 browser; the driver waits up to `--wait-reload` seconds and resumes |
| `guards 0/24` on an already-installed boot | automatic repair-only path for ps4-hen; with GoldHEN, cold reboot to launch it again |
| `STOP: boot is spent` | power-cycle; the driver first tries `safedown` |
| `missing required payload data` | restore the selected payload (`goldhen.bin` or `hen.bin`) or run `tools/prepare_operator_data.py` |
| `no live session` | open/reopen the page; check the server and LAN |

A failure **after** `fg` is different: the fake `sysfilt_ops` is live. The
driver makes a best-effort `safedown` pass, then asks for a cold reboot.

## Reboot and re-run

- The payload is **per-boot**. A cold reboot returns the console to stock.
- **GoldHEN is launched once per boot.** A second run on the same boot stops
  at the guard check; cold reboot and run `--launch` again.
- ps4-hen keeps `/data/hen` (payloads, config, plugins) across reboots and
  reuses it. An already-installed boot is detected from the guard-patch
  signature and switched to the repair-only path.
- To install again: reopen the page and run `chain.py --launch`
  (add `--payload hen` for ps4-hen).
- Removing the payload data directories requires a jailbroken process and is
  not covered here; leaving them does not affect a stock boot.

## Troubleshooting

| symptom | fix |
| --- | --- |
| page stays on “connecting” | check the server, firewall, IP, and subnet |
| `enqueue-failed … manifest` | restore `probes/stage_patch_v1.js` or rerun the preparation script |
| console powers off during a stage | power-cycle; the next boot is stock; retry |
| `fetch /goldhen.bin` fails | restore `artifacts/goldhen.bin` from the official GoldHEN release |
| `fetch /hen.bin` fails | restore `artifacts/hen.bin` or rerun the preparation script |
| ps4-hen menu missing after a successful run | rerun on a new page; all five PRXs are repaired after the hook |
| ps4-hen menu opens but a plugin is missing | user plugins load on game/app launch; check `/data/hen/plugins` and `plugins.ini` |
| second run stops at `guards` | expected; ps4-hen switches to repair-only, GoldHEN needs a cold reboot |

If the console is unstable, power it off, wait a few seconds, and boot normally.
See [`RISKS.md`](RISKS.md) for the recovery ladder.

## Security and legal

- The lab server is **HTTP and unauthenticated**. Anyone who can reach port
  8765 can enqueue probes that run in the console browser with kernel access.
  Bind it to the LAN only; never port-forward it or use public Wi-Fi. Stop it
  with `Ctrl-C` when done.
- Install only plugins you trust; they run with full process privileges.
- **Risks:** [`RISKS.md`](RISKS.md) — bricking, power-off, PSN/account bans,
  warranty, data loss, legal exposure.
- **Compliance:** [`COMPLIANCE.md`](COMPLIANCE.md) — own console only, no
  piracy, no DRM circumvention for infringement, no cheating, no distribution
  of Sony firmware or game content.
- **Credits:** [`CREDITS.md`](CREDITS.md).

This is not legal advice. If you are unsure whether your use is lawful where
you live, do not run it.
