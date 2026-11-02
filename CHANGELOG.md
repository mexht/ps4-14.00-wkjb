# Changelog

## 2026-11-03 — one-click, always-on host

- **Autostart:** `?auto=goldhen` (or `?auto=hen`) in the page URL makes the
  server start the chain when the session registers. `FW14_AUTOSTART=0`
  disables it.
- **Jailbreak API:** `POST /api/jailbreak` runs `chain.py` for an authenticated
  session — `202` on start, `409` while another chain runs.
- **Buttons:** the page has **Jailbreak** (GoldHEN v2.4b18.13, latest version
  by SiSTRo) and **ps4-hen** (ps4-hen 2.2.0). Both use the API and disable
  themselves while a chain runs.
- **PS4-client check:** sessions report `ps4: true|false`. Non-PS4 user agents
  get `403` from the API, are skipped by autostart, and see a disabled button.
- **Hosting:** `lab/ps4-lab.service` is a systemd user unit that serves port
  8765 from `~/ps4-14.00-wkjb` on an always-on machine.
- **Rest mode:** GoldHEN, FTP 2121 and klog 3232 survive suspend/resume on
  14.00; only a full power-off needs the chain again.
- Chain logs go to `lab/dumps/chain-<session>.log`.

## 2026-11-02 — GoldHEN default

- GoldHEN v2.4b18.13 is the default payload; `--payload hen` keeps ps4-hen
  2.2.0.
- The installer enters at `0x1653` in ring 0 with `CR0.WP` cleared for the
  call (`probes/stage_goldhen_v2.js`), fixing the post-klog freeze.
