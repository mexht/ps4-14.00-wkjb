# Probes

Each `*.json` manifest names a browser-side stage (`script`), the expected
`check_ids`, and a timeout. The lab server validates and hashes the source
before the page runs it.

`stage_patch_v1.js` ships rendered, with the pinned 632-byte kernel patch blob
embedded. `stage_patch_v1.js.in` is the placeholder template used by
`tools/prepare_operator_data.py` to regenerate it from `artifacts/pkb.bin`.

The probes are ordered by the driver; you normally do not enqueue them by
hand. `lab/README.md` documents the queue and the admin CLI if you need to.

`stage_hen_plugins_v1` rewrites `/data/hen/plugins.ini` during `--launch` and
turns every `plugin_mono.prx` entry off. The HEN Settings menu is injected by
the kpayload's 594 hook into SceShellUI and does not use that file; only game
processes read it, where plugin_mono can crash Mono-based titles. Every other
byte of the ini is preserved and a one-time `.pre14.bak` copy is kept.

`stage_party_restart_v1` kills ScePartyDaemon during `--launch`, before the
ShellUI restart. The 594 hook injects `plugin_server.prx` only while that
process loads libSceSysmodule, and `stage_hen_diag_v1` patches out HEN's own
daemon kill. Without the restart, HEN's FTP (2121), binloader (9090) and klog
(3232) never start even though `plugin_server.prx` is on disk.

`array_iterator_short_control_v1` is a harmless self-test probe used only by
`lab/test_lab.py` / `lab/test_page.js`; the chain does not use it.
