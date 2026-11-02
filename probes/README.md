# Probes

Each `*.json` manifest names a browser-side stage (`script`), the expected
`check_ids`, and a timeout. The lab server validates and hashes the source
before the page runs it.

`stage_patch_v1.js` ships rendered, with the pinned 632-byte kernel patch blob
embedded. `stage_patch_v1.js.in` is the placeholder template used by
`tools/prepare_operator_data.py` to regenerate it from `artifacts/pkb.bin`.

`stage_goldhen_v2` fetches the official GoldHEN v2.4b18.13 installer from
`/goldhen.bin`, copies it into a fresh anonymous RWX mapping (falling back to
a jitshm map at `0x926200000` if the kernel refuses `PROT_EXEC`), verifies the
`jmp rel32` head, entry (`0x16ab`), tail and zero-filled tail slack, then runs
a four-byte ring-0 self test through the kexec gate (`syscall 11`). Only then
does it enter the installer at image offset `0x1653` through the same gate,
inside a ring-0 wrapper that clears `CR0.WP` and 16-byte-aligns the stack for
the whole call.

`0x1653` is a ring-0 installer, not a thread entry. It detects the firmware,
fills its GOT, applies four of its own kernel patches, prints the banner,
hashes and decrypts the compressed kernel payload in place, asks the kernel
allocator for `0xc2418` bytes, inflates the 638 712-byte payload there and
calls its entry (`0x25f8`). The kernel payload then installs GoldHEN's hooks
and brings up klog 3232; FTP 2121 and binloader 9090 are enabled from
GoldHEN's own settings menu, so no `hen.ini`, plugin-PRX or ShellUI work
follows it. The driver runs `stage_safedown_v1` first because GoldHEN
restarts `SceShellUI`, which also takes the browser page with it.

The wrapper exists because the payload's init writes its BSS after the klog
step without bracketing the writes; with `CR0.WP` set those writes are the
reference driver's documented "delayed death" (klog 3232 comes up, FTP 2121
never does). Driving each of the payload's fifteen init steps separately would
need a composite image this tree does not ship, so the single installer call
runs with WP clear instead.

The payload's own entry must not be used as a pthread start routine: it tests
the return address it was called with for a kernel address and, when that test
fails, issues `syscall(11, 0x1653)` with a literal address, which jumps into
unmapped memory and powers the console off. That was `stage_goldhen_v1`; v2
replaces it.

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

`stage_hen_serverstart_v1` is the fallback when the console does not run
ScePartyDaemon. It loads `plugin_server.prx` into the page and calls
`plugin_load`, which starts FTP (2121) and klog (3232) in this WebProcess.
Those servers live only while the lab page stays open. Use it with
`chain.py --server` (which skips the ShellUI restart on purpose).

`array_iterator_short_control_v1` is a harmless self-test probe used only by
`lab/test_lab.py` / `lab/test_page.js`; the chain does not use it.
