// Stage HEN diag v1: launch HEN with the plugin system enabled (so the
// kpayload installs syscalls 107/108/109 and the 594 dynlib hook) but force
// kill_ui to 0, so SceShellUI is NOT restarted.
//
// This is the working stage_hen_diag_v1 flow (enable_plugins = 1,
// skip_patches = 0, PRX files written from the mapped image) plus the two
// _main code patches from stage_hen_full2_v1: r14d (kill_ui) becomes 0 and
// the ScePartyDaemon kill branch is skipped. The browser page therefore
// survives the HEN install, which is what lets stage_hen_hookread_v1 read
// sysent with the still-live kqueue ROP primitive and lets the userland
// syscall probes inspect SceShellUI afterwards.
//
// The quick variant (stage_hen_quick_v1) proved the console stays up, but it
// also disabled the two things HEN needs to become functional:
//
//   * it forced kill_ui = 0, so SceShellUI was never restarted. The plugin
//     system is injected by the 594 (dynlib_load_prx) hook into a process
//     while it loads /app0/sce_module/libc.prx - an already-running ShellUI
//     never does, so plugin_bootloader/plugin_mono/plugin_server never load
//     and there is no HEN UI at all;
//   * it set skip_patches = 1, which skips InstallShellCoreCodeForAppinfo() -
//     the ShellCore code cave that starts plugin_shellcore.prx and makes
//     installed fake PKGs launchable.
//
// Both were turned off because the console kept powering off. That was the
// global sysfilt_ops slot (stage_safedown_v1 now restores it), not HEN. This
// probe keeps the original HEN behaviour and only removes the post-Welcome
// drain loop.
//
// Upstream (Scene-Collective/ps4-hen, installer/source/main.c) shows the
// restart is gated:
//
//   bool kill_ui = config.enable_plugins;
//   ...
//   const char *proc = kill_ui ? "SceShellUI" : NULL;
//   if (kill_ui) { usleep(5s); notify(...); usleep(5s); }
//   kill_proc(proc);          // NULL -> immediate return
//
// So: enable_plugins = 1 is what makes the restart happen, and the restart is
// what injects the plugin system. The default config template is embedded in
// the image: its value bytes sit at fixed VAs (e.g. enable_plugins at
// 0x95000d03e), and init_config parses the file it was just given, so writing
// the template with the desired bytes is enough. The template already carries
// `config_version = 3`, matching DEFAULT_CONFIG_VERSION, so a pre-seeded
// /data/hen/hen.ini parses clean and HEN skips its "updating settings file"
// popup and the extra 5 s wait.
var HEN_BASE = 0x950000000;
var SCRATCH = 0x940900000;
var SYM_OFF = 0x800, NAME_OFF = 0x880, OUT_OFF = 0x900;
var BUF = SCRATCH + 0x500, RBUF = SCRATCH + 0x600;
var LOGPATH = "/data/hen/fw14_hen_log.txt";
var INIPATH = "/data/hen/hen.ini";
var TPL_VALUE = 0x95000d03e;   // '1' in "enable_plugins = 1"
var PATCH_R14D = 0x950004dcf;  // mov 0x44(%rsp),%r14d
var PATCH_PARTY = 0x950005dcb; // cmpl $0,0x44(%rsp)
var TPL_START = 0x95000b600, TPL_LEN = 6720;  // "[HEN]" .. "= 1\n"
var LIBKERNEL = 0x2001, O_RDONLY = 0, O_NONBLOCK = 0x4;
var O_WRONLY = 1, O_CREAT = 0x200, O_APPEND = 0x8, O_TRUNC = 0x400;
var phase = "preflight";

function fail(message) {
  return [{ id: "stage_hen_diag_v1", status: "error",
            details: { phase: phase, error: String(message).slice(0, 220) } }];
}

return (async function () {
  try {
    var n = window.__fw14NativeInvoke;
    var state = window.__fw14ArrayState;
    if (!n || !n.frame || !n.wrappers || !state || state.array[0] !== state.a ||
        !state.view || !state.ownedTypedView ||
        !Number.isSafeInteger(state.calibratedViewBase) ||
        !Number.isInteger(state.index))
      throw new Error("caller_missing");
    if (typeof n.callAddr !== "function") throw new Error("calladdr_missing");
    var su = window.__fw14StageU, hen = window.__fw14StageHen;
    if (!su || su.uid !== 0) throw new Error("uid_missing");
    if (!hen || !hen.mapped || hen.addr !== HEN_BASE)
      throw new Error("hen_not_mapped");

    var forged = state.view, carrier = state.ownedTypedView;
    var base = state.calibratedViewBase;
    function bytesAt(index, count) {
      var out = [];
      for (var i = 0; i < count; i++) out.push(forged[index + i]);
      return out;
    }
    function valueOf(bytes) {
      var v = 0;
      for (var i = bytes.length - 1; i >= 0; i--) v = v * 256 + bytes[i];
      return v;
    }
    function pointerBytes(value) {
      var out = [];
      for (var i = 0; i < 8; i++)
        out.push(Math.floor(value / Math.pow(2, i * 8)) & 255);
      return out;
    }
    function addressOf(object) {
      try {
        state.array[0] = object;
        return valueOf(bytesAt(state.index, 8));
      } finally { state.array[0] = state.a; }
    }
    var carrierSlot = addressOf(carrier) - base + 8;
    var carrierOriginal = bytesAt(carrierSlot, 8);
    function setCarrier(addr) {
      var next = pointerBytes(addr);
      for (var i = 0; i < 8; i++) forged[carrierSlot + i] = next[i];
    }
    function restoreCarrier() {
      for (var i = 0; i < 8; i++) forged[carrierSlot + i] = carrierOriginal[i];
    }
    function poke(addr, bytes) {
      setCarrier(addr);
      for (var i = 0; i < bytes.length; i++) carrier[i] = bytes[i];
      restoreCarrier();
    }
    function peek(addr, count) {
      setCarrier(addr);
      var out = [];
      for (var i = 0; i < count; i++) out.push(carrier[i]);
      restoreCarrier();
      return out;
    }
    function isErr(r) {
      return !!r && r.value === -1 && (r.high >>> 0) === 0xffffffff;
    }
    function eTag(r) {
      if (!isErr(r)) return "v" + r.value;
      var e = n.readErrno();
      return "e" + (e === null ? r.value : e);
    }
    function hex(v) { return "0x" + Math.floor(v).toString(16); }
    function pair(addr) {
      return [addr >>> 0, Math.floor(addr / 0x100000000) >>> 0];
    }
    function cstring(t) {
      var out = [];
      for (var i = 0; i < t.length; i++) out.push(t.charCodeAt(i) & 255);
      out.push(0);
      return out;
    }
    function putString(addr, t) { poke(addr, cstring(t)); }
    function toText(bytes) {
      var s = "";
      for (var i = 0; i < bytes.length; i++) {
        var c = bytes[i];
        if (c >= 32 && c < 127) s += String.fromCharCode(c);
        else if (c === 10) s += "|";
      }
      return s;
    }
    function drainRaw() {
      putString(BUF, "/dev/klog");
      var o = n.call("open", [BUF, O_RDONLY | O_NONBLOCK, 0]);
      if (isErr(o) || o.value < 0) return { tag: "open" + eTag(o), bytes: [] };
      var fd = o.value, all = [], total = 0, rtag = "-";
      for (var i = 0; i < 64; i++) {
        var r = n.call("read", [fd, RBUF, 4096]);
        rtag = eTag(r);
        if (isErr(r) || r.value <= 0) break;
        var chunk = peek(RBUF, r.value);
        for (var k = 0; k < chunk.length; k++) all.push(chunk[k]);
        total += r.value;
        if (total > 262144) break;
      }
      n.call("close", [fd]);
      return { tag: "fd" + fd + "/" + rtag + "/" + total, bytes: all };
    }
    function writeFile(path, bytes) {
      putString(BUF, path);
      var o = n.call("open", [BUF, O_WRONLY | O_CREAT | O_TRUNC, 420]);
      if (isErr(o) || o.value < 0) return "open" + eTag(o);
      var fd = o.value, off = 0;
      while (off < bytes.length) {
        var take = Math.min(4096, bytes.length - off);
        poke(RBUF, bytes.slice(off, off + take));
        var w = n.call("write", [fd, RBUF, take]);
        if (isErr(w) || w.value <= 0) break;
        off += w.value;
      }
      n.call("close", [fd]);
      return "ok" + off;
    }
    function appendLog(bytes) {
      if (!bytes.length) return "skip";
      putString(BUF, LOGPATH);
      var o = n.call("open", [BUF, O_WRONLY | O_CREAT | O_APPEND, 420]);
      if (isErr(o) || o.value < 0) return "open" + eTag(o);
      var fd = o.value, off = 0;
      while (off < bytes.length) {
        var take = Math.min(4096, bytes.length - off);
        poke(RBUF, bytes.slice(off, off + take));
        var w = n.call("write", [fd, RBUF, take]);
        if (isErr(w) || w.value <= 0) break;
        off += w.value;
      }
      n.call("close", [fd]);
      return "ok" + off;
    }
    // The server caps an attempt at 8 durable marks, so spend them only on
    // the stages that can kill the console. markSync needs the event loop to
    // run: never busy-wait around it.
    var markBudget = 8;
    async function mark(m) {
      if (markBudget <= 0) return;
      markBudget--;
      try {
        if (typeof api !== "undefined" && api && typeof api.markSync === "function")
          await api.markSync(m);
      } catch (error) { /* a lost mark must not abort the trace */ }
    }
    function sleep(ms) {
      return new Promise(function (resolve) { setTimeout(resolve, ms); });
    }

    var pid = n.call("getpid", []).value;
    var uidTag = eTag(n.call("sys24", []));

    // ---------------------------------- enable plugins, skip the restart
    // enable_plugins stays 1, so the kpayload installs syscalls 107/108/109
    // and the 594 dynlib hook, and the plugin system is armed. r14d (kill_ui)
    // is forced to 0 so SceShellUI is not killed: this page must survive the
    // install. HEN is therefore NOT fully active on this boot (no ShellUI
    // reload, so no plugin injection); this is a diagnostic boot.
    phase = "template";
    var tplByte = peek(TPL_VALUE, 1)[0];
    var tplTag = "keep:" + String.fromCharCode(tplByte);
    function same(a, b) { return a.join(",") === b.join(","); }

    // enable_plugins stays 1, but kill_ui (r14d) is forced to 0 so ShellUI
    // keeps running. The PartyDaemon branch is gated on the same config
    // field, so it is patched out too.
    phase = "codepatch";
    poke(PATCH_R14D, [0x45, 0x31, 0xf6, 0x90, 0x90]);   // xor r14d,r14d
    poke(PATCH_PARTY, [0xe9, 0x1e, 0x00, 0x00, 0x00]);  // jmp past kill block
    var codeTag = "r14:" +
      (same(peek(PATCH_R14D, 5), [0x45, 0x31, 0xf6, 0x90, 0x90]) ? "ok" : "bad") +
      ";pty:" +
      (same(peek(PATCH_PARTY, 5), [0xe9, 0x1e, 0, 0, 0]) ? "ok" : "bad");

    // Pre-seed /data/hen/hen.ini with the embedded template, rewriting only
    // the optional stages. enable_plugins stays 1 (the plugin system is
    // enabled) and skip_patches becomes 0 (so the kpayload's ShellCore/
    // ShellUI/RemotePlay patches and InstallShellCoreCodeForAppinfo run).
    // The template's `config_version = 3` matches DEFAULT_CONFIG_VERSION and
    // sets found_version = 1, so init_config's first parse suppresses both
    // the "updating settings file" popup and the 5 s re-parse wait.
    phase = "ini";
    var mkAddr = 0, mkTag = "-";
    putString(SCRATCH + SYM_OFF, "mkdir");
    poke(SCRATCH + OUT_OFF, [0, 0, 0, 0, 0, 0, 0, 0]);
    var mkRes = n.call("dynlib_dlsym",
      [LIBKERNEL, SCRATCH + SYM_OFF, SCRATCH + OUT_OFF]);
    if (!isErr(mkRes) && mkRes.value === 0) {
      var mkGot = valueOf(peek(SCRATCH + OUT_OFF, 8));
      if (Number.isSafeInteger(mkGot) && mkGot >= 0x100000000) mkAddr = mkGot;
    }
    if (mkAddr) {
      putString(SCRATCH + NAME_OFF, "/data/hen");
      var mkR = n.callAddr(mkAddr, [pair(SCRATCH + NAME_OFF), [511, 0]]);
      mkTag = isErr(mkR) ? ("e" + n.readErrno()) : ("v" + mkR.value);
    }
    var CFG = [
      [0x95000b811, 0x30],  // exploit_fixes  = 0
      [0x95000b8ea, 0x30],  // mmap_patches   = 0
      [0x95000b9f8, 0x30],  // block_updates  = 0
      [0x95000bda0, 0x30],  // disable_aslr   = 0
      [0x95000be54, 0x30],  // nobd_patches   = 0
      [0x95000c334, 0x30],  // genuine_cex    = 0
      [0x95000c6ac, 0x30],  // np_patch_check = 0
      [0x95000cc51, 0x30],  // np_regmgr_hook = 0
      [0x95000ccfa, 0x30],  // skip_patches   = 0
      [0x95000ce6d, 0x30],  // upload_prx     = 0
      [0x95000d03e, 0x31]   // enable_plugins = 1
    ];
    for (var ci = 0; ci < CFG.length; ci++) poke(CFG[ci][0], [CFG[ci][1]]);

    // HEN returns early ("HEN is already installed") if this exists.
    var ulTag = "-";
    putString(SCRATCH + SYM_OFF, "unlink");
    poke(SCRATCH + OUT_OFF, [0, 0, 0, 0, 0, 0, 0, 0]);
    var ulRes = n.call("dynlib_dlsym",
      [LIBKERNEL, SCRATCH + SYM_OFF, SCRATCH + OUT_OFF]);
    if (!isErr(ulRes) && ulRes.value === 0) {
      var ulAddr = valueOf(peek(SCRATCH + OUT_OFF, 8));
      if (Number.isSafeInteger(ulAddr) && ulAddr >= 0x100000000) {
        putString(SCRATCH + NAME_OFF, "/user/temp/hen.installed");
        var ulR = n.callAddr(ulAddr, [pair(SCRATCH + NAME_OFF)]);
        ulTag = isErr(ulR) ? ("e" + n.readErrno()) : ("v" + ulR.value);
        // InstallShellCoreCodeForAppinfo() is skipped if this marker exists,
        // but the code cave it guards is in-memory and does not survive a
        // reboot. A stale marker from an earlier run would silently disable
        // the fake-PKG appinfo patch, so remove it too.
        putString(SCRATCH + NAME_OFF, "/user/temp/shellcore_appinfo.installed");
        var aiR = n.callAddr(ulAddr, [pair(SCRATCH + NAME_OFF)]);
        ulTag += "/ai:" + (isErr(aiR) ? ("e" + n.readErrno()) : ("v" + aiR.value));
      }
    }
    var iniTag = "w:" + writeFile(INIPATH, peek(TPL_START, TPL_LEN));

    // Write the plugin PRXs ourselves, straight from the mapped image, and
    // leave upload_prx=0 so HEN's own upload_prx_to_disk() never runs. The
    // 64-bit source address is passed as a [lo,hi] pair to the write wrapper.
    phase = "prx";
    var PRX = [
      ["/data/hen/plugin_bootloader.prx", 0x95007bba0, 0xd4c0],
      ["/data/hen/plugin_loader.prx",     0x9500662c0, 0x158e0],
      ["/data/hen/plugin_server.prx",     0x95004ede0, 0x174e0],
      ["/data/hen/plugin_mono.prx",       0x95002c640, 0x22790],
      ["/data/hen/plugin_shellcore.prx",  0x950016d80, 0x158b0],
      ["/data/hen/patches.ini",           0x950016580, 0x7ef]
    ];
    var prxTag = "";
    for (var pi = 0; pi < PRX.length; pi++) {
      var path = PRX[pi][0], va = PRX[pi][1], len = PRX[pi][2];
      putString(BUF, path);
      var po = n.call("open", [BUF, O_WRONLY | O_CREAT | O_TRUNC, 420]);
      if (isErr(po) || po.value < 0) { prxTag += "o" + eTag(po) + ","; continue; }
      var pfd = po.value;
      var plo = va >>> 0, phi = Math.floor(va / 0x100000000);
      var pw = n.callAddr("write", [[pfd, 0], [plo, phi], [len, 0]]);
      n.call("close", [pfd]);
      prxTag += (isErr(pw) ? ("e" + n.readErrno()) : ("v" + pw.value)) + ",";
    }

    // baseline: drop whatever is already buffered
    phase = "klog_before";
    drainRaw();

    // ------------------------------------------------------- resolve
    phase = "dlsym";
    poke(SCRATCH + OUT_OFF, [0, 0, 0, 0, 0, 0, 0, 0]);
    var pcAddr = 0, symUsed = "-", dlsymTag = "-";
    var symbols = ["pthread_create", "scePthreadCreate"];
    for (var si = 0; si < symbols.length && pcAddr === 0; si++) {
      putString(SCRATCH + SYM_OFF, symbols[si]);
      var dRes = n.call("dynlib_dlsym",
        [LIBKERNEL, SCRATCH + SYM_OFF, SCRATCH + OUT_OFF]);
      dlsymTag = eTag(dRes);
      if (!isErr(dRes) && dRes.value === 0) {
        var got = valueOf(peek(SCRATCH + OUT_OFF, 8));
        if (Number.isSafeInteger(got) && got >= 0x100000000 &&
            got < 0x1000000000000) { pcAddr = got; symUsed = symbols[si]; }
      }
    }
    if (pcAddr === 0) throw new Error("pthread_create_not_resolved");

    // ------------------------------------------------------- launch
    phase = "create";
    poke(SCRATCH + OUT_OFF, [0, 0, 0, 0, 0, 0, 0, 0]);
    putString(SCRATCH + NAME_OFF, "hen");
    var lo = HEN_BASE >>> 0, hi = Math.floor(HEN_BASE / 0x100000000);
    var rcRes = n.callAddr(pcAddr, [
      pair(SCRATCH + OUT_OFF), [0, 0], [lo, hi], [0, 0],
      pair(SCRATCH + NAME_OFF)
    ]);
    var handle = valueOf(peek(SCRATCH + OUT_OFF, 8));
    var rcTag = eTag(rcRes);
    var launched = !isErr(rcRes) && rcRes.value === 0 && handle !== 0;

    // ------------------------------------------------------- outcome
    // Quick variant: NO post-launch drain loop.
    //
    // stage_hen_prxwrite_v1 keeps the console busy for 24 s after Welcome,
    // draining klog and appending to a file. Boots 36 and 39 both died inside
    // that window, and boot 26 - the only run that survived - completed it.
    // That is confounded: we cannot tell whether HEN or our own loop killed
    // the console. This probe launches HEN, records ONE durable mark, and
    // returns immediately. If the console still dies, HEN did it.
    phase = "outcome";
    await mark("hen_fq_launch");
    var post = n.call("getpid", []);
    var intact = post.value === pid && post.high === 0 &&
      state.array[0] === state.a &&
      bytesAt(carrierSlot, 8).join(",") === carrierOriginal.join(",");
    return [{
      id: "stage_hen_diag_v1",
      status: launched ? "pass" : "fail",
      details: {
        pid: pid, uid: uidTag, patch: tplTag + "/" + codeTag,
        ini: iniTag + "/" + mkTag, rc: rcTag, handle: hex(handle),
        prx: prxTag.slice(0, 180),
        state: launched ? "launched" : "create_failed", intact: intact
      }
    }];
  } catch (error) {
    return fail(error);
  }
})();
