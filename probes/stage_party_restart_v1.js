// Stage party restart v1: find ScePartyDaemon by name with sysctl and kill it.
//
// HEN's 594 hook injects plugin_mono into SceShellUI and plugin_server into
// ScePartyDaemon, but only while that process loads libSceSysmodule.sprx.
// stage_hen_diag_v1 patches out HEN's own ScePartyDaemon kill branch (and
// forces kill_ui=0), so the daemon is never restarted during --launch and
// plugin_server is never injected. That is why the FTP server (2121), the
// binloader (9090) and the klog server (3232) stay closed even though the
// modules are on disk.
//
// Killing the daemon makes the system respawn it; the next libSceSysmodule
// load then hits the live hook and plugin_server starts its servers.
//
// Same scan shape as stage_shell_restart_v2: walk KERN_PROC_PID for a process
// record whose comm contains the name, then SIGKILL it. Non-fatal if the
// daemon is not running: open the Party app and run this again.
var state = window.__fw14ArrayState;
var result;
try {
  var n = window.__fw14NativeInvoke;
  if (!n || !n.frame || !n.wrappers ||
      typeof n.wrappers.sysctl !== "number" ||
      typeof n.wrappers.kill !== "number" ||
      !state || state.array[0] !== state.a)
    throw new Error("caller_missing");
  var f = n.frame;
  var dv = new DataView(f.buffer, f.byteOffset, f.byteLength);
  var MIB = 0x300, LEN = 0x200, BUF = 0x400, BUFSZ = 0x1800;
  var NEEDLE = "SceParty";
  function isErr(r) {
    return !!r && r.value === -1 && (r.high >>> 0) === 0xffffffff;
  }
  function comm(pid) {
    dv.setUint32(MIB, 1, true);
    dv.setUint32(MIB + 4, 14, true);
    dv.setUint32(MIB + 8, 1, true);
    dv.setUint32(MIB + 12, pid, true);
    dv.setUint32(LEN, BUFSZ, true);
    f.fill(0, BUF, BUF + BUFSZ);
    var r = n.call("sysctl",
      [n.frameAddress + MIB, 4, n.frameAddress + BUF, n.frameAddress + LEN, 0, 0]);
    if (isErr(r) || r.value !== 0) return "";
    var len = dv.getUint32(LEN, true);
    if (len > BUFSZ) len = BUFSZ;
    var name = "", best = "";
    for (var i = 0; i <= len; i++) {
      var c = i < len ? f[BUF + i] : 0;
      if (c >= 32 && c < 127) { name += String.fromCharCode(c); continue; }
      if (name.length >= 5 && name.indexOf(NEEDLE) >= 0 &&
          (best === "" || name.length < best.length)) best = name;
      name = "";
    }
    return best;
  }
  var me = n.call("getpid", []).value;
  var target = 0, name = "";
  for (var p = 1; p <= 200; p++) {
    if (p === me) continue;
    var c = comm(p);
    if (c) { target = p; name = c; break; }
  }
  if (!target)
    return [{ id: "party_restart_v1", status: "fail",
              details: { me: me, target: 0, kill: "not_running",
                         note: "open the Party app, then retry" } }];
  try { api.markSync("party_kill_pre"); } catch (ignore) {}
  var kr = n.call("kill", [target, 9]);
  var ok = !isErr(kr);
  result = {
    id: "party_restart_v1", status: ok ? "pass" : "fail",
    details: { me: me, target: target, name: name.slice(0, 28),
               kill: ok ? "v" + kr.value : "e" + n.readErrno(),
               note: ok ? "restarting_partydaemon" : "kill_failed" }
  };
} catch (e) {
  result = { id: "party_restart_v1", status: "error",
             details: { error: String(e).slice(0, 220) } };
}
return [result];
