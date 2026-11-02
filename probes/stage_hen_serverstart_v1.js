// Stage hen serverstart v1: run HEN's plugin_server inside this page.
//
// plugin_server's plugin_load() is process-agnostic: it spawns pthread_kserver
// (klog, 3232) and pthread_ftp (FTP, 2121) and then parks the calling thread.
// HEN normally reaches it by injecting the PRX into ScePartyDaemon, which this
// console does not run. Loading it here gives an FTP server for as long as the
// lab page stays open, without touching ScePartyDaemon or a game process.
//
// Run it only after HEN's 594 hook is live and the process is jailbroken
// (uid 0 + prison escaped). Requires /data/hen/plugin_server.prx on disk.
var SCRATCH = 0x940900000;
var BUF = SCRATCH + 0x400;
var NAME = SCRATCH + 0x1500;
var THREAD = SCRATCH + 0x1680;
var HANDLE = SCRATCH + 0x1700;
var SYM = SCRATCH + 0x1740;
var OUT = SCRATCH + 0x1780;
var LIBKERNEL = 0x2001;
var PRX = "/data/hen/plugin_server.prx";
var phase = "preflight";

function fail(message) {
  return [{ id: "hen_serverstart_v1", status: "error",
            details: { phase: phase, error: String(message).slice(0, 220) } }];
}
return (async function () {
  try {
    var n = window.__fw14NativeInvoke;
    var state = window.__fw14ArrayState;
    if (!n || !n.frame || !n.wrappers || !state ||
        state.array[0] !== state.a || !state.view || !state.ownedTypedView ||
        !Number.isSafeInteger(state.calibratedViewBase) ||
        !Number.isInteger(state.index))
      throw new Error("caller_missing");
    if (typeof n.wrappers.sys594 !== "number" ||
        typeof n.wrappers.dynlib_dlsym !== "number" ||
        typeof n.callAddr !== "function")
      throw new Error("native_primitives_missing");

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
    function pair(addr) {
      return [addr >>> 0, Math.floor(addr / 0x100000000) >>> 0];
    }
    function putString(addr, t) {
      var bytes = [];
      for (var i = 0; i < t.length; i++) bytes.push(t.charCodeAt(i) & 255);
      bytes.push(0);
      poke(addr, bytes);
    }
    function sym(handle, name) {
      putString(SYM, name);
      poke(OUT, [0, 0, 0, 0, 0, 0, 0, 0]);
      var r = n.call("dynlib_dlsym", [handle, SYM, OUT]);
      var a = (!isErr(r) && r.value === 0) ? valueOf(peek(OUT, 8)) : 0;
      return (Number.isSafeInteger(a) && a >= 0x100000000 &&
              a < 0x1000000000000) ? a : 0;
    }

    // ------------------------------------------------ load plugin_server
    phase = "load";
    putString(BUF, PRX);
    poke(HANDLE, [0, 0, 0, 0, 0, 0, 0, 0]);
    var lr = n.call("sys594", [BUF, 0, HANDLE]);
    var handle = valueOf(peek(HANDLE, 4)) >>> 0;
    if (!handle) throw new Error("load_" + eTag(lr));

    // ------------------------------------------------ resolve entry points
    phase = "dlsym";
    var loadAddr = sym(handle, "plugin_load");
    if (!loadAddr) throw new Error("no_plugin_load");
    var createAddr = sym(LIBKERNEL, "pthread_create");
    if (!createAddr) createAddr = sym(LIBKERNEL, "scePthreadCreate");
    if (!createAddr) throw new Error("no_pthread_create");

    // ------------------------------------------------ run plugin_load
    // The entry point parks its thread forever, so it must not run here.
    phase = "create";
    poke(THREAD, [0, 0, 0, 0, 0, 0, 0, 0]);
    putString(NAME, "henserver");
    var rc = n.callAddr(createAddr, [
      pair(THREAD), [0, 0], pair(loadAddr), [0, 0], pair(NAME)
    ]);
    var thread = valueOf(peek(THREAD, 8));
    var started = !isErr(rc) && rc.value === 0 && thread !== 0;

    phase = "outcome";
    return [{
      id: "hen_serverstart_v1",
      status: started ? "pass" : "fail",
      details: {
        state: started ? "started" : "create_failed",
        handle: "0x" + handle.toString(16),
        plugin_load: "0x" + loadAddr.toString(16),
        pthread_create: "0x" + createAddr.toString(16),
        thread: "0x" + thread.toString(16),
        rc: eTag(rc),
        note: started ? "FTP 2121 / klog 3232 should be listening" : "-"
      }
    }];
  } catch (error) {
    return fail(error && error.message ? error.message : error);
  }
})();
