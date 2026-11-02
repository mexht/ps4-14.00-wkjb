// Stage HEN verify v1: did the launched hen.bin actually do anything?
//
// Preconditions: stage_hen_launch_v1 reported state=launched and uid=0.
// The escape lets this process open absolute paths, so the probe looks for
// the files a GoldHEN-style payload creates during startup and reads the
// version file if present. Read-only: it opens with O_RDONLY and closes.
var SCRATCH = 0x940900000;
var BUF = SCRATCH + 0x700;   // path strings
var RBUF = SCRATCH + 0x780;  // read buffer
var PATHS = [
  "/data/hen/version.txt",
  "/data/hen/hen.ini",
  "/data/hen/plugin_loader.prx",
  "/user/temp/hen.installed"
];
var phase = "preflight";

function fail(message) {
  return [{ id: "stage_hen_verify_v1", status: "error",
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
    var su = window.__fw14StageU, hen = window.__fw14StageHen;
    if (!su || su.uid !== 0) throw new Error("uid_missing");
    if (!hen || !hen.mapped) throw new Error("hen_not_mapped");

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
    function mark(m) {
      if (typeof api !== "undefined" && api && typeof api.markSync === "function")
        api.markSync(m);
    }

    var pid = n.call("getpid", []).value;
    phase = "scan";
    mark("hen_verify_scan");
    var found = [], version = "-";
    for (var pi = 0; pi < PATHS.length; pi++) {
      var path = PATHS[pi];
      var bytes = [];
      for (var ci = 0; ci < path.length; ci++) bytes.push(path.charCodeAt(ci) & 255);
      bytes.push(0);
      poke(BUF, bytes);
      var oRes = n.call("open", [BUF, 0, 0]);
      if (isErr(oRes) || oRes.value < 0) { found.push("no"); continue; }
      var fd = oRes.value;
      found.push("v" + fd);
      if (pi === 0) {
        var rRes = n.call("read", [fd, RBUF, 63]);
        if (!isErr(rRes) && rRes.value > 0) {
          var rb = peek(RBUF, Math.min(rRes.value, 63));
          var text = "";
          for (var ri = 0; ri < rb.length; ri++) {
            var c = rb[ri];
            if (c >= 32 && c < 127) text += String.fromCharCode(c);
            else if (c === 10 || c === 13) text += "|";
          }
          version = text.slice(0, 60);
        }
      }
      n.call("close", [fd]);
    }

    phase = "outcome";
    var post = n.call("getpid", []);
    var intact = post.value === pid && post.high === 0 &&
      state.array[0] === state.a &&
      bytesAt(carrierSlot, 8).join(",") === carrierOriginal.join(",");
    var any = found.join(",").indexOf("v") >= 0;
    return [{
      id: "stage_hen_verify_v1",
      status: any && intact ? "pass" : "fail",
      details: {
        pid: pid, uid: "v0", paths: PATHS.join(";"),
        fds: found.join(","), version: version,
        state: any ? "hen_files" : "no_hen_files", intact: intact,
        phase: phase
      }
    }];
  } catch (error) {
    return fail(error);
  }
})();
