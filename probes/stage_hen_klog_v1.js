// Stage HEN klog v1: drain /dev/klog after a HEN install and keep the
// interesting lines.
//
// The kpayload prints "Hello from KPayload: 1400" when it starts, and the
// 594 hook prints "TITLEID init env 0x... plugin load 0x..." for the
// SceShellUI/ScePartyDaemon branch. The installer prints its stage messages
// through printf_debug. All of that lands in the kernel log, which is
// readable from the browser process once HEN's jailbreak() has made it root.
//
// Userland only: no kernel primitive is needed, so this runs after
// stage_safedown_v1. It writes the whole log to /data/hen/fw14_klog.txt and
// returns the filtered tail plus a marker summary (detail strings are capped
// at 512 bytes by the harness).
var SCRATCH = 0x940900000;
var BUF = SCRATCH + 0x500, RBUF = SCRATCH + 0x600;
var LOGPATH = "/data/hen/fw14_klog.txt";
var O_RDONLY = 0, O_NONBLOCK = 0x4;
var O_WRONLY = 1, O_CREAT = 0x200, O_TRUNC = 0x400;
var phase = "preflight";
var KEYS = ["kpayload", "init env", "plugin", "mono", "hen", "libc",
            "sceshellui", "shellui", "dynlib", "syscall", "install",
            "patch", "error", "fail", "bootloader", "loader", "prx"];

function fail(message) {
  return [{ id: "stage_hen_klog_v1", status: "error",
            details: { phase: phase, error: String(message).slice(0, 220) } }];
}

return (async function () {
  try {
    var n = window.__fw14NativeInvoke;
    var state = window.__fw14ArrayState;
    if (!n || !n.frame || !n.wrappers || !Number.isSafeInteger(n.frameAddress) ||
        !state || state.array[0] !== state.a || !state.view ||
        !state.ownedTypedView || !Number.isSafeInteger(state.calibratedViewBase) ||
        !Number.isInteger(state.index))
      throw new Error("caller_missing");

    var forged = state.view;
    var carrier = state.ownedTypedView;
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
      for (var i = 0; i < 8; i++)
        forged[carrierSlot + i] = carrierOriginal[i];
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
    function cstring(t) {
      var out = [];
      for (var i = 0; i < t.length; i++) out.push(t.charCodeAt(i) & 255);
      out.push(0);
      return out;
    }
    function putString(addr, t) { poke(addr, cstring(t)); }
    function toText(bytes) {
      var out = "";
      for (var i = 0; i < bytes.length; i++) {
        var c = bytes[i] & 255;
        out += (c === 10 || c === 13 || (c >= 32 && c < 127)) ?
          String.fromCharCode(c) : ".";
      }
      return out;
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
      var fd = o.value, off = 0, wtag = "-";
      while (off < bytes.length) {
        var take = Math.min(4096, bytes.length - off);
        poke(RBUF, bytes.slice(off, off + take));
        var w = n.call("write", [fd, RBUF, take]);
        wtag = eTag(w);
        if (isErr(w) || w.value <= 0) break;
        off += w.value;
      }
      n.call("close", [fd]);
      return "fd" + fd + "/" + wtag + "/" + off;
    }

    phase = "drain";
    var got = drainRaw();
    var text = toText(got.bytes);

    phase = "filter";
    var lines = text.split("\n");
    var kept = [], counts = {};
    for (var li = 0; li < lines.length; li++) {
      var line = lines[li];
      if (!line) continue;
      var low = line.toLowerCase();
      var hit = false;
      for (var ki = 0; ki < KEYS.length; ki++)
        if (low.indexOf(KEYS[ki]) >= 0) { hit = true; break; }
      if (!hit) continue;
      kept.push(line);
      for (var kj = 0; kj < KEYS.length; kj++) {
        if (low.indexOf(KEYS[kj]) >= 0)
          counts[KEYS[kj]] = (counts[KEYS[kj]] || 0) + 1;
      }
    }
    var joined = kept.join("\n");
    var hits = [];
    for (var kk = 0; kk < KEYS.length; kk++)
      if (counts[KEYS[kk]]) hits.push(KEYS[kk] + ":" + counts[KEYS[kk]]);

    phase = "write";
    var fileTag = writeFile(LOGPATH, got.bytes);

    phase = "outcome";
    var post = n.call("getpid", []);
    var intact = post.value > 0 && post.high === 0;
    return [{
      id: "stage_hen_klog_v1",
      status: got.bytes.length ? "pass" : "fail",
      details: {
        read: got.tag,
        lines: lines.length,
        kept: kept.length,
        hits: hits.join(",").slice(0, 240),
        file: fileTag,
        tail: joined.slice(-430),
        intact: intact
      }
    }];
  } catch (error) {
    return fail(error);
  }
})();
