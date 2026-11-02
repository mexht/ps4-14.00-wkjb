// Stage hen prxensure v1: make the /data/hen plugin PRXs loadable again.
//
// Root cause of the missing HEN Settings menu (14.00, 2026-11-02): the file
// instance at /data/hen/plugin_mono.prx was rejected by sys_dynlib_load_prx
// with EACCES even though a byte-identical copy under /data/self/ loaded
// fine. HEN's 594 hook therefore got handle 0 from its internal load,
// plugin_load resolved to 0, _init_env was never patched, and the plugin never
// ran. Replacing the *file instance* (unlink + recreate with the same bytes)
// fixed it, and the menu appeared after the next ShellUI restart.
//
// The other four PRXs are loaded by the same mechanism (bootloader from the
// libc branch, loader from the bootloader, server/mono from the Sysmodule
// branch, shellcore from the ShellCore cave), so this probe repairs all five.
//
// For each file:
//   1. load-test /data/hen/<name>.prx,
//   2. if it loads, leave it,
//   3. otherwise stage the bytes at /data/self/<name>.prx on a fresh inode and
//      load-test there (that path accepted the bytes while /data/hen was
//      rejected),
//   4. if the staged copy loads, unlink the /data/hen file, copy the staged
//      bytes back, and load-test again.
//
// Userland only; uid 0 + prison escaped. Raw sys594 loads a PRX without
// starting the module, so loading the other plugins has no side effects.
var SCRATCH = 0x940900000;
var BUF = SCRATCH + 0x400;
var RB = SCRATCH + 0x500;
var PATH = SCRATCH + 0x1500;
var DSTBUF = SCRATCH + 0x1600;
var HANDLE = SCRATCH + 0x1700;
var SYM = SCRATCH + 0x1740;
var OUT = SCRATCH + 0x1780;
var NAMES = ["plugin_bootloader", "plugin_loader", "plugin_server",
             "plugin_mono", "plugin_shellcore"];
var O_RDONLY = 0, O_WRONLY = 1, O_CREAT = 0x200, O_TRUNC = 0x400;

var state = window.__fw14ArrayState;
var phase = "preflight";
function fail(message) {
  return [{ id: "hen_prxensure_v1", status: "error",
            details: { phase: phase, error: String(message).slice(0, 220) } }];
}
return (async function () {
  try {
    var n = window.__fw14NativeInvoke;
    if (!n || !n.frame || !n.wrappers || !state || state.array[0] !== state.a ||
        !state.view || !state.ownedTypedView ||
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
    function sym(name) {
      putString(SYM, name);
      poke(OUT, [0, 0, 0, 0, 0, 0, 0, 0]);
      var r = n.call("dynlib_dlsym", [0x2001, SYM, OUT]);
      var a = (!isErr(r) && r.value === 0) ? valueOf(peek(OUT, 8)) : 0;
      return (Number.isSafeInteger(a) && a >= 0x100000000) ? a : 0;
    }
    var unlinkAddr = sym("unlink");
    if (!unlinkAddr) throw new Error("no_unlink");

    function unlink(path) {
      putString(PATH, path);
      return n.callAddr(unlinkAddr, [pair(PATH)]);
    }
    function copy(src, dst) {
      putString(BUF, src);
      var so = n.call("open", [BUF, O_RDONLY, 0]);
      if (isErr(so) || so.value < 0) return "src/" + n.readErrno();
      var sfd = so.value;
      putString(DSTBUF, dst);
      var doo = n.call("open", [DSTBUF, O_WRONLY | O_CREAT | O_TRUNC, 511]);
      if (isErr(doo) || doo.value < 0) {
        n.call("close", [sfd]);
        return "dst/" + n.readErrno();
      }
      var dfd = doo.value, total = 0;
      for (var i = 0; i < 128; i++) {
        var rr = n.call("read", [sfd, RB, 4096]);
        if (isErr(rr) || rr.value <= 0) break;
        var left = rr.value, off = 0;
        while (left > 0) {
          var ww = n.call("write", [dfd, RB + off, left]);
          if (isErr(ww) || ww.value <= 0) {
            n.call("close", [sfd]); n.call("close", [dfd]);
            return "write/" + n.readErrno();
          }
          left -= ww.value;
          off += ww.value;
        }
        total += rr.value;
        if (total > 2097152) break;
      }
      n.call("close", [sfd]);
      n.call("close", [dfd]);
      return "v" + total;
    }
    function load(path) {
      putString(BUF, path);
      poke(HANDLE, [0, 0, 0, 0, 0, 0, 0, 0]);
      var r = n.call("sys594", [BUF, 0, HANDLE]);
      var h = valueOf(peek(HANDLE, 4)) >>> 0;
      var pl = "-";
      if (h) {
        putString(SYM, "plugin_load");
        poke(OUT, [0, 0, 0, 0, 0, 0, 0, 0]);
        var d = n.call("dynlib_dlsym", [h, SYM, OUT]);
        var got = (!isErr(d) && d.value === 0) ? valueOf(peek(OUT, 8)) : 0;
        pl = got ? "0x" + got.toString(16) : "no";
      }
      return { tag: eTag(r), handle: h, plugin_load: pl };
    }

    phase = "run";
    var ok = 0, repaired = 0, failed = 0, missing = 0;
    var summary = [], monoPointer = "-";
    for (var i = 0; i < NAMES.length; i++) {
      var name = NAMES[i];
      var hen = "/data/hen/" + name + ".prx";
      var self = "/data/self/" + name + ".prx";
      var before = load(hen);
      if (before.handle) {
        ok++;
        if (name === "plugin_mono") monoPointer = before.plugin_load;
        summary.push(name + ":ok");
        continue;
      }
      // A missing /data/hen file cannot be staged from itself.
      unlink(self);
      var staged = copy(hen, self);
      if (staged.indexOf("v") !== 0) {
        missing++;
        summary.push(name + ":missing");
        continue;
      }
      var selfLoad = load(self);
      if (!selfLoad.handle) {
        failed++;
        summary.push(name + ":bad");
        continue;
      }
      unlink(hen);
      var back = copy(self, hen);
      var after = load(hen);
      if (after.handle) {
        repaired++;
        if (name === "plugin_mono") monoPointer = after.plugin_load;
        summary.push(name + ":fixed");
      } else {
        failed++;
        summary.push(name + ":fail");
      }
    }

    phase = "outcome";
    var out = {
      state: failed ? "failed" : (repaired ? "repaired" :
              (missing ? "partial" : "unchanged")),
      ok: ok, repaired: repaired, failed: failed, missing: missing,
      files: summary.join(",").slice(0, 300),
      plugin_load: monoPointer
    };
    var intact = n.call("getpid", []).value > 0 &&
      state.array[0] === state.a &&
      bytesAt(carrierSlot, 8).join(",") === carrierOriginal.join(",");
    out.intact = intact;
    return [{ id: "hen_prxensure_v1", status: intact ? "pass" : "fail",
              details: out }];
  } catch (error) {
    return fail(error);
  }
})();
