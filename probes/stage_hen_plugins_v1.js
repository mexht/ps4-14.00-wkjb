// Stage hen plugins v1: stop plugin_mono from loading into game processes.
//
// The 14.00 crash on launch is caused by plugin_mono being listed under [all]
// in /data/hen/plugins.ini. HEN's plugin_loader reads that file at process
// start and injects every enabled entry into the new game process; a game
// that also uses Mono dies right after plugin_load. HEN Settings is NOT
// affected: its menu comes from the kpayload's 594 hook, which injects
// plugin_mono into SceShellUI directly and does not consult plugins.ini.
//
// This probe rewrites only the value of lines that mention plugin_mono.prx
// (any section, not just [all]), preserving every other byte of the file.
// `1` becomes `0`, so the file length and all comments/entries survive. It
// keeps a one-time copy at /data/hen/plugins.ini.pre14.bak before the first
// change.
//
// Userland only; uid 0 + prison escaped. Nothing is launched.
var SCRATCH = 0x940900000;
var BUF = SCRATCH + 0x400;
var RBUF = SCRATCH + 0x600;
var SYM = SCRATCH + 0x800;
var OUT = SCRATCH + 0x900;
var NAME = SCRATCH + 0x1800;
var PLUGINS = "/data/hen/plugins.ini";
var BACKUP = "/data/hen/plugins.ini.pre14.bak";
var O_RDONLY = 0, O_WRONLY = 1, O_CREAT = 0x200, O_TRUNC = 0x400;
var MAX = 262144;

var state = window.__fw14ArrayState;
var phase = "preflight";
function fail(message) {
  return [{ id: "hen_plugins_v1", status: "error",
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
    function putString(addr, t) {
      var bytes = [];
      for (var i = 0; i < t.length; i++) bytes.push(t.charCodeAt(i) & 255);
      bytes.push(0);
      poke(addr, bytes);
    }

    function readFile(path) {
      putString(BUF, path);
      var o = n.call("open", [BUF, O_RDONLY, 0]);
      if (isErr(o) || o.value < 0) return { tag: "open" + eTag(o), bytes: null };
      var fd = o.value, all = [], total = 0, rtag = "-";
      while (total < MAX) {
        var r = n.call("read", [fd, RBUF, 4096]);
        rtag = eTag(r);
        if (isErr(r) || r.value <= 0) break;
        var chunk = peek(RBUF, r.value);
        for (var k = 0; k < chunk.length; k++) all.push(chunk[k]);
        total += r.value;
      }
      n.call("close", [fd]);
      if (isErr(r) && total === 0) return { tag: "read" + rtag, bytes: null };
      return { tag: "fd" + fd + "/" + total, bytes: all };
    }
    function writeFile(path, bytes, append) {
      putString(BUF, path);
      var flags = O_WRONLY | O_CREAT | (append ? 0x8 : O_TRUNC);
      var o = n.call("open", [BUF, flags, 420]);
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

    // ------------------------------------------------ read plugins.ini
    phase = "read";
    var got = readFile(PLUGINS);
    if (!got.bytes) {
      return [{ id: "hen_plugins_v1", status: "pass",
                details: { state: "missing", tag: got.tag,
                           path: PLUGINS } }];
    }
    var src = got.bytes;

    // ------------------------------------------------ rewrite plugin_mono
    // Work on bytes, line by line. A line is changed only if it names
    // plugin_mono.prx and has an '=' after the name. The value token after
    // '=' is replaced with a single '0'; whitespace and a trailing comment
    // are kept as they were.
    phase = "rewrite";
    var out = [], changed = [], lineStart = 0, lineNo = 0, section = "";
    function flushLine(end) {           // end is index of '\n' or src.length
      var line = src.slice(lineStart, end);
      var text = "";
      for (var i = 0; i < line.length; i++) text += String.fromCharCode(line[i]);
      var trimmed = text.trim();
      if (trimmed.charAt(0) === "[" && trimmed.indexOf("]") > 1)
        section = trimmed.slice(1, trimmed.indexOf("]"));
      var eq = -1;
      if (trimmed.charAt(0) !== ";" && trimmed.charAt(0) !== "#" &&
          text.indexOf("plugin_mono.prx") >= 0)
        eq = text.indexOf("=", text.indexOf("plugin_mono.prx"));
      if (eq < 0) {
        for (var j = 0; j < line.length; j++) out.push(line[j]);
        return;
      }
      // Keep everything up to and including '=', then one '0', then the
      // rest of the line (trailing spaces, CR, comment, ...).
      var k = eq + 1;
      while (k < text.length && text.charAt(k) === " ") k++;
      var tokenStart = k;
      while (k < text.length && " \t\r,;#".indexOf(text.charAt(k)) < 0) k++;
      var token = text.slice(tokenStart, k);
      for (var m = 0; m < tokenStart; m++) out.push(line[m]);
      out.push(48);                      // '0'
      for (; k < line.length; k++) out.push(line[k]);
      if (token !== "0") changed.push(section + ":" + lineNo + ":" + token);
    }
    for (var i = 0; i < src.length; i++) {
      if (src[i] === 10) {
        flushLine(i);
        out.push(10);
        lineStart = i + 1;
        lineNo++;
      }
    }
    flushLine(src.length);

    if (changed.length === 0) {
      return [{ id: "hen_plugins_v1", status: "pass",
                details: { state: "already", bytes: src.length,
                           path: PLUGINS } }];
    }

    // ------------------------------------------------ one-time backup
    phase = "backup";
    var existing = readFile(BACKUP);
    var backupTag = "kept";
    if (!existing.bytes) {
      backupTag = writeFile(BACKUP, src, false);
      if (backupTag.charAt(0) !== "o") backupTag = "fail:" + backupTag;
    }

    // ------------------------------------------------ write it back
    phase = "write";
    var tag = writeFile(PLUGINS, out, false);
    if (tag.charAt(0) !== "o")
      throw new Error("write_" + tag);

    return [{ id: "hen_plugins_v1", status: "pass",
              details: { state: "patched", changes: changed.join(","),
                         bytes: out.length, backup: backupTag,
                         path: PLUGINS } }];
  } catch (error) {
    return fail(error && error.message ? error.message : error);
  }
})();
