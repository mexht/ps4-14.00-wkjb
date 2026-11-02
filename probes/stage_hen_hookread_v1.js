// Stage HEN hookread v1: is sysent[594] hooked after HEN installs?
//
// HEN's kpayload installs custom syscalls 107/108/109 and (only if the
// dynlib symbols resolve) replaces sysent[594] with sys_dynlib_load_prx_hook.
// The plugin system depends on that hook: it is what loads
// plugin_bootloader/prx into a process that loads /app0/sce_module/libc.prx
// and plugin_mono.prx into SceShellUI when it loads libSceSysmodule.sprx.
//
// This probe reads the four sysent entries with the still-live kqueue ROP
// primitive (the fake filterops slot must NOT be restored yet), stores the
// stock values in window.__fw14HenHook on the first run, and reports what
// changed on later runs. It also reads 16 bytes at the new sy_call and
// compares them with the hook prologue from the reviewed kpayload blob.
//
// Run it twice in the same boot: once BEFORE stage_hen_diag_v1 (baseline)
// and once AFTER (HEN installed, ShellUI left running). It must be followed
// by stage_safedown_v1, which is still the last ROP action of the boot.
var result, n, f, dv, saved, phase = "preflight";
var st = null, fake = 0, ops = 0, gSTACK = 0, gRES = 0, gMARK = 0, gCTX = 0;
var gDUMP = 0;
var forged = null, carrier = null, carrierSlot = -1, carrierOriginal = null;
var KBASE_LO = 0;
var R_SLOT = 0x1a312b0, R_OPS = 0x152a108;
var R_RET0 = 0x349ee, R_TOUCH = 0x73e886;
var R_POPRSP = 0x1c9dc, R_SAVE = 0x2be040, R_REST = 0x2be070;
var R_CONT = 0xe4f40, R_PRAX = 0x1ca05, R_PRDX = 0x184ab2;
var R_PRDI = 0x3b0a2a, R_LDRAX = 0x6aaf3, R_ADDRAX = 0x3fc327;
var R_STRAXRDX = 0x2e3d59, R_STRDIRAX = 0x2f1cb;
var Z8 = [0, 0, 0, 0, 0, 0, 0, 0];
var MARK = [49, 74, 84, 79, 79, 82, 77, 77];
var GIDENT = [49, 90, 84, 82, 80, 75, 52, 49];
var M120 = [136, 255, 255, 255, 255, 255, 255, 255];
// FreeBSD/PS4 14.00: sysent base and stride (same table stage_patch_v1 uses).
var SYSENT = 0x1102b70, STRIDE = 0x30;
var IDX = [594, 107, 108, 109];
// First 16 bytes of sys_dynlib_load_prx_hook in the reviewed kpayload blob
// (kpayload.bin + 0x340).
var PROLOGUE = [0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54,
                0x55, 0x48, 0x89, 0xf5, 0x53, 0x48, 0x89, 0xfb];
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
  var need = ["kevent", "kqueue", "close", "getpid"];
  var missing = [];
  for (var mi = 0; mi < need.length; mi++)
    if (typeof n.wrappers[need[mi]] !== "number") missing.push(need[mi]);
  if (missing.length) throw new Error("wrappers_missing:" + missing.join(","));
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
  function isBytes(v) { return v && typeof v === "object" && v.length === 8; }
  function isErr(r) {
    return !!r && r.value === -1 && (r.high >>> 0) === 0xffffffff;
  }
  function eTag(r) {
    if (!isErr(r)) return "v" + r.value;
    var e = n.readErrno();
    return "e" + (e === null ? r.value : e);
  }
  function hexQ(bytes) {
    var out = "";
    for (var i = 7; i >= 0; i--)
      out += ("0" + (bytes[i] & 255).toString(16)).slice(-2);
    return out;
  }
  function hexN(bytes) {
    var out = "";
    for (var i = 0; i < bytes.length; i++)
      out += ("0" + (bytes[i] & 255).toString(16)).slice(-2);
    return out;
  }

  var pidRes = n.call("getpid", []);
  if (pidRes.high !== 0 || pidRes.value < 1 || pidRes.value > 100000)
    throw new Error("pid_invalid");
  var pid = pidRes.value;

  // Re-install the fake filterops (the F stage values) so this probe does not
  // depend on whatever the previous stage left in the struct.
  phase = "ops";
  poke(ops, Z8);
  poke(ops + 8, kq(R_RET0));
  poke(ops + 16, kq(R_RET0));
  poke(ops + 24, kq(R_RET0));
  poke(ops + 32, kq(R_TOUCH));

  phase = "kqueue";
  var kqRes = n.call("kqueue", []);
  if (kqRes.value < 0) throw new Error("kqueue" + eTag(kqRes));
  var kqFd = kqRes.value;

  f.fill(0, 0x900, 0x940);
  for (var gi = 0; gi < 8; gi++) f[0x900 + gi] = GIDENT[gi];
  dv.setInt16(0x908, -23, true);
  dv.setUint16(0x90a, 1, true);
  phase = "initial_add";
  var addRes = n.call("kevent",
    [kqFd, n.frameAddress + 0x900, 1, 0, 0, 0]);

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
    poke(gMARK, Z8);
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
    return { rc: rc, mark: same(peekQ(gMARK), MARK), qwords: chain.qwords };
  }
  function readStep(emit, emitU, src, dst) {
    emit(kq(R_PRAX)); emitU(src);
    emit(kq(R_LDRAX)); emitU(0);
    emit(kq(R_PRDI)); emitU(dst);
    emit(kq(R_STRDIRAX)); emitU(0);
  }

  // ------------------------------------------- 1. prove the hook is live
  phase = "probe";
  var mRes = fire(makeChain(function () {}));
  var live = mRes.mark;

  // ------------------------------------------- 2. read sysent entries
  // sy_narg at +0, sy_call at +8, stride 0x30 (see kpayload/include/hooks.h).
  var calls = [], nargs = [], hooked = false;
  if (live) {
    phase = "read_sysent";
    var rRes = fire(makeChain(function (emit, emitU) {
      for (var i = 0; i < IDX.length; i++) {
        var ent = kq(SYSENT + IDX[i] * STRIDE);
        readStep(emit, emitU, ent, gDUMP + i * 8);
        readStep(emit, emitU, kq(SYSENT + IDX[i] * STRIDE + 8),
                 gDUMP + 0x40 + i * 8);
      }
    }));
    if (!rRes.mark) throw new Error("read_chain_dead");
    for (var ci = 0; ci < IDX.length; ci++) {
      nargs.push(valueOf(peek(gDUMP + ci * 8, 8)) >>> 0);
      calls.push(hexQ(peek(gDUMP + 0x40 + ci * 8, 8)));
    }
  }

  // ------------------------------------------- 3. 16 bytes at sy_call[594]
  var prologue = "", prologueMatch = false;
  if (live && calls.length === 4) {
    phase = "read_prologue";
    // sy_call is a kernel address (0xffffffff8...), which a JS number cannot
    // hold exactly. Keep it as the 8 raw bytes and add 8 byte-wise.
    var callBytes = peek(gDUMP + 0x40, 8);
    var plus8 = callBytes.slice();
    var carry = 8;
    for (var bi3 = 0; bi3 < 8 && carry; bi3++) {
      var vv = plus8[bi3] + carry;
      plus8[bi3] = vv & 255;
      carry = vv >> 8;
    }
    var pRes = fire(makeChain(function (emit, emitU) {
      readStep(emit, emitU, callBytes, gDUMP + 0x80);
      readStep(emit, emitU, plus8, gDUMP + 0x88);
    }));
    if (pRes.mark) {
      prologue = hexN(peek(gDUMP + 0x80, 16));
      prologueMatch = same(peek(gDUMP + 0x80, 16), PROLOGUE);
    }
  }

  // ------------------------------------------- 4. cleanup
  phase = "cleanup";
  f.fill(0, 0x900, 0x940);
  for (var di = 0; di < 8; di++) f[0x900 + di] = GIDENT[di];
  dv.setInt16(0x908, -23, true);
  dv.setUint16(0x90a, 2, true);       // EV_DELETE
  var delTag = eTag(n.call("kevent",
    [kqFd, n.frameAddress + 0x900, 1, 0, 0, 0]));
  var closeTag = eTag(n.call("close", [kqFd]));

  // ------------------------------------------------------- outcome
  phase = "outcome";
  for (var ri = 0; ri < saved.length; ri++) f[0x200 + ri] = saved[ri];
  saved = null;
  var post = n.call("getpid", []);
  var intact = post.value === pid && post.high === 0 &&
    state.array[0] === state.a &&
    bytesAt(carrierSlot, 8).join(",") === carrierOriginal.join(",");

  var baseline = window.__fw14HenHook || null;
  var firstRun = !baseline;
  var changed = [], sameTag = "n/a";
  if (baseline) {
    for (var bi2 = 0; bi2 < IDX.length; bi2++)
      if (baseline.calls[bi2] !== calls[bi2]) changed.push(IDX[bi2]);
    hooked = calls[0] !== baseline.calls[0];
    sameTag = changed.length ? changed.join(",") : "none";
  }
  if (firstRun && live)
    window.__fw14HenHook = {
      calls: calls.slice(), nargs: nargs.slice(), prologue: prologue,
      kbaseLo: KBASE_LO, pid: pid
    };
  if (baseline)
    window.__fw14HenHook.after = {
      calls: calls.slice(), nargs: nargs.slice(), prologue: prologue,
      changed: sameTag, hooked: hooked
    };

  var stateTag = !live ? "dead" : (firstRun ? "baseline" :
                 (hooked ? "hooked" : "stock"));
  result = {
    id: "stage_hen_hookread_v1",
    status: live && intact ? "pass" : "fail",
    details: {
      pid: pid,
      state: stateTag,
      s594: calls[0] || "-",
      s107: calls[1] || "-",
      s108: calls[2] || "-",
      s109: calls[3] || "-",
      narg: nargs.join("/"),
      changed: firstRun ? "first" : sameTag,
      prologue: prologueMatch ? "match" : (prologue || "-"),
      cleanup: eTag(addRes) + "/" + delTag + "/" + closeTag,
      intact: intact
    }
  };
} catch (e) {
  result = {
    id: "stage_hen_hookread_v1",
    status: "error",
    details: { phase: phase, error: String(e).slice(0, 220) }
  };
} finally {
  try { if (forged && carrierSlot >= 0 && carrierOriginal)
    for (var ci2 = 0; ci2 < 8; ci2++)
      forged[carrierSlot + ci2] = carrierOriginal[ci2]; } catch (ignore) {}
  if (f && saved)
    for (var fi = 0; fi < saved.length; fi++) f[0x200 + fi] = saved[fi];
}
return [result];
