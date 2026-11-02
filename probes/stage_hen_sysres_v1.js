// Stage HEN sysres v1: can the page reach HEN's custom syscalls (107/108/109)?
//
// The native-invoke install locates fixed syscall wrapper stubs in
// libkernel_web by matching their 16-byte prologue. There are no stubs for
// 107/108/109 (they are not real PS4 syscalls; HEN's kpayload installs them
// into sysent at runtime), so the post-HEN probes need an entry point of
// their own.
//
// Method A (primary) is a byte-for-byte copy of a real libkernel wrapper in
// the stage_jit_v1 RWX page:
//
//   b8 <num> 00 00 00   mov eax, num
//   49 89 ca            mov r10, rcx     <- the wrapper's arg4 move
//   0f 05               syscall
//   c3                  ret
//
// The `mov r10, rcx` is NOT optional: the x86-64 `syscall` instruction
// clobbers rcx, so the kernel ABI takes the fourth argument in r10. The
// real wrappers carry exactly this instruction (48 c7 c0 <num> 00 00 00
// 49 89 ca 0f 05 72 01 c3 48), which is the pattern the install probe
// matches. Dropping it made 5-argument syscall 108 pass a garbage length.
//
// Method B (fallback) is dlsym(0x2001, "syscall"). It is only tried when
// method A fails, because calling an export whose ABI we have not verified
// is the riskier of the two.
//
// Both are validated with syscall 20 (getpid), which must return this
// process's pid, then 107 once HEN is installed. api.markSync markers
// bracket every risky call so a power-off still localises the culprit.
var SCRATCH = 0x940900000;
var SYM = SCRATCH + 0x800, OUT = SCRATCH + 0x880;
var phase = "preflight";

function fail(message) {
  return [{ id: "stage_hen_sysres_v1", status: "error",
            details: { phase: phase, error: String(message).slice(0, 220) } }];
}

return (async function () {
  try {
    var n = window.__fw14NativeInvoke;
    var state = window.__fw14ArrayState;
    if (!n || !n.frame || !n.wrappers || !state || state.array[0] !== state.a ||
        !state.view || !state.ownedTypedView ||
        !Number.isSafeInteger(state.calibratedViewBase) ||
        !Number.isInteger(state.index))
      throw new Error("caller_missing");
    if (typeof n.callAddr !== "function") throw new Error("calladdr_missing");

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
      } finally { state.array[0] = state.a; }
    }
    var carrierSlot = addressOf(carrier) - base + 8;
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
    function cstring(t) {
      var out = [];
      for (var i = 0; i < t.length; i++) out.push(t.charCodeAt(i) & 255);
      out.push(0);
      return out;
    }
    function putString(addr, t) { poke(addr, cstring(t)); }
    function isErr(r) {
      return !!r && r.value === -1 && (r.high >>> 0) === 0xffffffff;
    }
    function eTag(r) {
      if (!isErr(r)) return "v" + r.value;
      var e = n.readErrno();
      return "e" + (e === null ? r.value : e);
    }
    function hex(v) { return "0x" + Math.floor(v).toString(16); }
    function mark(m) {
      try {
        if (typeof api !== "undefined" && api && typeof api.markSync === "function")
          api.markSync(m);
      } catch (ignore) {}
    }
    function resolve(handle, name) {
      putString(SYM, name);
      poke(OUT, [0, 0, 0, 0, 0, 0, 0, 0]);
      var r = n.call("dynlib_dlsym", [handle, SYM, OUT]);
      if (isErr(r) || r.value !== 0) return 0;
      var got = valueOf(peek(OUT, 8));
      return (got > 0xffffffff && got < 0x1000000000000) ? got : 0;
    }
    function stubBytes(num) {
      return [0xb8, num & 255, (num >>> 8) & 255, (num >>> 16) & 255,
              (num >>> 24) & 255, 0x49, 0x89, 0xca, 0x0f, 0x05, 0xc3];
    }

    var pidRes = n.call("getpid", []);
    var pid = pidRes.value;

    // ------------------------------------------- A. JIT syscall stub
    phase = "stub";
    mark("sr_start");
    var jit = window.__fw14StageJit;
    var jitAddr = (jit && typeof jit.addr === "number") ? jit.addr : 0;
    var stubAddr = 0, stubTag = "-", stubOk = false, stubPid = 0, stubHex = "";
    if (jitAddr) {
      stubAddr = jitAddr + 0x100;
      poke(stubAddr, stubBytes(20));
      stubHex = peek(stubAddr, 11).join(",");
      mark("sr_stub_pre");
      var s = n.callAddr(stubAddr, []);
      mark("sr_stub_post");
      stubTag = eTag(s);
      stubPid = s.value;
      stubOk = !isErr(s) && s.high === 0 && s.value === pid;
    }

    // ------------------------------------------- B. dlsym("syscall")
    // Only when the stub failed: this export's ABI is unverified.
    phase = "dlsym";
    var sysAddr = 0, dlsymTag = "-", dlsymOk = false, dlsymPid = 0;
    if (!stubOk) {
      mark("sr_dlsym_pre");
      sysAddr = resolve(0x2001, "syscall");
      if (sysAddr) {
        var r = n.callAddr(sysAddr, [[20, 0]]);
        dlsymTag = eTag(r);
        dlsymPid = r.value;
        dlsymOk = !isErr(r) && r.high === 0 && r.value === pid;
      }
      mark("sr_dlsym_post");
    }

    // ------------------------------------------- C. pthread naming symbols
    phase = "names";
    var names = ["scePthreadRename", "pthread_setname_np", "scePthreadSelf",
                 "pthread_self", "scePthreadGetname"];
    var addrs = {};
    for (var i = 0; i < names.length; i++) addrs[names[i]] = resolve(0x2001, names[i]);

    // ------------------------------------------- D. HEN syscalls, if live
    // The HEN liveness call is deliberately NOT made here. syscall 107 in
    // count mode (procs = 0) is the call that powered the console off on
    // boot 47, and this probe has no way to survive it: stage_hen_proc_v1
    // is the bisect that tests 108/107/109 one call at a time with durable
    // marks. Reporting whether the hook flag is set is enough here.
    phase = "hen_call";
    var henState = window.__fw14HenHook ? "hooked_deferred" : "no_hook";
    var henNum = 0, henTag = "-";

    // ------------------------------------------- outcome
    phase = "outcome";
    var method = stubOk ? "stub" : (dlsymOk ? "dlsym" : "none");
    var found = [];
    for (var ni = 0; ni < names.length; ni++)
      if (addrs[names[ni]]) found.push(names[ni]);
    var rename = addrs["scePthreadRename"] || addrs["pthread_setname_np"] || 0;
    window.__fw14HenSysRes = {
      syscall: sysAddr, stub: stubAddr, method: method, pid: pid
    };
    mark("sr_done");
    return [{
      id: "stage_hen_sysres_v1",
      status: (stubOk || dlsymOk) ? "pass" : "fail",
      details: {
        pid: pid,
        stub: stubAddr ? hex(stubAddr) : "no_jit",
        stub_bytes: stubHex,
        stub_call: stubTag + "/" + stubPid,
        dlsym: sysAddr ? hex(sysAddr) : "missing",
        dlsym_call: dlsymTag + "/" + dlsymPid,
        method: method,
        hen: henState + "/" + henNum + "/" + henTag,
        symbols: found.join(",").slice(0, 200),
        rename: rename ? hex(rename) : "missing"
      }
    }];
  } catch (error) {
    return fail(error);
  }
})();
