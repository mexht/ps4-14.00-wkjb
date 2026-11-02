// Stage HEN deps v1: which of hen.bin's imports can this process resolve?
//
// hen.bin's init calls syscall 594 (module handle by name) on
// libkernel.sprx / libkernel_web.sprx / libkernel_sys.sprx and then
// sceKernelDlsym (591) for every symbol below. Inside the WebProcess the
// handle is libkernel_web.sprx, which is a restricted variant: a symbol it
// does not export leaves a NULL import slot, and the first call through that
// slot jumps to 0. This probe resolves the same list read-only and reports
// the failures, so a launch crash can be attributed.
var SCRATCH = 0x940900000, NAME = SCRATCH + 0x600, OUT = SCRATCH + 0x700;
var LIBS = ["libkernel.sprx", "libkernel_web.sprx", "libkernel_sys.sprx"];
var KERN = ["__stack_chk_guard", "__stack_chk_fail", "__error", "sceKernelError", "sceKernelLoadStartModule", "sceKernelAllocateDirectMemory", "sceKernelMapDirectMemory", "sceKernelGetDirectMemorySize", "sceKernelStat", "sceKernelOpen", "sceKernelRead", "sceKernelLseek", "sceKernelClose", "sceKernelLwfsAllocateBlock", "sceKernelLwfsSetAttribute", "sceKernelLwfsTrimBlock", "sceKernelLwfsLseek", "sceKernelLwfsWrite", "sceKernelSleep", "sceKernelUsleep", "usleep", "sceKernelGettimeofday", "sceKernelGetProcessTime", "sceKernelGetCurrentCpu", "sysctl", "sysctlbyname", "sysarch", "execve", "pthread_self", "pthread_setaffinity_np", "sceKernelCreateEqueue", "sceKernelDeleteEqueue", "sceKernelAddUserEvent", "sceKernelAddReadEvent", "getuid", "getgid", "getpid", "setuid", "setgid", "setreuid", "setregid", "sceKernelSendNotificationRequest", "sceKernelGetFsSandboxRandomWord", "sceKernelGetSystemSwVersion", "sceKernelGetCpuTemperature", "sceKernelGetIdPs", "sceKernelGetOpenPsId", "sceKernelGetOpenPsIdForSystem"];
var LIBC = ["malloc", "free", "calloc", "realloc", "memalign", "memset", "memcpy", "memcmp", "memmove", "memmove_s", "strcpy", "strncpy", "strncpy_s", "strcat", "strncat", "strlen", "strcmp", "strcasecmp", "strncmp", "sprintf", "snprintf", "snprintf_s", "sscanf", "strtol", "strtok", "strchr", "strrchr", "strstr", "strdup", "rindex", "isspace", "isdigit", "isxdigit", "atoi", "atof", "strlcpy", "strerror", "_Getpctype", "_Stoul", "bcopy", "ceil", "tolower", "toupper", "srand", "asctime", "asctime_r", "gmtime", "gmtime_s", "localtime", "localtime_r", "mktime", "opendir", "readdir", "readdir_r", "telldir", "seekdir", "rewinddir", "closedir", "dirfd", "getprogname", "fopen", "fread", "fwrite", "fseek", "ftell", "fclose", "fprintf", "fgets"];
var phase = "preflight";

function fail(message) {
  return [{ id: "stage_hen_deps_v1", status: "error",
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
    var su = window.__fw14StageU;
    if (!su || su.uid !== 0) throw new Error("uid_missing");
    var need = ["sys594", "dynlib_dlsym", "getpid", "sys24"];
    for (var mi = 0; mi < need.length; mi++)
      if (typeof n.wrappers[need[mi]] !== "number")
        throw new Error("wrappers_missing_" + need[mi]);

    var forged = state.view, carrier = state.ownedTypedView;
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
      for (var i = 0; i < 8; i++) forged[carrierSlot + i] = carrierOriginal[i];
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
    function mark(m) {
      if (typeof api !== "undefined" && api && typeof api.markSync === "function")
        api.markSync(m);
    }
    function putString(text) {
      var out = [];
      for (var i = 0; i < text.length; i++) out.push(text.charCodeAt(i) & 255);
      out.push(0);
      poke(NAME, out);
    }
    function moduleHandle(name) {
      putString(name);
      poke(OUT, [0, 0, 0, 0, 0, 0, 0, 0]);
      var r = n.call("sys594", [NAME, 0, OUT, 0, 0, 0]);
      if (isErr(r) || r.value !== 0) return { tag: eTag(r), handle: 0 };
      var h = valueOf(peek(OUT, 8));
      return { tag: "v" + r.value, handle: (h < 0x1000000000000) ? h : 0 };
    }
    function missingFor(handle, names, into) {
      for (var i = 0; i < names.length; i++) {
        putString(names[i]);
        poke(OUT, [0, 0, 0, 0, 0, 0, 0, 0]);
        var r = n.call("dynlib_dlsym", [handle, NAME, OUT]);
        if (isErr(r) || r.value !== 0 || valueOf(peek(OUT, 8)) === 0)
          into.push(names[i]);
      }
    }

    var pid = n.call("getpid", []).value;
    phase = "handles";
    mark("hen_deps_handles");
    var tags = [], kHandle = 0, cHandle = 0;
    for (var li = 0; li < LIBS.length; li++) {
      var got = moduleHandle(LIBS[li]);
      tags.push(LIBS[li].replace(".sprx", "") + "=" + got.tag);
      if (got.handle !== 0 && kHandle === 0) kHandle = got.handle;
    }
    var libc = moduleHandle("libSceLibcInternal.sprx");
    tags.push("libc=" + libc.tag);
    if (libc.handle !== 0) cHandle = libc.handle;

    phase = "symbols";
    mark("hen_deps_symbols");
    var missing = [];
    if (kHandle !== 0) missingFor(kHandle, KERN, missing);
    if (cHandle !== 0) missingFor(cHandle, LIBC, missing);

    phase = "outcome";
    var post = n.call("getpid", []);
    var intact = post.value === pid && post.high === 0 &&
      state.array[0] === state.a &&
      bytesAt(carrierSlot, 8).join(",") === carrierOriginal.join(",");
    var list = missing.join(",");
    return [{
      id: "stage_hen_deps_v1",
      status: (kHandle !== 0 && intact) ? "pass" : "fail",
      details: {
        pid: pid, uid: "v0", handles: tags.join(";"),
        count: String(missing.length),
        missing: list.length > 460 ? list.slice(0, 460) + "..." : list,
        state: missing.length === 0 ? "all_resolved" : "missing_imports",
        intact: intact, phase: phase
      }
    }];
  } catch (error) {
    return fail(error);
  }
})();
