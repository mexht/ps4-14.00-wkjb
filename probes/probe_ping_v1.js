// Probe ping v1: the cheapest possible round trip.
//
// Used as a settle checkpoint: it touches nothing but getpid and the frame,
// so if the console powers off while this is the only thing running, the
// cause is not this probe.
var result;
try {
  var n = window.__fw14NativeInvoke;
  if (!n || !n.frame || !n.wrappers || !Number.isSafeInteger(n.frameAddress))
    throw new Error("caller_missing");
  var pidRes = n.call("getpid", []);
  var ok = pidRes.high === 0 && pidRes.value > 0 && pidRes.value < 100000;
  result = {
    id: "probe_ping_v1",
    status: ok ? "pass" : "fail",
    details: {
      pid: pidRes.value,
      high: pidRes.high,
      state: ok ? "alive" : "bad_pid",
      stage_c: window.__fw14StageC ? "yes" : "no",
      stage_f: window.__fw14StageF ? "yes" : "no",
      jit: window.__fw14StageJit ? "yes" : "no"
    }
  };
} catch (e) {
  result = {
    id: "probe_ping_v1",
    status: "error",
    details: { error: String(e).slice(0, 220) }
  };
}
return [result];
