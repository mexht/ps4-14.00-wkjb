// Reload probe: report a pass, then reload the page so the next chain attempt
// starts in a fresh WebProcess. Used by the driver after a bad heap draw
// (storage/groom failure), where the kernel is still untouched and a reload is
// cheaper than a power cycle.
//
// The delay leaves time for the result POST to complete; the reload itself is
// what matters, so a lost result is harmless.
var result;
try {
  if (typeof location === "undefined" || !location ||
      typeof location.reload !== "function")
    throw new Error("no_location");
  setTimeout(function () { location.reload(); }, 2500);
  result = {
    id: "reload_v1",
    status: "pass",
    details: { scheduled_ms: 2500 }
  };
} catch (error) {
  result = {
    id: "reload_v1",
    status: "error",
    details: { error: String(error).slice(0, 160) }
  };
}
return [result];
