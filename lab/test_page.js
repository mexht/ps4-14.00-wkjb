"use strict";

/*
 * Browser-free integration test for lab/web/app.js.
 *
 * A tiny DOM + XHR shim runs the real page code against a throwaway
 * lab/server.py, so the session -> claim -> probe -> result -> log path and the
 * result/stage rendering are exercised end to end without a PS4.
 *
 *     node lab/test_page.js
 */
const fs = require("fs");
const net = require("net");
const os = require("os");
const path = require("path");
const http = require("http");
const vm = require("vm");
const { execFileSync, spawn } = require("child_process");

const REPO = path.dirname(__dirname);
const MANIFEST = path.join(REPO, "probes",
  "array_iterator_short_control_v1.json");
const PYTHON = process.env.PYTHON || "python3";

// ---------------------------------------------------------------- DOM shim

function Node(tag) {
  this.tagName = tag;
  this.className = "";
  this._text = "";
  this.children = [];
  this.parent = null;
  this.scrollTop = 0;
  this.scrollHeight = 0;
  this.onclick = null;
}
Object.defineProperty(Node.prototype, "textContent", {
  get: function () { return this._text; },
  set: function (value) { this._text = String(value); this.children = []; },
});
Object.defineProperty(Node.prototype, "innerHTML", {
  get: function () { return ""; },
  set: function (value) { if (value === "") this.children = []; },
});
Object.defineProperty(Node.prototype, "firstChild", {
  get: function () { return this.children[0] || null; },
});
Node.prototype.appendChild = function (child) {
  child.parent = this;
  this.children.push(child);
  return child;
};
Node.prototype.removeChild = function (child) {
  const index = this.children.indexOf(child);
  if (index >= 0) this.children.splice(index, 1);
  child.parent = null;
  return child;
};
Node.prototype.text = function () {
  return this._text + this.children.map(function (c) { return c.text(); }).join("");
};
Node.prototype.findAll = function (predicate, out) {
  out = out || [];
  if (predicate(this)) out.push(this);
  this.children.forEach(function (c) { c.findAll(predicate, out); });
  return out;
};

const ids = ["pill", "session", "age", "stage", "stage-count", "result", "log",
             "pause", "clear"];
const elements = {};
ids.forEach(function (id) { elements[id] = new Node("div"); });

const loadHandlers = [];
global.window = global;
global.document = {
  getElementById: function (id) {
    if (!elements[id]) elements[id] = new Node("div");
    return elements[id];
  },
  createElement: function (tag) { return new Node(tag); },
  createTextNode: function (text) {
    const node = new Node("#text");
    node.textContent = text;
    return node;
  },
};
Object.defineProperty(global, "navigator", {
  configurable: true,
  value: { userAgent: "Mozilla/5.0 (PlayStation 4/14.00) AppleWebKit/605.1.15" },
});
global.addEventListener = function (name, fn) {
  if (name === "load") loadHandlers.push(fn);
};

// ---------------------------------------------------------------- XHR shim

let BASE = "";

function headerMap(lines) {
  const map = {};
  lines.forEach(function (line) {
    const at = line.indexOf(":");
    if (at > 0) map[line.slice(0, at).trim().toLowerCase()] = line.slice(at + 1).trim();
  });
  return map;
}

function syncFetch(method, url, headers, body) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ps4lab-xhr-"));
  const hdrFile = path.join(dir, "h");
  const bodyFile = path.join(dir, "b");
  const args = ["-sS", "-X", method, "-D", hdrFile, "-o", bodyFile, "-w", "%{http_code}"];
  Object.keys(headers).forEach(function (name) {
    args.push("-H", name + ": " + headers[name]);
  });
  if (body != null) args.push("--data-binary", body);
  const status = parseInt(execFileSync("curl", args.concat([BASE + url]),
                                       { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim(), 10);
  const raw = fs.readFileSync(hdrFile, "utf8").split(/\r?\n\r?\n/)[0];
  return { status: status, text: fs.readFileSync(bodyFile, "utf8"),
           headers: headerMap(raw.split(/\r?\n/).slice(1)) };
}

function XHR() {
  this.headers = {};
  this.status = 0;
  this.responseText = "";
  this._headers = {};
  this.onload = this.onerror = this.ontimeout = null;
  this.timeout = 0;
}
XHR.prototype.open = function (method, url, async) {
  this.method = method;
  this.url = url;
  this.async = async !== false;
};
XHR.prototype.setRequestHeader = function (name, value) {
  this.headers[name] = value;
};
XHR.prototype.getResponseHeader = function (name) {
  return this._headers[String(name).toLowerCase()] || null;
};
XHR.prototype.send = function (body) {
  const self = this;
  if (!this.async) {
    const out = syncFetch(this.method, this.url, this.headers, body);
    this.status = out.status;
    this.responseText = out.text;
    this._headers = out.headers;
    return;
  }
  const url = new URL(BASE + this.url);
  if (body != null) this.headers["Content-Length"] = Buffer.byteLength(body);
  let timer = null;
  const request = http.request({
    hostname: url.hostname, port: url.port, path: url.pathname + url.search,
    method: this.method, headers: this.headers,
  }, function (response) {
    let text = "";
    response.setEncoding("utf8");
    response.on("data", function (chunk) { text += chunk; });
    response.on("end", function () {
      clearTimeout(timer);
      self.status = response.statusCode;
      self.responseText = text;
      self._headers = {};
      Object.keys(response.headers).forEach(function (name) {
        self._headers[name.toLowerCase()] = response.headers[name];
      });
      if (self.onload) self.onload();
    });
  });
  request.on("error", function () {
    clearTimeout(timer);
    if (self.onerror) self.onerror();
  });
  timer = setTimeout(function () {
    request.destroy();
    if (self.ontimeout) self.ontimeout();
  }, this.timeout || 30000);
  if (body != null) request.write(body);
  request.end();
};
global.XMLHttpRequest = XHR;

// ---------------------------------------------------------------- harness

function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

function admin(method, route, value) {
  const body = value == null ? null : JSON.stringify(value);
  return syncFetch(method, route,
                   body == null ? {} : { "Content-Type": "application/json" }, body);
}

let failures = 0;
function check(name, cond, extra) {
  console.log((cond ? "PASS " : "FAIL ") + name + (extra ? "  " + extra : ""));
  if (!cond) failures += 1;
}

function freePort() {
  return new Promise(function (resolve) {
    const probe = net.createServer();
    probe.listen(0, "127.0.0.1", function () {
      const port = probe.address().port;
      probe.close(function () { resolve(port); });
    });
  });
}

async function startServer() {
  const port = await freePort();
  BASE = "http://127.0.0.1:" + port;
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "ps4lab-page-"));
  const out = fs.openSync(path.join(tmp, "server.log"), "w");
  const child = spawn(PYTHON, [path.join(REPO, "lab", "server.py"), "serve",
    "--host", "127.0.0.1", "--port", String(port),
    "--state", path.join(tmp, "state.json"),
    "--results", path.join(tmp, "results"),
    "--dumps", path.join(tmp, "dumps")],
  { stdio: ["ignore", out, out] });
  for (let i = 0; i < 60; i += 1) {
    try {
      if (syncFetch("GET", "/api/health", {}).status === 200) return child;
    } catch (error) { /* not up yet */ }
    await sleep(100);
  }
  child.kill();
  throw new Error("server did not start; see " + path.join(tmp, "server.log"));
}

async function main() {
  const server = await startServer();
  try {
    vm.runInThisContext(fs.readFileSync(path.join(REPO, "lab/web/sha256.js"), "utf8"));
    vm.runInThisContext(fs.readFileSync(path.join(REPO, "lab/web/app.js"), "utf8"));
    loadHandlers.forEach(function (fn) { fn(); });

    await sleep(1200);
    check("page registered a session", /^[0-9a-f]{8}$/.test(elements.session.textContent),
          elements.session.textContent);
    check("pill shows connected", elements.pill.textContent === "connected",
          elements.pill.textContent);

    const sessions = JSON.parse(admin("GET", "/api/admin/sessions").text);
    check("one session on the server", sessions.length === 1, String(sessions.length));
    const sid = sessions[0].id;

    const queued = JSON.parse(admin("POST", "/api/admin/enqueue-probe",
      { session_id: sid, manifest: MANIFEST }).text);
    check("probe queued", /^[0-9a-f]{32}$/.test(queued.command_id), queued.command_id);

    let command = null;
    for (let i = 0; i < 40; i += 1) {
      await sleep(250);
      const rows = JSON.parse(admin("GET", "/api/admin/commands").text);
      command = rows.filter(function (r) { return r.id === queued.command_id; })[0];
      if (command && command.status === "completed") break;
    }
    check("probe completed", command && command.status === "completed",
          command && command.status);
    check("check recorded",
          command && command.checks && command.checks[0].id === "short_iterator",
          command && command.checks && JSON.stringify(command.checks[0]));

    await sleep(1200);
    const logText = elements.log.text();
    check("log shows the claim",
          logText.indexOf("claimed array_iterator_short_control_v1") >= 0);
    check("log shows the result", logText.indexOf("short_iterator: pass") >= 0);
    check("log has level classes",
          elements.log.findAll(function (n) {
            return n.className.indexOf("level-ok") >= 0;
          }).length > 0);
    check("result rendered",
          elements.result.text().indexOf("array_iterator_short_control_v1") >= 0,
          elements.result.text().slice(0, 80));
    check("result counts rendered",
          elements.result.text().indexOf("1 pass / 0 fail") >= 0,
          elements.result.text().slice(0, 80));

    admin("POST", "/api/admin/note", { text: "chain: stage C armed", level: "stage" });
    await sleep(1500);
    check("stage line rendered", elements.stage.textContent === "chain: stage C armed",
          elements.stage.textContent);
    check("stage counter", elements["stage-count"].textContent === "1",
          elements["stage-count"].textContent);

    elements.pause.onclick();
    check("pause button toggles", elements.pause.textContent === "resume",
          elements.pause.textContent);
    elements.clear.onclick();
    check("clear empties the log", elements.log.children.length === 0);
  } finally {
    server.kill();
  }

  console.log(failures === 0 ? "\nALL OK" : "\n" + failures + " FAILURES");
  process.exit(failures === 0 ? 0 : 1);
}

main().catch(function (error) {
  console.error(error);
  process.exit(1);
});
