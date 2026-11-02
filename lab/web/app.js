"use strict";

/*
 * Page runner for the PS4 14.00 browser lab.
 *
 * ES5 + XHR only: the console's WebKit is old, and the chain probe must not
 * depend on modern syntax. The page registers a session, claims queued probes,
 * executes them with the `api` object the probes expect, and renders a live
 * log that the PC driver writes to as the chain advances.
 */
(function () {
  var FIRMWARE = "14.00";
  var LOG_LIMIT = 400;
  var MAX_LINES = 240;

  var pill = document.getElementById("pill");
  var sessionLabel = document.getElementById("session");
  var ageLabel = document.getElementById("age");
  var stageText = document.getElementById("stage");
  var stageCount = document.getElementById("stage-count");
  var resultBox = document.getElementById("result");
  var logBox = document.getElementById("log");
  var pauseButton = document.getElementById("pause");
  var clearButton = document.getElementById("clear");

  var session = null;
  var active = false;
  var polling = false;
  var running = false;
  var paused = false;
  var logSeq = 0;
  var logLines = 0;
  var stageEvents = 0;
  var connectedAt = 0;
  var lastLine = "";
  var logTimer = null;
  var ageTimer = null;

  function setStatus(text, state) {
    pill.textContent = text;
    pill.className = "pill is-" + state;
  }

  function pad(value) {
    return value < 10 ? "0" + value : String(value);
  }

  function ageText() {
    if (!connectedAt) return "00:00";
    var seconds = Math.floor((Date.now() - connectedAt) / 1000);
    var hours = Math.floor(seconds / 3600);
    var minutes = Math.floor((seconds % 3600) / 60);
    if (hours > 0) return hours + ":" + pad(minutes) + ":" + pad(seconds % 60);
    return pad(minutes) + ":" + pad(seconds % 60);
  }

  function request(method, path, value, headers, timeout) {
    return new Promise(function (resolve, reject) {
      var xhr = new XMLHttpRequest();
      xhr.open(method, path, true);
      xhr.timeout = timeout || 10000;
      if (value !== null && value !== undefined) {
        xhr.setRequestHeader("Content-Type", "application/json");
      }
      if (headers) {
        for (var name in headers) {
          if (Object.prototype.hasOwnProperty.call(headers, name)) {
            xhr.setRequestHeader(name, headers[name]);
          }
        }
      }
      xhr.onload = function () {
        var body = null;
        try { body = JSON.parse(xhr.responseText); }
        catch (error) { body = null; }
        if (xhr.status >= 200 && xhr.status < 300) {
          resolve(body);
        } else {
          var failure = new Error((body && body.error) || "server rejected request");
          failure.httpStatus = xhr.status;
          reject(failure);
        }
      };
      xhr.onerror = function () { reject(new Error("network error")); };
      xhr.ontimeout = function () { reject(new Error("request timed out")); };
      xhr.send(value === null || value === undefined ? null : JSON.stringify(value));
    });
  }

  function requestSync(path, value) {
    var xhr = new XMLHttpRequest();
    xhr.open("POST", path, false);
    xhr.setRequestHeader("Content-Type", "application/json");
    if (session) xhr.setRequestHeader("X-FW14-Session", session.secret);
    xhr.send(JSON.stringify(value));
    if (xhr.status < 200 || xhr.status >= 300) {
      throw new Error("synchronous marker rejected (HTTP " + xhr.status + ")");
    }
    try { return JSON.parse(xhr.responseText); }
    catch (error) { throw new Error("invalid synchronous marker response"); }
  }

  function addLog(level, time, text) {
    var line = document.createElement("div");
    line.className = "log-line level-" + level;
    var stamp = document.createElement("span");
    stamp.className = "log-time";
    stamp.textContent = time;
    var body = document.createElement("span");
    body.className = "log-text";
    body.textContent = text;
    line.appendChild(stamp);
    line.appendChild(body);
    logBox.appendChild(line);
    logLines += 1;
    while (logLines > MAX_LINES) {
      logBox.removeChild(logBox.firstChild);
      logLines -= 1;
    }
    if (!paused) logBox.scrollTop = logBox.scrollHeight;
  }

  function noteLine(line) {
    var time = String(line.ts || "").slice(11, 19) || "--:--:--";
    var text = String(line.text || "").slice(0, 12000);
    addLog(line.level || "info", time, text);
    if (line.level !== "debug") {
      lastLine = text;
      stageText.textContent = text.length > 160 ? text.slice(0, 157) + "..." : text;
    }
    if (line.level === "stage") {
      stageEvents += 1;
      stageCount.textContent = String(stageEvents);
    }
  }

  function pollLog() {
    if (logTimer) clearTimeout(logTimer);
    logTimer = setTimeout(pollLog, paused ? 5000 : 1000);
    request("GET", "/api/log?since=" + logSeq, null, null, 8000).then(function (body) {
      if (!body || !body.lines) return;
      for (var i = 0; i < body.lines.length; i += 1) {
        noteLine(body.lines[i]);
        if (body.lines[i].seq > logSeq) logSeq = body.lines[i].seq;
      }
    }).catch(function () {
      /* keep polling; a dead page is more visible than a dead poller */
    });
  }

  function validChecks(checks, expected) {
    if (!Array.isArray(checks) || checks.length !== expected.length) return false;
    for (var i = 0; i < checks.length; i += 1) {
      var check = checks[i];
      if (!check || Object.prototype.toString.call(check) !== "[object Object]" ||
          Object.keys(check).sort().join(",") !== "details,id,status" ||
          check.id !== expected[i] ||
          ["pass", "fail", "unsupported", "error"].indexOf(check.status) === -1 ||
          !check.details || Object.prototype.toString.call(check.details) !== "[object Object]") {
        return false;
      }
      var keys = Object.keys(check.details);
      if (keys.length > 12) return false;
      for (var j = 0; j < keys.length; j += 1) {
        if (!/^[a-z][a-z0-9_-]{0,63}$/.test(keys[j])) return false;
        var item = check.details[keys[j]];
        if (item !== null && typeof item !== "string" && typeof item !== "number" &&
            typeof item !== "boolean") return false;
        if (typeof item === "string" && item.length > 512) return false;
        if (typeof item === "number" && !isFinite(item)) return false;
      }
    }
    try { return JSON.stringify(checks).length <= 3600; }
    catch (error) { return false; }
  }

  function fetchProbe(command) {
    return new Promise(function (resolve, reject) {
      var xhr = new XMLHttpRequest();
      xhr.open("GET", "/api/commands/" + command.command_id + "/probe", true);
      xhr.timeout = 15000;
      xhr.setRequestHeader("X-FW14-Session", session.secret);
      xhr.setRequestHeader("X-FW14-Attempt", command.attempt_token);
      xhr.onload = function () {
        if (xhr.status !== 200) {
          reject(new Error("probe fetch failed (HTTP " + xhr.status + ")"));
          return;
        }
        var actual;
        try { actual = window.FW14_SHA256.hex(xhr.responseText); }
        catch (error) { reject(new Error("probe digest check failed")); return; }
        if (actual !== command.source_sha256 ||
            xhr.getResponseHeader("X-FW14-Source-SHA256") !== command.source_sha256) {
          reject(new Error("probe source digest mismatch"));
          return;
        }
        resolve(xhr.responseText);
      };
      xhr.onerror = function () { reject(new Error("probe fetch network error")); };
      xhr.ontimeout = function () { reject(new Error("probe fetch timed out")); };
      xhr.send();
    });
  }

  function runProbe(command) {
    return new Promise(function (resolve, reject) {
      var settled = false;
      var timer = setTimeout(function () {
        finish(new Error("probe exceeded its time limit"));
      }, command.timeout_ms);

      function finish(error, checks) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (error) reject(error);
        else resolve(checks);
      }

      fetchProbe(command).then(function (source) {
        if (settled) return;
        var runner;
        try { runner = new Function("api", '"use strict";\n' + source); }
        catch (error) { finish(error); return; }
        var result;
        try {
          result = runner({
            probe_id: command.probe_id,
            isActive: function () { return !settled; },
            log: function (message) { addLog("page", ageText(), String(message)); },
            mark: function (phase) {
              return request("POST", "/api/commands/mark", {
                session_id: session.id,
                command_id: command.command_id,
                attempt: command.attempt,
                attempt_token: command.attempt_token,
                phase: phase
              }, { "X-FW14-Session": session.secret }, 15000);
            },
            markSync: function (phase) {
              return requestSync("/api/commands/mark", {
                session_id: session.id,
                command_id: command.command_id,
                attempt: command.attempt,
                attempt_token: command.attempt_token,
                phase: phase
              });
            },
            uploadChunkSync: function (chunk) {
              return requestSync("/api/dump/chunk", {
                session_id: session.id,
                command_id: command.command_id,
                attempt_token: command.attempt_token,
                pid: chunk.pid,
                module_handle: chunk.module_handle,
                segment_kind: chunk.segment_kind,
                range_start: chunk.range_start,
                range_size: chunk.range_size,
                offset: chunk.offset,
                data_b64: chunk.data_b64
              });
            }
          });
        } catch (error) { finish(error); return; }
        Promise.resolve(result).then(function (checks) {
          if (!validChecks(checks, command.check_ids)) {
            finish(new Error("probe returned invalid checks"));
          } else {
            finish(null, checks);
          }
        }).catch(function (error) { finish(error); });
      }).catch(function (error) { finish(error); });
    });
  }

  function renderResult(probeId, attempt, checks) {
    var counts = { pass: 0, fail: 0, unsupported: 0, error: 0 };
    var html = document.createElement("div");
    var head = document.createElement("p");
    head.className = "result-head";
    head.textContent = probeId + "  (attempt " + attempt + ")";
    html.appendChild(head);
    var list = document.createElement("ul");
    list.className = "checks";
    for (var i = 0; i < checks.length; i += 1) {
      var check = checks[i];
      counts[check.status] = (counts[check.status] || 0) + 1;
      var item = document.createElement("li");
      item.className = "check check-" + check.status;
      var title = document.createElement("b");
      title.textContent = check.id;
      item.appendChild(title);
      item.appendChild(document.createTextNode(" " + check.status));
      var keys = Object.keys(check.details).sort();
      if (keys.length) {
        var details = document.createElement("span");
        details.className = "details";
        var parts = [];
        for (var j = 0; j < keys.length; j += 1) {
          parts.push(keys[j] + "=" + String(check.details[keys[j]]));
        }
        details.textContent = "  " + parts.join("  ");
        item.appendChild(details);
      }
      list.appendChild(item);
    }
    html.appendChild(list);
    var summary = document.createElement("p");
    summary.className = "result-counts";
    summary.textContent = counts.pass + " pass / " + counts.fail + " fail / " +
      counts.unsupported + " unsupported / " + counts.error + " error";
    html.appendChild(summary);
    resultBox.innerHTML = "";
    resultBox.appendChild(html);
  }

  function deliverResult(payload, command) {
    request("POST", "/api/commands/result", payload,
            { "X-FW14-Session": session.secret }, 15000).then(function () {
      running = false;
      setStatus("connected", "connected");
      renderResult(command.probe_id, command.attempt, payload.checks);
      polling = false;
      schedulePoll(1500);
    }).catch(function (error) {
      if (error.httpStatus === 400) {
        /* The server rejects malformed output; report that as a probe error so
         * the operator sees it instead of a silent queue stall. */
        running = false;
        setStatus("result rejected", "error");
        addLog("error", ageText(), "result rejected: " + String(error));
        polling = false;
        schedulePoll(3000);
        return;
      }
      setStatus("saving result", "connecting");
      setTimeout(function () { deliverResult(payload, command); }, 3000);
    });
  }

  function runCommand(command) {
    running = true;
    setStatus("running " + command.probe_id, "running");
    addLog("run", ageText(), "claimed " + command.probe_id + " (attempt " + command.attempt + ")");
    var started = new Date().toISOString();
    runProbe(command).catch(function (error) {
      return [{ id: "probe_error", status: "error",
                details: { error: String(error).slice(0, 512) } }];
    }).then(function (checks) {
      deliverResult({
        session_id: session.id,
        command_id: command.command_id,
        attempt: command.attempt,
        attempt_token: command.attempt_token,
        started_at: started,
        completed_at: new Date().toISOString(),
        checks: checks
      }, command);
    });
  }

  function schedulePoll(delay) {
    if (!active) return;
    setTimeout(poll, delay);
  }

  function poll() {
    if (!active || polling || running) return;
    polling = true;
    request("POST", "/api/commands/claim", { session_id: session.id },
            { "X-FW14-Session": session.secret }, 15000).then(function (body) {
      if (body && body.command) {
        runCommand(body.command);
      } else {
        polling = false;
        schedulePoll(2000);
      }
    }).catch(function (error) {
      polling = false;
      if (error.httpStatus === 403) {
        active = false;
        setStatus("session lost", "error");
        addLog("error", ageText(), "server rejected the session: " + String(error));
        return;
      }
      setStatus("reconnecting", "connecting");
      schedulePoll(3000);
    });
  }

  function connect() {
    if (active) return;
    setStatus("connecting", "connecting");
    request("POST", "/api/sessions", {
      firmware_label: FIRMWARE,
      user_agent: navigator.userAgent || "unavailable",
      runner_version: 1
    }, null, 10000).then(function (identity) {
      session = { id: identity.session_id, secret: identity.session_secret };
      active = true;
      connectedAt = Date.now();
      sessionLabel.textContent = session.id.slice(0, 8);
      setStatus("connected", "connected");
      addLog("info", ageText(), "session " + session.id.slice(0, 8) +
             " registered from the browser");
      ageTimer = setInterval(function () { ageLabel.textContent = ageText(); }, 1000);
      poll();
    }).catch(function (error) {
      setStatus("offline", "error");
      addLog("error", ageText(), "cannot reach the server: " + String(error));
      setTimeout(connect, 5000);
    });
  }

  pauseButton.onclick = function () {
    paused = !paused;
    pauseButton.textContent = paused ? "resume" : "pause";
  };

  clearButton.onclick = function () {
    logBox.innerHTML = "";
    logLines = 0;
  };

  window.addEventListener("load", function () {
    pollLog();
    setTimeout(connect, 300);
  });
}());
