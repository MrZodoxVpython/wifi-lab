/* STRYKER · live terminal stream */
(function () {
  "use strict";

  var shell = document.getElementById("terminal-shell");
  if (!shell) return;

  var jobId = shell.dataset.job;
  var output = document.getElementById("terminal-output");
  var cursor = document.getElementById("term-cursor");
  var waiting = document.getElementById("stream-start");
  var statusPill = document.getElementById("term-status");
  var metaStatus = document.getElementById("meta-status");
  var metaRc = document.getElementById("meta-rc");
  var metaElapsed = document.getElementById("meta-elapsed");
  var stopBtn = document.getElementById("term-stop");
  var copyBtn = document.getElementById("term-copy");
  var downloadBtn = document.getElementById("term-download");
  var autoBtn = document.getElementById("term-autoscroll");

  var after = 0;
  var running = true;
  var autoScroll = true;
  var currentStatus = "running";
  var serverElapsed = 0;
  var serverElapsedAt = Date.now();
  var finishedRendered = false;

  var labels = {
    running: "RUNNING",
    done: "COMPLETE",
    failed: "FAILED",
    stopped: "STOPPED",
    timeout: "TIMEOUT"
  };

  function classify(line) {
    if (/^\$ /.test(line)) return "cmd";
    if (/^\[(?:priv|system|hint|info)\]/.test(line)) return "system";
    if (/^\[fix\]/i.test(line)) return "system";
    if (/^\[error\]/i.test(line) || /not found|permission denied|operation not permitted|no such file/i.test(line)) return "error";
    if (/^\[exit\]/i.test(line)) return "exit";
    return "";
  }

  function append(line) {
    if (!output || !cursor) return;
    if (waiting && waiting.style.display !== "none") {
      waiting.style.display = "none";
    }
    var el = document.createElement("div");
    el.className = "term-line " + classify(line);
    el.textContent = line === "" ? "\u00a0" : line;
    output.insertBefore(el, cursor);
    if (autoScroll) output.scrollTop = output.scrollHeight;
  }

  function setStatus(status) {
    currentStatus = status;
    var label = labels[status] || String(status).toUpperCase();
    if (statusPill) {
      statusPill.textContent = label;
      statusPill.className = "term-status " + status;
    }
    if (metaStatus) {
      metaStatus.textContent = label;
      metaStatus.className = "status-text " + status;
    }
  }

  function updateElapsed() {
    if (!running || !metaElapsed) return;
    var extra = (Date.now() - serverElapsedAt) / 1000;
    metaElapsed.textContent = (serverElapsed + extra).toFixed(1) + "s";
  }
  setInterval(updateElapsed, 200);

  function finish(data) {
    if (finishedRendered) return;
    finishedRendered = true;
    running = false;
    if (cursor) cursor.style.display = "none";
    if (stopBtn) {
      stopBtn.disabled = true;
      stopBtn.textContent = "Selesai";
    }
    if (metaRc) metaRc.textContent = data.rc === null || data.rc === undefined ? "—" : String(data.rc);
    if (data.elapsed !== undefined) {
      serverElapsed = data.elapsed;
      serverElapsedAt = Date.now();
      if (metaElapsed) metaElapsed.textContent = Number(data.elapsed).toFixed(1) + "s";
    }
    append("────────────────────────────────────────");
    append("[done] status=" + data.status + " exit=" + (data.rc ?? "—") + " elapsed=" + (data.elapsed ?? 0).toFixed(1) + "s");
    if (autoScroll && output) output.scrollTop = output.scrollHeight;
  }

  async function poll() {
    if (!running) return;
    try {
      var response = await fetch("/api/jobs/" + encodeURIComponent(jobId) + "?after=" + after, {
        cache: "no-store",
        headers: { "Accept": "application/json" }
      });
      if (!response.ok) throw new Error("HTTP " + response.status);
      var data = await response.json();
      if (data.lines && data.lines.length) data.lines.forEach(append);
      if (typeof data.next === "number") after = data.next;
      if (typeof data.elapsed === "number") {
        serverElapsed = data.elapsed;
        serverElapsedAt = Date.now();
      }
      setStatus(data.status);
      if (data.status !== "running") {
        finish(data);
        return;
      }
      setTimeout(poll, 450);
    } catch (error) {
      append("[error] stream terputus: " + error.message + " — mencoba lagi…");
      setTimeout(poll, 1500);
    }
  }

  function terminalText() {
    if (!output) return "";
    return Array.prototype.slice.call(output.querySelectorAll(".term-line"))
      .filter(function (el) { return el.style.display !== "none"; })
      .map(function (el) { return el.textContent; })
      .join("\n");
  }

  if (stopBtn) {
    stopBtn.addEventListener("click", async function () {
      stopBtn.disabled = true;
      stopBtn.textContent = "Stopping…";
      try {
        await fetch("/api/jobs/" + encodeURIComponent(jobId) + "/stop", { method: "POST" });
      } catch (error) {
        append("[error] gagal menghentikan proses: " + error.message);
        stopBtn.disabled = false;
        stopBtn.textContent = "Stop";
      }
    });
  }

  if (copyBtn) {
    copyBtn.addEventListener("click", async function () {
      try {
        await navigator.clipboard.writeText(terminalText());
        if (window.strykerToast) window.strykerToast("Output terminal disalin");
      } catch (error) {
        if (window.strykerToast) window.strykerToast("Gagal menyalin: " + error.message);
      }
    });
  }

  if (downloadBtn) {
    downloadBtn.addEventListener("click", function () {
      var blob = new Blob([terminalText()], { type: "text/plain;charset=utf-8" });
      var url = URL.createObjectURL(blob);
      var link = document.createElement("a");
      link.href = url;
      link.download = "stryker-" + jobId + ".log";
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
      if (window.strykerToast) window.strykerToast("Log terminal diunduh");
    });
  }

  if (autoBtn) {
    autoBtn.addEventListener("click", function () {
      autoScroll = !autoScroll;
      autoBtn.classList.toggle("active", autoScroll);
      if (autoScroll && output) output.scrollTop = output.scrollHeight;
    });
  }

  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") window.location.href = "/";
  });

  setStatus("running");
  poll();
})();
