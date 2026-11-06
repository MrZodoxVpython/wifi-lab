/* STRYKER · global interaction layer */
(function () {
  "use strict";

  document.documentElement.classList.add("js");

  /* ------------------------------ Clock -------------------------------- */
  var clock = document.getElementById("live-clock");
  if (clock) {
    var tick = function () {
      clock.textContent = new Date().toLocaleTimeString("id-ID", { hour12: false });
    };
    tick();
    setInterval(tick, 1000);
  }

  /* ------------------------------ Toast -------------------------------- */
  var toastStack = document.getElementById("toast-stack");
  function toast(message) {
    if (!toastStack) return;
    var el = document.createElement("div");
    el.className = "toast";
    el.textContent = message;
    toastStack.appendChild(el);
    setTimeout(function () {
      el.classList.add("out");
      setTimeout(function () { el.remove(); }, 240);
    }, 2600);
  }
  window.strykerToast = toast;

  /* --------------------------- Confirm modal --------------------------- */
  var modal = document.getElementById("confirm-modal");
  var modalTitle = document.getElementById("confirm-title");
  var modalText = document.getElementById("confirm-text");
  var modalTarget = document.getElementById("confirm-target");
  var modalCmd = document.getElementById("confirm-cmd");
  var modalIcon = document.getElementById("confirm-icon");
  var okBtn = document.getElementById("confirm-ok");
  var cancelBtn = document.getElementById("confirm-cancel");
  var pendingForm = null;

  function closeModal() {
    if (!modal) return;
    modal.hidden = true;
    pendingForm = null;
  }

  function openModal(form) {
    if (!modal) return;
    pendingForm = form;
    var risk = form.dataset.risk || "medium";
    if (modalTitle) modalTitle.textContent = form.dataset.confirmTitle || "Konfirmasi tindakan";
    if (modalText) modalText.textContent = form.dataset.confirm || "Lanjutkan tindakan ini?";
    if (modalTarget) {
      var target = form.dataset.target;
      modalTarget.hidden = !target;
      modalTarget.innerHTML = target ? "<strong>Target:</strong> " + escapeHtml(target) : "";
    }
    if (modalCmd) {
      var cmd = form.dataset.command;
      modalCmd.hidden = !cmd;
      modalCmd.textContent = cmd || "";
    }
    if (modalIcon) {
      modalIcon.textContent = risk === "high" ? "!" : "?";
      modalIcon.className = "modal-icon" + (risk === "high" ? " high" : "");
    }
    if (okBtn) {
      okBtn.textContent = risk === "high" ? "Ya, jalankan" : "Lanjutkan";
      okBtn.className = "btn small " + (risk === "high" ? "danger" : "primary");
    }
    modal.hidden = false;
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, function (ch) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch];
    });
  }

  document.addEventListener("submit", function (event) {
    var form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    if (!form.dataset.confirm) return;
    event.preventDefault();
    openModal(form);
  }, true);

  if (okBtn) {
    okBtn.addEventListener("click", function () {
      var form = pendingForm;
      closeModal();
      if (form) form.submit();
    });
  }
  if (cancelBtn) cancelBtn.addEventListener("click", closeModal);
  if (modal) {
    modal.addEventListener("click", function (event) {
      if (event.target === modal) closeModal();
    });
  }
  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape" && modal && !modal.hidden) closeModal();
  });

  /* ------------------------------- Copy -------------------------------- */
  async function copyText(text) {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
      } else {
        var area = document.createElement("textarea");
        area.value = text;
        area.style.position = "fixed";
        area.style.opacity = "0";
        document.body.appendChild(area);
        area.select();
        document.execCommand("copy");
        area.remove();
      }
      toast("Disalin ke clipboard");
    } catch (err) {
      toast("Gagal menyalin: " + err.message);
    }
  }

  document.addEventListener("click", function (event) {
    var copyBtn = event.target.closest("[data-copy]");
    if (copyBtn) {
      copyText(copyBtn.dataset.copy || copyBtn.textContent || "");
      return;
    }
    var targetBtn = event.target.closest("[data-copy-target]");
    if (targetBtn) {
      var target = document.getElementById(targetBtn.dataset.copyTarget);
      if (target) copyText(target.textContent || "");
    }
  });

  /* --------------------------- Network filter -------------------------- */
  var networkTable = document.querySelector("[data-network-table]");
  if (networkTable) {
    var rows = Array.prototype.slice.call(networkTable.querySelectorAll("tbody tr"));
    var search = document.querySelector("[data-network-search]");
    var chips = Array.prototype.slice.call(document.querySelectorAll("[data-filter]"));
    var empty = document.querySelector("[data-filter-empty]");
    var visibleCount = document.querySelector("[data-visible-count]");
    var activeFilter = "all";

    var applyFilter = function () {
      var query = (search && search.value ? search.value : "").toLowerCase().trim();
      var shown = 0;
      rows.forEach(function (row) {
        var haystack = (row.dataset.search || row.textContent || "").toLowerCase();
        var security = row.dataset.security || "";
        var matchQuery = !query || haystack.indexOf(query) !== -1;
        var matchSecurity = activeFilter === "all" || security === activeFilter;
        var visible = matchQuery && matchSecurity;
        row.hidden = !visible;
        if (visible) shown += 1;
      });
      if (visibleCount) visibleCount.textContent = String(shown);
      if (empty) empty.hidden = shown !== 0;
    };

    if (search) search.addEventListener("input", applyFilter);
    chips.forEach(function (chip) {
      chip.addEventListener("click", function () {
        activeFilter = chip.dataset.filter || "all";
        chips.forEach(function (c) { c.classList.toggle("active", c === chip); });
        applyFilter();
      });
    });

    var sortBtn = document.querySelector("[data-sort-signal]");
    if (sortBtn) {
      var descending = true;
      sortBtn.addEventListener("click", function () {
        descending = !descending;
        var tbody = networkTable.querySelector("tbody");
        rows.sort(function (a, b) {
          var av = Number(a.dataset.signal || 0);
          var bv = Number(b.dataset.signal || 0);
          return (av - bv) * (descending ? -1 : 1);
        });
        rows.forEach(function (row) { tbody.appendChild(row); });
        var label = sortBtn.querySelector("span");
        if (label) label.textContent = descending ? "Signal ↓" : "Signal ↑";
      });
    }
  }

  /* ----------------------------- Shortcuts ----------------------------- */
  document.addEventListener("keydown", function (event) {
    if (event.key !== "/" || event.metaKey || event.ctrlKey || event.altKey) return;
    var tag = (event.target.tagName || "").toLowerCase();
    if (tag === "input" || tag === "textarea" || tag === "select") return;
    var box = document.querySelector("[data-network-search]");
    if (box) {
      event.preventDefault();
      box.focus();
    }
  });

  /* ------------------------------ Reveal ------------------------------- */
  var revealItems = Array.prototype.slice.call(document.querySelectorAll(".reveal"));
  if ("IntersectionObserver" in window) {
    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add("in");
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.08, rootMargin: "0px 0px -30px 0px" });
    revealItems.forEach(function (item) { observer.observe(item); });
  } else {
    revealItems.forEach(function (item) { item.classList.add("in"); });
  }
})();
