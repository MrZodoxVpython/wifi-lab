/* STRYKER · ISP & router info panel */
(function () {
  "use strict";

  var root = document.getElementById("network-info");
  if (!root) return;

  var btn = document.getElementById("run-network-info");
  var btnLabel = document.getElementById("run-network-info-label");
  var statusEl = document.getElementById("netinfo-status");
  var resultEl = document.getElementById("netinfo-result");

  function esc(value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, function (ch) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch];
    });
  }

  function text(value, fallback) {
    var str = value == null ? "" : String(value).trim();
    return str ? str : (fallback || "—");
  }

  function copyButton(value, label) {
    if (!value) return "";
    return '<button type="button" class="netinfo-copy" data-copy="' + esc(value) + '">' +
      esc(label || "Copy") + "</button>";
  }

  function kv(rows) {
    return '<div class="netinfo-kv">' + rows.map(function (row) {
      if (!row) return "";
      return "<div><span>" + esc(row[0]) + "</span><strong" +
        (row[2] ? ' title="' + esc(row[2]) + '"' : "") + ">" + esc(row[1]) + "</strong></div>";
    }).join("") + "</div>";
  }

  function card(title, badge, body, extraClass) {
    return '<article class="netinfo-card ' + (extraClass || "") + '">' +
      '<div class="netinfo-card-head"><span class="netinfo-kicker">' + esc(title) + "</span>" +
      (badge || "") + "</div>" + body + "</article>";
  }

  function warningList(items) {
    var list = (items || []).filter(Boolean);
    if (!list.length) return "";
    return '<div class="netinfo-warnings">' + list.map(function (item) {
      return '<div class="netinfo-warning"><span aria-hidden="true">!</span><span>' + esc(item) + "</span></div>";
    }).join("") + "</div>";
  }

  function setStatus(html, tone) {
    if (!statusEl) return;
    statusEl.hidden = false;
    statusEl.className = "netinfo-status" + (tone ? " " + tone : "");
    statusEl.innerHTML = html;
  }

  function renderLoading() {
    if (resultEl) {
      resultEl.hidden = true;
      resultEl.innerHTML = "";
    }
    setStatus(
      '<div class="netinfo-loading"><span class="netinfo-spinner" aria-hidden="true"></span>' +
      "Memeriksa koneksi, gateway, ISP, dan router… proses ini bisa memakan beberapa detik.</div>",
      "loading"
    );
  }

  function renderError(message) {
    setStatus("", "");
    if (!resultEl) return;
    resultEl.hidden = false;
    resultEl.innerHTML = '<div class="netinfo-empty">' +
      '<strong>Run info gagal.</strong><p>' + esc(message) + "</p>" +
      '<p class="small">Periksa koneksi Wi-Fi lalu coba lagi. Jika masalah berlanjut, lihat log terminal server.</p>' +
      "</div>";
  }

  function renderNotConnected(data) {
    setStatus(
      '<span class="badge amber">BELUM TERHUBUNG</span> ' +
      esc(data.message || "Perangkat belum terhubung ke Wi-Fi target."),
      "warn"
    );
    if (!resultEl) return;
    resultEl.hidden = false;
    var link = data.link || {};
    var rows = [
      ["Interface", text(link.iface || (data.target || {}).iface)],
      ["Status", link.connected ? "Terhubung ke jaringan lain" : "Tidak terhubung"],
    ];
    if (link.connected) {
      rows.push(["SSID aktif", text(link.ssid)]);
      rows.push(["BSSID aktif", text(link.bssid)]);
    }
    rows.push(["Target SSID", text((data.target || {}).ssid)]);
    rows.push(["Target BSSID", text((data.target || {}).bssid)]);
    resultEl.innerHTML = '<div class="netinfo-grid">' +
      card("Koneksi saat ini", '<span class="badge amber">OFFLINE</span>', kv(rows), "wide") +
      "</div>" +
      '<div class="netinfo-empty"><p>Sambungkan komputer ke jaringan <b>' +
      esc(text((data.target || {}).ssid, "target")) + "</b>, lalu klik <b>Run info</b> lagi.</p></div>" +
      warningList(data.warnings);
  }

  function renderResult(data) {
    var link = data.link || {};
    var isp = data.isp || {};
    var router = data.router || {};
    var login = data.login || {};
    var creds = login.credentials || {};

    var ipv4 = (link.ipv4 || []).map(function (item) {
      return item.address + (item.prefix != null ? "/" + item.prefix : "");
    }).join(", ");
    var dns = (link.dns || []).join(", ");

    var connectionBody = kv([
      ["SSID", text(link.ssid || (data.target || {}).ssid)],
      ["BSSID", text(link.bssid || (data.target || {}).bssid)],
      ["Interface", text(link.iface || (data.target || {}).iface)],
      ["IP lokal", text(ipv4)],
      ["Gateway", text(link.gateway)],
      ["DNS", text(dns)],
    ]);

    var ispBadge = isp.error
      ? '<span class="badge red">TIDAK TERSEDIA</span>'
      : '<span class="badge green">TERDETEKSI</span>';
    var location = [isp.city, isp.region, isp.country].filter(Boolean).join(", ");
    var ispBody = isp.error
      ? '<div class="netinfo-empty tight"><p>' + esc(isp.error) + "</p></div>"
      : kv([
        ["ISP", text(isp.isp)],
        ["Organisasi", text(isp.org)],
        ["ASN", text(isp.asn)],
        ["IP publik", text(isp.public_ip)],
        ["Lokasi", text(location)],
        ["Sumber", text(isp.source)],
      ]);

    var brand = router.brand || router.vendor_oui || "Tidak teridentifikasi";
    var model = [router.model, router.model_number].filter(Boolean).join(" ");
    var evidence = (router.evidence || []).length
      ? '<ul class="netinfo-evidence">' + router.evidence.map(function (item) {
        return "<li>" + esc(item) + "</li>";
      }).join("") + "</ul>"
      : "";
    var routerBadge = router.brand
      ? '<span class="badge cyan">' + esc(router.brand) + "</span>"
      : '<span class="badge amber">GENERIK</span>';
    var routerBody = kv([
      ["Brand", text(brand)],
      ["Model", text(model)],
      ["Manufaktur", text(router.manufacturer)],
      ["Friendly name", text(router.friendly_name)],
      ["Gateway", text(router.gateway)],
      ["MAC gateway", text(router.mac) + (router.vendor_oui ? " · " + router.vendor_oui : "")],
      ["Hostname", text(router.gateway_hostname)],
    ]) + evidence;

    var adminUrl = login.url || "";
    var urlLine = adminUrl
      ? '<div class="netinfo-login-url">' +
        '<span class="netinfo-kicker">Login URL</span>' +
        '<a href="' + esc(adminUrl) + '" target="_blank" rel="noopener noreferrer">' + esc(adminUrl) + "</a>" +
        copyButton(adminUrl, "Copy URL") + "</div>"
      : "";

    var usernameRow = '<div class="netinfo-cred"><span>Username</span><strong>' +
      esc(text(creds.username, "(kosong)")) + "</strong>" + copyButton(creds.username) + "</div>";
    var passwordRow = '<div class="netinfo-cred"><span>Password</span><strong>' +
      esc(text(creds.password, "(kosong)")) + "</strong>" + copyButton(creds.password) + "</div>";

    var alternatives = (creds.alternatives || []).map(function (pair) {
      return '<code>' + esc(pair.username || "(kosong)") + " / " +
        esc(pair.password || "(kosong)") + "</code>";
    }).join(" ");

    var loginBody = urlLine +
      '<div class="netinfo-creds">' + usernameRow + passwordRow + "</div>" +
      '<div class="netinfo-kv netinfo-login-meta">' +
      '<div><span>Login IP</span><strong>' + esc(text(login.ip, router.gateway)) + "</strong></div>" +
      '<div><span>Hostname</span><strong>' + esc(text(login.hostname, router.gateway_hostname)) + "</strong></div>" +
      '<div><span>Referensi brand</span><strong>' + esc(text(creds.brand, "Generic")) + "</strong></div>" +
      "</div>" +
      (alternatives ? '<div class="netinfo-alts"><span>Alternatif default:</span> ' + alternatives + "</div>" : "") +
      '<p class="netinfo-note">' + esc(login.note || "") + "</p>";

    if (resultEl) {
      resultEl.hidden = false;
      resultEl.innerHTML = '<div class="netinfo-grid">' +
        card("Koneksi", '<span class="badge green">TERHUBUNG</span>', connectionBody) +
        card("ISP", ispBadge, ispBody) +
        card("Router", routerBadge, routerBody) +
        card(
          "Login router",
          '<span class="badge amber">REFERENSI DEFAULT</span>',
          loginBody,
          "wide"
        ) +
        "</div>" +
        warningList(data.warnings) +
        '<p class="netinfo-stamp">Diperbarui ' + esc(text(data.generated_at)) +
        " · kredensial default belum diverifikasi</p>";
    }
    setStatus('<span class="badge green">SELESAI</span> Info jaringan berhasil dikumpulkan.', "ok");
  }

  async function runInfo() {
    var iface = root.dataset.iface || "";
    var bssid = root.dataset.bssid || "";
    var ssid = root.dataset.ssid || "";
    if (!iface || !bssid) {
      renderError("Data target tidak lengkap. Muat ulang halaman detail SSID.");
      return;
    }

    var url = "/api/network-info?iface=" + encodeURIComponent(iface) +
      "&bssid=" + encodeURIComponent(bssid) +
      "&ssid=" + encodeURIComponent(ssid);

    if (btn) btn.disabled = true;
    if (btnLabel) btnLabel.textContent = "Memeriksa…";
    renderLoading();

    var controller = new AbortController();
    var timer = setTimeout(function () { controller.abort(); }, 45000);
    try {
      var response = await fetch(url, { signal: controller.signal, headers: { Accept: "application/json" } });
      var data = await response.json().catch(function () { return null; });
      if (!response.ok || !data || data.ok === false) {
        renderError((data && data.error) || ("Server mengembalikan HTTP " + response.status + "."));
        return;
      }
      if (!data.connected) {
        renderNotConnected(data);
        return;
      }
      renderResult(data);
    } catch (err) {
      if (err && err.name === "AbortError") {
        renderError("Permintaan melebihi 45 detik. Router atau layanan ISP mungkin tidak merespons.");
      } else {
        renderError("Tidak dapat menghubungi server: " + (err && err.message ? err.message : err));
      }
    } finally {
      clearTimeout(timer);
      if (btn) btn.disabled = false;
      if (btnLabel) btnLabel.textContent = "Run info";
    }
  }

  if (btn) btn.addEventListener("click", runInfo);
})();
