// Hunter Web UI — Vanilla JavaScript

/**
 * submitScan handles the scan form submission via fetch.
 */
function submitScan(event) {
  event.preventDefault();

  var target = document.getElementById("target").value.trim();
  if (!target) return false;

  var checkboxes = document.querySelectorAll('input[name="scanners"]:checked');
  var scanners = [];
  checkboxes.forEach(function (cb) {
    scanners.push(cb.value);
  });
  if (scanners.length === 0) {
    showFormError("Please select at least one scanner.");
    return false;
  }

  var concurrency =
    parseInt(document.getElementById("concurrency").value, 10) || 10;
  var timeout = document.getElementById("timeout").value;

  var btn = document.getElementById("submit-btn");
  btn.disabled = true;
  btn.textContent = "Starting...";
  hideFormError();

  fetch("/api/v1/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      target: target,
      scanners: scanners,
      concurrency: concurrency,
      timeout: timeout,
    }),
  })
    .then(function (resp) {
      if (!resp.ok) {
        return resp.json().then(function (data) {
          throw new Error(data.error || "Failed to create scan");
        });
      }
      return resp.json();
    })
    .then(function (data) {
      window.location.href = "/scans/" + data.id;
    })
    .catch(function (err) {
      showFormError(err.message);
      btn.disabled = false;
      btn.textContent = "Start Scan";
    });

  return false;
}

/**
 * toggleAllScanners toggles all scanner checkboxes.
 */
function toggleAllScanners(selectAll) {
  var checkboxes = document.querySelectorAll('input[name="scanners"]');
  checkboxes.forEach(function (cb) {
    cb.checked = selectAll.checked;
  });
}

/**
 * pollScanStatus polls the scan API every 2 seconds and updates the page.
 */
function pollScanStatus(scanId) {
  var interval = setInterval(function () {
    fetch("/api/v1/scans/" + scanId)
      .then(function (resp) {
        return resp.json();
      })
      .then(function (data) {
        // Update status badge
        var statusEl = document.getElementById("scan-status");
        if (statusEl) {
          statusEl.textContent = data.status;
          statusEl.className = "status-badge status-" + data.status;
        }

        // Update progress bar
        if (data.progress) {
          var pct = 0;
          if (data.progress.total_scanners > 0) {
            pct = Math.round(
              (data.progress.completed_scanners /
                data.progress.total_scanners) *
                100
            );
          }
          var bar = document.getElementById("progress-bar");
          if (bar) bar.style.width = pct + "%";

          var text = document.getElementById("progress-text");
          if (text) {
            var msg =
              data.progress.completed_scanners +
              " / " +
              data.progress.total_scanners +
              " scanners complete";
            if (data.progress.current_scanner) {
              msg +=
                " \u2014 running <strong>" +
                escapeHtml(data.progress.current_scanner) +
                "</strong>";
            }
            text.innerHTML = msg;
          }
        }

        // Stop polling and reload when done
        if (data.status === "completed" || data.status === "failed") {
          clearInterval(interval);
          window.location.reload();
        }
      })
      .catch(function () {
        // Silently ignore polling errors
      });
  }, 2000);
}

/**
 * refreshScanList fetches the scan list API and updates the table.
 */
function refreshScanList() {
  fetch("/api/v1/scans")
    .then(function (resp) {
      return resp.json();
    })
    .then(function (scans) {
      var tbody = document.querySelector("#scans-table tbody");
      if (!tbody) return;

      tbody.innerHTML = "";
      var hasRunning = false;

      scans.forEach(function (scan) {
        if (scan.status === "running" || scan.status === "pending") {
          hasRunning = true;
        }
        var tr = document.createElement("tr");
        var target = scan.target.url || scan.target.host || "";
        var scannerBadges = (scan.scanners || [])
          .map(function (s) {
            return '<span class="pill">' + escapeHtml(s) + "</span>";
          })
          .join("");
        var findingCount = scan.finding_count || 0;

        tr.innerHTML =
          '<td><a href="/scans/' +
          scan.id +
          '" class="link-mono">' +
          escapeHtml(scan.id.substring(0, 8)) +
          "</a></td>" +
          '<td class="cell-target">' +
          escapeHtml(target) +
          "</td>" +
          '<td class="cell-scanners">' +
          scannerBadges +
          "</td>" +
          '<td><span class="status-badge status-' +
          scan.status +
          '">' +
          escapeHtml(scan.status) +
          "</span></td>" +
          "<td>" +
          findingCount +
          "</td>" +
          '<td class="cell-time">' +
          escapeHtml(scan.created_at || "") +
          "</td>";
        tbody.appendChild(tr);
      });

      // Stop auto-refresh if nothing is running
      if (!hasRunning) {
        // Page will not keep refreshing
      }
    })
    .catch(function () {
      // Silently ignore refresh errors
    });
}

/**
 * deleteScan deletes a scan and redirects to the scan list.
 */
function deleteScan(scanId) {
  if (!confirm("Are you sure you want to delete this scan?")) return;

  fetch("/api/v1/scans/" + scanId, { method: "DELETE" })
    .then(function (resp) {
      if (resp.ok) {
        window.location.href = "/scans";
      } else {
        alert("Failed to delete scan.");
      }
    })
    .catch(function () {
      alert("Failed to delete scan.");
    });
}

// Helpers

function showFormError(msg) {
  var el = document.getElementById("form-error");
  if (el) {
    el.textContent = msg;
    el.style.display = "block";
  }
}

function hideFormError() {
  var el = document.getElementById("form-error");
  if (el) el.style.display = "none";
}

function escapeHtml(str) {
  var div = document.createElement("div");
  div.appendChild(document.createTextNode(str));
  return div.innerHTML;
}
