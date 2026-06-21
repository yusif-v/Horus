/**
 * Dashboard Chart.js visualisations for Horus.
 *
 * Reads window.__DASHBOARD_DATA__ (embedded by dashboard.html) and renders
 * four responsive charts that honour the current light/dark theme.
 */

(function () {
  "use strict";

  var DATA = window.__DASHBOARD_DATA__;
  if (!DATA) return;

  // ── Theme-aware colours ──────────────────────────────────────────────────

  function css(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  function chartColours() {
    return {
      text:       css("--text-mid") || "#a3a3a3",
      textHi:     css("--text") || "#ebebeb",
      grid:       css("--border") || "#262626",
      surface:    css("--surface") || "#0e0e14",
      accent:     css("--accent") || "#4abeff",
      critical:   css("--critical") || "#fb3748",
      high:       css("--high") || "#ff8a3b",
      medium:     css("--medium") || "#f0c419",
      low:        css("--low") || "#1fc16b",
      info:       css("--info") || "#8576ff",
    };
  }

  var SEVERITY_COLORS = {
    CRITICAL: "#fb3748",
    HIGH:     "#ff8a3b",
    MEDIUM:   "#f0c419",
    LOW:      "#1fc16b",
  };

  var EPSS_COLORS = {
    "Very High (≥0.5)": "#fb3748",
    "High (0.1-0.5)":   "#ff8a3b",
    "Medium (0.01-0.1)": "#f0c419",
    "Low (<0.01)":      "#1fc16b",
  };

  // ── Chart.js defaults ─────────────────────────────────────────────────────

  var C = chartColours();

  Chart.defaults.color = C.text;
  Chart.defaults.borderColor = C.grid;
  Chart.defaults.font.family = "'IBM Plex Sans', system-ui, sans-serif";
  Chart.defaults.font.size = 12;

  // ── Helper: build a colour array from a severity-keyed map ────────────────

  function mapSeverityColors(labels) {
    return labels.map(function (l) { return SEVERITY_COLORS[l] || C.accent; });
  }

  function mapEpssColors(labels) {
    return labels.map(function (l) { return EPSS_COLORS[l] || C.accent; });
  }

  // ── 1. Severity donut ────────────────────────────────────────────────────

  function buildSeverityChart() {
    if (!DATA.severity || !DATA.severity.length) return;
    var labels = DATA.severity.map(function (d) { return d.cvss_severity; });
    var values = DATA.severity.map(function (d) { return d.cnt; });
    var colours = mapSeverityColors(labels);

    new Chart(document.getElementById("severityChart"), {
      type: "doughnut",
      data: {
        labels: labels,
        datasets: [{
          data: values,
          backgroundColor: colours,
          borderColor: C.surface,
          borderWidth: 2,
          hoverOffset: 6,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: true,
        cutout: "60%",
        plugins: {
          legend: {
            position: "bottom",
            labels: {
              color: C.text,
              padding: 14,
              usePointStyle: true,
              pointStyleWidth: 10,
              font: { size: 11 },
            },
          },
          tooltip: {
            backgroundColor: C.surface,
            titleColor: C.textHi,
            bodyColor: C.text,
            borderColor: C.grid,
            borderWidth: 1,
            callbacks: {
              label: function (ctx) {
                var total = ctx.dataset.data.reduce(function (a, b) { return a + b; }, 0);
                var pct = total > 0 ? ((ctx.parsed / total) * 100).toFixed(1) : 0;
                return " " + ctx.label + ": " + ctx.parsed + " (" + pct + "%)";
              },
            },
          },
        },
      },
    });
  }

  // ── 2. EPSS horizontal bar ───────────────────────────────────────────────

  function buildEpssChart() {
    if (!DATA.epss || !DATA.epss.length) return;
    // Sort by severity (Very High first)
    var order = { "Very High (≥0.5)": 0, "High (0.1-0.5)": 1, "Medium (0.01-0.1)": 2, "Low (<0.01)": 3 };
    var sorted = DATA.epss.slice().sort(function (a, b) {
      return (order[a.bucket] ?? 9) - (order[b.bucket] ?? 9);
    });
    var labels = sorted.map(function (d) { return d.bucket; });
    var values = sorted.map(function (d) { return d.cnt; });
    var colours = mapEpssColors(labels);

    new Chart(document.getElementById("epssChart"), {
      type: "bar",
      data: {
        labels: labels,
        datasets: [{
          label: "CVEs",
          data: values,
          backgroundColor: colours,
          borderRadius: 3,
          barPercentage: 0.6,
        }],
      },
      options: {
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: C.surface,
            titleColor: C.textHi,
            bodyColor: C.text,
            borderColor: C.grid,
            borderWidth: 1,
          },
        },
        scales: {
          x: {
            grid: { color: C.grid },
            ticks: { color: C.text },
          },
          y: {
            grid: { display: false },
            ticks: { color: C.text },
          },
        },
      },
    });
  }

  // ── 3. Publication trend line ────────────────────────────────────────────

  function buildTrendChart() {
    if (!DATA.trend || !DATA.trend.length) return;
    var labels = DATA.trend.map(function (d) { return d.month; });
    var values = DATA.trend.map(function (d) { return d.cnt; });

    new Chart(document.getElementById("trendChart"), {
      type: "line",
      data: {
        labels: labels,
        datasets: [{
          label: "CVEs published",
          data: values,
          borderColor: C.accent,
          backgroundColor: C.accent + "18",
          borderWidth: 2,
          pointBackgroundColor: C.accent,
          pointBorderColor: C.surface,
          pointBorderWidth: 2,
          pointRadius: 4,
          pointHoverRadius: 6,
          fill: true,
          tension: 0.35,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: C.surface,
            titleColor: C.textHi,
            bodyColor: C.text,
            borderColor: C.grid,
            borderWidth: 1,
          },
        },
        scales: {
          x: {
            grid: { color: C.grid },
            ticks: { color: C.text },
          },
          y: {
            grid: { color: C.grid },
            ticks: { color: C.text, stepSize: 1 },
          },
        },
      },
    });
  }

  // ── 4. Top attack vectors bar ────────────────────────────────────────────

  function buildAttackChart() {
    if (!DATA.attacks || !DATA.attacks.length) return;
    var top = DATA.attacks.slice(0, 10);
    var labels = top.map(function (d) { return d.tag; });
    var values = top.map(function (d) { return d.cnt; });

    // Gradient palette for attack bars
    var palette = ["#fb3748","#ff8a3b","#f0c419","#1fc16b","#4abeff",
                   "#8576ff","#e85bd4","#36c4a6","#f7c948","#6b9dff"];
    var colours = labels.map(function (_, i) { return palette[i % palette.length]; });

    new Chart(document.getElementById("attackChart"), {
      type: "bar",
      data: {
        labels: labels,
        datasets: [{
          label: "Occurrences",
          data: values,
          backgroundColor: colours,
          borderRadius: 3,
          barPercentage: 0.65,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: C.surface,
            titleColor: C.textHi,
            bodyColor: C.text,
            borderColor: C.grid,
            borderWidth: 1,
          },
        },
        scales: {
          x: {
            grid: { display: false },
            ticks: { color: C.text, maxRotation: 45, minRotation: 30, font: { size: 10 } },
          },
          y: {
            grid: { color: C.grid },
            ticks: { color: C.text },
          },
        },
      },
    });
  }

  // ── Init ──────────────────────────────────────────────────────────────────

  function init() {
    if (typeof Chart === "undefined") return; // CDN not loaded
    buildSeverityChart();
    buildEpssChart();
    buildTrendChart();
    buildAttackChart();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
