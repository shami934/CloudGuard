/**
 * CloudGuard: Intelligent Cloud Monitoring & Automated Remediation System
 * Frontend Application & Real-time Telemetry Engine
 */

let pollTimer = null;
let currentPollInterval = 5000;

function isDashboardPage() {
  const page = document.body ? document.body.getAttribute("data-page") : null;
  if (page) {
    return page === "dashboard";
  }
  return !!document.getElementById("cpu-value") && !!document.querySelector(".metric-grid");
}

document.addEventListener("DOMContentLoaded", () => {
  initSplashScreen();
  initLiveClock();
  setupMobileMenu();
  setupHistoryChart();

  // Only initiate live telemetry polling on the dashboard
  if (isDashboardPage()) {
    fetchMetrics();
  }
});

/* ==========================================================================
   1. Welcome / Splash Screen Intro Controller (Exactly 5 Seconds)
   ========================================================================== */
function initSplashScreen() {
  const splash = document.getElementById("splash-screen");
  if (!splash) return;

  // Only trigger on the dashboard view
  if (!isDashboardPage()) {
    splash.style.display = "none";
    return;
  }

  // Check if splash screen was already displayed during this browser session
  try {
    if (sessionStorage.getItem("cloudguard_splash_shown")) {
      splash.style.display = "none";
      return;
    }
    // Mark as shown so navigating between pages in this session doesn't re-trigger splash
    sessionStorage.setItem("cloudguard_splash_shown", "true");
  } catch (e) {
    // Graceful fallback if storage access is restricted
  }

  const statusText = document.getElementById("splash-status-text");
  const progressBar = document.getElementById("splash-progress");

  // Telemetry status message ticker steps mapped across 5.0 seconds (5000ms)
  const steps = [
    { time: 150, text: "INITIALIZING TELEMETRY ENGINE...", progress: "15%" },
    { time: 1200, text: "AUTHENTICATING CLOUDGUARD AGENTS...", progress: "38%" },
    { time: 2300, text: "CALIBRATING DEFENSE & SELF-HEALING POLICIES...", progress: "65%" },
    { time: 3500, text: "SYNCHRONIZING ZERO-TRUST PERIMETER MESH...", progress: "88%" },
    { time: 4600, text: "PERIMETER SECURE · ACCESS GRANTED", progress: "100%" }
  ];

  const timeouts = [];
  steps.forEach((step) => {
    const t = setTimeout(() => {
      if (statusText) statusText.textContent = step.text;
      if (progressBar) progressBar.style.width = step.progress;
    }, step.time);
    timeouts.push(t);
  });

  // Dissolve splash screen smoothly after EXACTLY 5.0s (5000ms)
  const exitTimer = setTimeout(() => {
    dismissSplash();
  }, 5000);

  // Optional manual skip fallback on click
  splash.addEventListener("click", () => {
    clearTimeout(exitTimer);
    timeouts.forEach(clearTimeout);
    if (progressBar) progressBar.style.width = "100%";
    dismissSplash();
  });

  let dismissed = false;
  function dismissSplash() {
    if (dismissed) return;
    dismissed = true;
    splash.classList.add("splash-fade-out");
    setTimeout(() => {
      splash.style.display = "none";
    }, 600);
  }
}

/* ==========================================================================
   2. Real-time SOC Clock
   ========================================================================== */
function initLiveClock() {
  const clockEl = document.querySelector("#topbar-clock .clock-val");
  if (!clockEl) return;

  function updateClock() {
    const now = new Date();
    const isoString = now.toISOString().replace("T", " ").substring(0, 19) + " UTC";
    clockEl.textContent = isoString;
  }

  updateClock();
  setInterval(updateClock, 1000);
}

/* ==========================================================================
   3. Telemetry Polling & Mobile Navigation
   ========================================================================== */
function scheduleNextPoll(intervalMs) {
  if (pollTimer) clearTimeout(pollTimer);
  if (!isDashboardPage()) return;
  pollTimer = setTimeout(async () => {
    await fetchMetrics();
  }, intervalMs);
}

function setupMobileMenu() {
  const menuBtn = document.getElementById("menu-btn");
  const sidebar = document.getElementById("sidebar");
  const overlay = document.getElementById("overlay");

  if (!menuBtn || !sidebar || !overlay) {
    return;
  }

  function closeMenu() {
    sidebar.classList.remove("is-open");
    overlay.hidden = true;
  }

  menuBtn.addEventListener("click", () => {
    const isOpen = sidebar.classList.toggle("is-open");
    overlay.hidden = !isOpen;
  });

  overlay.addEventListener("click", closeMenu);
}

async function fetchMetrics() {
  if (!isDashboardPage()) return;
  try {
    const response = await fetch("/api/metrics");
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const data = await response.json();
    if (data.status === "success" && data.current) {
      updateDashboard(data.current, data.history || [], data.aws_cpu_percent, data.aws_cloudwatch);
      if (data.interval_seconds && Number(data.interval_seconds) > 0) {
        currentPollInterval = Number(data.interval_seconds) * 1000;
      }
    }
  } catch (error) {
    console.error("Failed to fetch metrics:", error);
  } finally {
    if (isDashboardPage()) {
      scheduleNextPoll(currentPollInterval);
    }
  }
}

/* ==========================================================================
   4. Live Dashboard Telemetry DOM Updates
   ========================================================================== */
function updateDashboard(current, history, awsCpu = null, awsInfo = null) {
  // Update Local Host CPU
  const cpuVal = document.getElementById("cpu-value");
  const cpuBar = document.getElementById("cpu-bar");
  const cpuPill = document.getElementById("cpu-pill");
  if (cpuVal) cpuVal.textContent = `${current.cpu_percent}%`;
  if (cpuBar) {
    cpuBar.style.width = `${Math.min(current.cpu_percent, 100)}%`;
    cpuBar.className = "bar-fill";
    if (current.cpu_percent >= 90) cpuBar.classList.add("bar-critical");
    else if (current.cpu_percent >= 70) cpuBar.classList.add("bar-warn");
  }
  if (cpuPill) {
    if (current.cpu_percent >= 90) {
      cpuPill.textContent = "Critical";
      cpuPill.className = "pill pill-offline";
    } else if (current.cpu_percent >= 70) {
      cpuPill.textContent = "Elevated";
      cpuPill.className = "pill pill-warning";
    } else {
      cpuPill.textContent = "Normal";
      cpuPill.className = "pill pill-online";
    }
  }

  // Update AWS EC2 CloudWatch CPU Card
  const awsVal = document.getElementById("aws-cpu-value");
  const awsBar = document.getElementById("aws-cpu-bar");
  const awsPill = document.getElementById("aws-cpu-pill");
  const awsMeta = document.getElementById("aws-cpu-meta");
  const awsTime = document.getElementById("aws-cpu-time");
  const awsInstLabel = document.getElementById("aws-instance-label");

  if (awsVal) {
    if (awsCpu !== null && awsCpu !== undefined) {
      awsVal.textContent = `${awsCpu}%`;
      if (awsBar) {
        awsBar.style.width = `${Math.min(awsCpu, 100)}%`;
        awsBar.className = "bar-fill bar-aws";
        if (awsCpu >= 90) awsBar.classList.add("bar-critical");
        else if (awsCpu >= 70) awsBar.classList.add("bar-warn");
      }
      if (awsPill) {
        if (awsCpu >= 90) {
          awsPill.textContent = "Critical";
          awsPill.className = "pill pill-offline";
        } else if (awsCpu >= 70) {
          awsPill.textContent = "Elevated";
          awsPill.className = "pill pill-warning";
        } else {
          awsPill.textContent = "Optimal";
          awsPill.className = "pill pill-online";
        }
      }
      if (awsTime && awsInfo && awsInfo.last_datapoint_time) {
        awsTime.textContent = awsInfo.last_datapoint_time;
      }
      if (awsMeta && awsInfo) {
        awsMeta.textContent = `EC2: ${awsInfo.instance_id || 'i-076ce4fc220f4f297'} · CloudWatch 5m`;
      }
    } else {
      // CloudWatch state when datapoint is not yet received or awaiting IAM/CloudWatch polling
      if (awsBar) awsBar.style.width = "0%";
      if (awsPill) {
        if (awsInfo && awsInfo.status === "no_datapoints") {
          awsPill.textContent = "No Data";
          awsPill.className = "pill pill-warning";
        } else if (awsInfo && awsInfo.status === "error") {
          awsPill.textContent = "Standby";
          awsPill.className = "pill pill-neutral";
        } else {
          awsPill.textContent = "CloudWatch";
          awsPill.className = "pill pill-aws";
        }
      }
      if (awsMeta && awsInfo) {
        if (awsInfo.status === "no_datapoints") {
          awsMeta.textContent = "No 5m datapoints in last 60m";
        } else if (awsInfo.error) {
          const errMsg = awsInfo.error.length > 36 ? awsInfo.error.substring(0, 33) + "..." : awsInfo.error;
          awsMeta.textContent = `CloudWatch: ${errMsg}`;
        } else {
          awsMeta.textContent = "CloudWatch 5-min Average";
        }
      }
      if (awsTime && awsInfo) {
        awsTime.textContent = awsInfo.status === "available" ? "Synced" : "IAM Active";
      }
    }
    if (awsInstLabel && awsInfo && awsInfo.instance_id) {
      awsInstLabel.textContent = `Instance: ${awsInfo.instance_id}`;
    }
  }

  // Update Memory
  const memVal = document.getElementById("memory-value");
  const memBar = document.getElementById("memory-bar");
  const memPill = document.getElementById("mem-pill");
  if (memVal) memVal.textContent = `${current.memory_percent}%`;
  if (memBar) {
    memBar.style.width = `${Math.min(current.memory_percent, 100)}%`;
    memBar.className = "bar-fill";
    if (current.memory_percent >= 95) memBar.classList.add("bar-critical");
    else if (current.memory_percent >= 80) memBar.classList.add("bar-warn");
  }
  if (memPill) {
    if (current.memory_percent >= 95) {
      memPill.textContent = "Critical";
      memPill.className = "pill pill-offline";
    } else if (current.memory_percent >= 80) {
      memPill.textContent = "Elevated";
      memPill.className = "pill pill-warning";
    } else {
      memPill.textContent = "Normal";
      memPill.className = "pill pill-online";
    }
  }

  // Update Storage
  const diskVal = document.getElementById("storage-value");
  const diskBar = document.getElementById("storage-bar");
  const diskPill = document.getElementById("disk-pill");
  if (diskVal) diskVal.textContent = `${current.disk_percent}%`;
  if (diskBar) {
    diskBar.style.width = `${Math.min(current.disk_percent, 100)}%`;
    diskBar.className = "bar-fill";
    if (current.disk_percent >= 90) diskBar.classList.add("bar-critical");
    else if (current.disk_percent >= 75) diskBar.classList.add("bar-warn");
  }
  if (diskPill) {
    if (current.disk_percent >= 90) {
      diskPill.textContent = "Critical";
      diskPill.className = "pill pill-offline";
    } else if (current.disk_percent >= 75) {
      diskPill.textContent = "Elevated";
      diskPill.className = "pill pill-warning";
    } else {
      diskPill.textContent = "Healthy";
      diskPill.className = "pill pill-online";
    }
  }

  // Update Network
  const netVal = document.getElementById("network-value");
  const netBar = document.getElementById("network-bar");
  const netMeta = document.getElementById("network-meta");

  const sentMB = (current.bytes_sent / (1024 * 1024)).toFixed(1);
  const recvMB = (current.bytes_recv / (1024 * 1024)).toFixed(1);

  if (netVal) netVal.innerHTML = `${recvMB} <span class="unit">MB</span>`;
  if (netBar) netBar.style.width = `${Math.min((current.bytes_recv / (1024 * 1024 * 10)) * 100, 100)}%`;
  if (netMeta) netMeta.textContent = `Inbound ${recvMB} MB · Outbound ${sentMB} MB`;

  // Render SVG charts
  drawCharts(history, current);
}

/* ==========================================================================
   5. Cyber SOC SVG Trend Charts Generator
   ========================================================================== */
function drawCharts(history, current) {
  const charts = document.querySelectorAll("[data-chart]");
  if (!charts.length) return;

  // Extract historical series, padding to 12 data points if needed
  let cpuSeries = history.map((item) => item.cpu_usage);
  let memSeries = history.map((item) => item.memory_usage);
  let netSeries = history.map((item) => item.network_inbound / (1024 * 1024)); // MB

  if (cpuSeries.length === 0) cpuSeries = [current.cpu_percent];
  if (memSeries.length === 0) memSeries = [current.memory_percent];
  if (netSeries.length === 0) netSeries = [current.bytes_recv / (1024 * 1024)];

  // Pad series so SVGs render smooth curves across 12 points
  while (cpuSeries.length < 12) cpuSeries.unshift(cpuSeries[0] || 0);
  while (memSeries.length < 12) memSeries.unshift(memSeries[0] || 0);
  while (netSeries.length < 12) netSeries.unshift(netSeries[0] || 0);

  charts.forEach((chart) => {
    const key = chart.getAttribute("data-chart");
    if (key === "cpu") {
      chart.innerHTML = buildLineChart(cpuSeries, 100, "cyan");
    } else if (key === "memory") {
      chart.innerHTML = buildLineChart(memSeries, 100, "indigo");
    } else if (key === "network") {
      const maxNet = Math.max(...netSeries, 10);
      chart.innerHTML = buildLineChart(netSeries, maxNet, "emerald");
    }
  });
}

function buildLineChart(values, maxPossibleValue = 100, colorTheme = "cyan") {
  const width = 340;
  const height = 150;
  const paddingX = 14;
  const paddingY = 16;
  const maxValue = maxPossibleValue || 100;
  const stepX = (width - paddingX * 2) / Math.max(values.length - 1, 1);

  const points = values.map((value, index) => {
    const x = paddingX + index * stepX;
    const y = height - paddingY - (Math.min(value, maxValue) / maxValue) * (height - paddingY * 2);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });

  const line = points.join(" ");
  const area = `${paddingX},${height - paddingY} ${line} ${width - paddingX},${height - paddingY}`;

  // Unique gradient ID
  const gradId = `chart-grad-${colorTheme}-${Math.floor(Math.random() * 10000)}`;

  let strokeColor = "#00f0ff";
  let gradStop1 = "rgba(0, 240, 255, 0.35)";
  let gradStop2 = "rgba(0, 240, 255, 0.0)";

  if (colorTheme === "indigo") {
    strokeColor = "#818cf8";
    gradStop1 = "rgba(129, 140, 248, 0.32)";
    gradStop2 = "rgba(129, 140, 248, 0.0)";
  } else if (colorTheme === "emerald") {
    strokeColor = "#10e79d";
    gradStop1 = "rgba(16, 231, 157, 0.32)";
    gradStop2 = "rgba(16, 231, 157, 0.0)";
  }

  // Generate data point circles for current & peak
  const lastPoint = points[points.length - 1].split(",");

  return `
    <svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" role="img" aria-label="Cyber usage trend chart" class="cyber-svg-chart">
      <defs>
        <linearGradient id="${gradId}" x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" stop-color="${gradStop1}" />
          <stop offset="100%" stop-color="${gradStop2}" />
        </linearGradient>
        <filter id="glow-${gradId}" x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur stdDeviation="3" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>
      <line class="chart-grid-line" x1="${paddingX}" y1="${height * 0.25}" x2="${width - paddingX}" y2="${height * 0.25}" />
      <line class="chart-grid-line" x1="${paddingX}" y1="${height * 0.5}" x2="${width - paddingX}" y2="${height * 0.5}" />
      <line class="chart-grid-line" x1="${paddingX}" y1="${height * 0.75}" x2="${width - paddingX}" y2="${height * 0.75}" />
      <polygon class="chart-area" points="${area}" fill="url(#${gradId})" />
      <polyline class="chart-line" points="${line}" stroke="${strokeColor}" filter="url(#glow-${gradId})" />
      <circle cx="${lastPoint[0]}" cy="${lastPoint[1]}" r="4.5" fill="${strokeColor}" class="chart-pulse-point" />
      <circle cx="${lastPoint[0]}" cy="${lastPoint[1]}" r="2" fill="#ffffff" />
    </svg>
  `;
}

/* ==========================================================================
   6. Multi-Series History Chart Generator
   ========================================================================== */
function setupHistoryChart() {
  if (!window.HISTORY_METRICS_DATA || !Array.isArray(window.HISTORY_METRICS_DATA)) {
    return;
  }
  const chartEl = document.getElementById("history-chart");
  if (!chartEl) return;

  const data = window.HISTORY_METRICS_DATA.slice().reverse();
  const cpuPoints = data.map((d) => d.cpu_usage);
  const memPoints = data.map((d) => d.memory_usage);
  const diskPoints = data.map((d) => d.storage_usage);

  if (cpuPoints.length === 0) return;

  chartEl.innerHTML = buildMultiSeriesChart(cpuPoints, memPoints, diskPoints);
}

function buildMultiSeriesChart(cpuSeries, memSeries, diskSeries) {
  const width = 640;
  const height = 210;
  const paddingX = 18;
  const paddingY = 20;
  const maxVal = 100;
  const len = Math.max(cpuSeries.length, 1);
  const stepX = (width - paddingX * 2) / Math.max(len - 1, 1);

  function makePoints(values) {
    return values
      .map((val, idx) => {
        const x = paddingX + idx * stepX;
        const y = height - paddingY - (Math.min(val, maxVal) / maxVal) * (height - paddingY * 2);
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(" ");
  }

  const cpuPoly = makePoints(cpuSeries);
  const memPoly = makePoints(memSeries);
  const diskPoly = makePoints(diskSeries);

  return `
    <svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" role="img" aria-label="History trends chart" class="cyber-svg-chart">
      <line class="chart-grid-line" x1="${paddingX}" y1="${height * 0.2}" x2="${width - paddingX}" y2="${height * 0.2}" />
      <line class="chart-grid-line" x1="${paddingX}" y1="${height * 0.4}" x2="${width - paddingX}" y2="${height * 0.4}" />
      <line class="chart-grid-line" x1="${paddingX}" y1="${height * 0.6}" x2="${width - paddingX}" y2="${height * 0.6}" />
      <line class="chart-grid-line" x1="${paddingX}" y1="${height * 0.8}" x2="${width - paddingX}" y2="${height * 0.8}" />
      <polyline class="chart-line-disk" points="${diskPoly}" />
      <polyline class="chart-line-mem" points="${memPoly}" />
      <polyline class="chart-line-cpu" points="${cpuPoly}" />
    </svg>
  `;
}
