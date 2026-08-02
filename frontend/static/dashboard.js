"use strict";

/* Dashboard: fetches GET /stats and renders it as plain HTML/CSS bar charts
 * -- no charting library, consistent with the rest of the frontend having no
 * build step and no runtime dependency beyond the two Google Fonts already
 * loaded by every other page. escapeHtml comes from common.js. */

const esc = escapeHtml;

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
const SEV_VAR = {
    critical: "var(--sev-critical)", high: "var(--sev-high)",
    medium: "var(--sev-medium)", low: "var(--sev-low)", info: "var(--sev-info)",
};

const STATUS_LABEL = { open: "Open", closed: "Closed", false_positive: "False positive" };
const STATUS_VAR = {
    open: "var(--struct)", closed: "var(--text-mute)", false_positive: "var(--sev-high)",
};

let currentDays = 14;

async function load(days) {
    currentDays = days;
    let data;
    try {
        const r = await fetch(`/stats?days=${days}`);
        if (!r.ok) throw new Error(String(r.status));
        data = await r.json();
    } catch {
        document.querySelectorAll(".db-body").forEach((el) => {
            el.innerHTML = `<div class="db-empty">Failed to load stats.</div>`;
        });
        return;
    }
    render(data);
}

function render(data) {
    renderTotals(data.totals);
    renderTimeChart(data.incidents_per_day);
    renderSeverityChart(data.severity_distribution, data.totals.incidents);
    renderStatusChart(data.totals);
    renderBarList("rules-chart", data.top_rules, {
        key: "rule_id", count: "count",
        renderLabel: (row) => `
            <span>${esc(row.rule_id)}</span>
            <span class="db-rule-title">${esc(row.title)}</span>`,
    });
    renderBarList("technique-chart", data.top_techniques, {
        key: "technique_id", count: "count",
        renderLabel: (row) => {
            const url = `https://attack.mitre.org/techniques/${row.technique_id.replace(".", "/")}`;
            return `<a href="${esc(url)}" target="_blank" rel="noopener">${esc(row.technique_id)}</a>
                    <span class="db-rule-title">${esc(row.name)}</span>`;
        },
    });
}

function renderTotals(totals) {
    document.getElementById("t-incidents").textContent = totals.incidents;
    document.getElementById("t-detections").textContent = totals.detections;
    document.getElementById("t-actionable").textContent = totals.actionable_open;
    document.getElementById("t-closed").textContent = totals.closed;
    document.getElementById("t-fp").textContent = totals.false_positive;
}

function renderTimeChart(series) {
    const el = document.getElementById("time-chart");
    if (!series || series.length === 0) {
        el.innerHTML = `<div class="db-empty">No incidents recorded yet.</div>`;
        return;
    }
    const max = Math.max(1, ...series.map((d) => d.count));
    const showEveryLabel = series.length <= 14;
    const labelStep = showEveryLabel ? 1 : Math.ceil(series.length / 8);

    const bars = series.map((d) => {
        const pct = Math.max(2, Math.round((d.count / max) * 100));
        return `<div class="db-time-col">
            <div class="db-time-bar" style="height:${pct}%" title="${esc(d.date)}: ${d.count} incident${d.count === 1 ? "" : "s"}"></div>
        </div>`;
    }).join("");

    const labels = series.map((d, i) => {
        const show = i === 0 || i === series.length - 1 || i % labelStep === 0;
        return `<span style="flex:1;text-align:center;overflow:hidden">${show ? esc(d.date.slice(5)) : ""}</span>`;
    }).join("");

    el.innerHTML = `
        <div class="db-timechart">${bars}</div>
        <div class="db-time-labels">${labels}</div>`;
}

function renderSeverityChart(distribution, total) {
    const el = document.getElementById("severity-chart");
    const byKey = Object.fromEntries((distribution || []).map((d) => [d.severity, d.count]));
    if (!total) {
        el.innerHTML = `<div class="db-empty">No incidents recorded yet.</div>`;
        return;
    }
    const max = Math.max(1, ...SEV_ORDER.map((s) => byKey[s] || 0));
    el.innerHTML = SEV_ORDER.map((sev) => {
        const count = byKey[sev] || 0;
        const pct = Math.max(count > 0 ? 2 : 0, Math.round((count / max) * 100));
        return `<div class="db-hrow">
            <div class="db-hrow-label">${SEV_LABEL[sev]}</div>
            <div class="db-hrow-track"><div class="db-hrow-bar" style="width:${pct}%;background:${SEV_VAR[sev]}"></div></div>
            <div class="db-hrow-count">${count}</div>
        </div>`;
    }).join("");
}

function renderStatusChart(totals) {
    const el = document.getElementById("status-chart");
    if (!totals.incidents) {
        el.innerHTML = `<div class="db-empty">No incidents recorded yet.</div>`;
        return;
    }
    const rows = [
        { key: "open", count: totals.open },
        { key: "closed", count: totals.closed },
        { key: "false_positive", count: totals.false_positive },
    ];
    const max = Math.max(1, ...rows.map((r) => r.count));
    el.innerHTML = rows.map(({ key, count }) => {
        const pct = Math.max(count > 0 ? 2 : 0, Math.round((count / max) * 100));
        return `<div class="db-hrow">
            <div class="db-hrow-label">${STATUS_LABEL[key]}</div>
            <div class="db-hrow-track"><div class="db-hrow-bar" style="width:${pct}%;background:${STATUS_VAR[key]}"></div></div>
            <div class="db-hrow-count">${count}</div>
        </div>`;
    }).join("");
}

function renderBarList(elementId, rows, opts) {
    const el = document.getElementById(elementId);
    if (!rows || rows.length === 0) {
        el.innerHTML = `<div class="db-empty">No detections recorded yet.</div>`;
        return;
    }
    const max = Math.max(1, ...rows.map((r) => r[opts.count]));
    el.innerHTML = rows.map((row) => {
        const count = row[opts.count];
        const pct = Math.max(2, Math.round((count / max) * 100));
        return `<div class="db-hrow">
            <div class="db-hrow-label">${opts.renderLabel(row)}</div>
            <div class="db-hrow-track"><div class="db-hrow-bar" style="width:${pct}%"></div></div>
            <div class="db-hrow-count">${count}</div>
        </div>`;
    }).join("");
}

document.getElementById("range-filters").addEventListener("click", (e) => {
    const btn = e.target.closest(".filter");
    if (!btn) return;
    document.querySelectorAll("#range-filters .filter").forEach((b) => b.setAttribute("aria-pressed", "false"));
    btn.setAttribute("aria-pressed", "true");
    load(Number(btn.dataset.days));
});

load(currentDays);
