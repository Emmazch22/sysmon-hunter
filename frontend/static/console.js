"use strict";

/* ============================================================
   Sysmon Hunter console

   Two data paths that must agree:
     - On load, history is replayed from SQLite over REST.
     - While open, the engine pushes new objects over WebSocket.
   Both deliver the identical JSON shape (see backend/api/serializers.py),
   so a rendered row cannot tell which path it arrived on.
   ============================================================ */

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const SEVERITY_COLOR = {
    critical: "var(--sev-critical)",
    high: "var(--sev-high)",
    medium: "var(--sev-medium)",
    low: "var(--sev-low)",
    info: "var(--sev-info)",
};

const state = {
    incidents: new Map(),   // id -> incident. A Map because incidents are updated
    // in place as new detections land on them.
    detections: [],         // append-only stream, oldest first
    expanded: new Set(),    // incident ids currently drilled into
    scope: "triage",        // "triage" (actionable only) or "all"
};

const $ = (id) => document.getElementById(id);

/* ---------- Helpers ---------- */

/** Escape untrusted strings before they touch innerHTML.
 *  Command lines are attacker-controlled by definition: an operator who names
 *  a process `<img onerror=...>` should not get script execution in the SOC. */
function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, (c) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
}

/** Reduce a full Windows path to the executable name. */
function baseName(path) {
    if (!path) return "unknown";
    const parts = String(path).split(/[\\/]/);
    return parts[parts.length - 1] || String(path);
}

function clockTime(iso) {
    const date = iso ? new Date(iso) : new Date();
    return date.toLocaleTimeString("en-GB", { hour12: false });
}

/** Pick an icon for a detection by its rule family.
 *
 *  The prefix encodes the detector: BCN is the beacon engine, DSC the discovery
 *  engine, everything else a YAML rule. Giving each family a glyph lets an
 *  analyst tell a statistical finding from a rule match at a glance, before
 *  reading a word -- a beacon and an Office-macro detection want different
 *  mental models, and the icon cues which one applies.
 */
function detectionIcon(ruleId) {
    const id = String(ruleId || "");
    if (id.startsWith("BCN")) return "i-beacon";
    if (id.startsWith("DSC")) return "i-recon";
    return "i-process";
}

/* ---------- Rendering: incidents ---------- */

function incidentHtml(incident, isFresh) {
    const severity = incident.severity || "medium";
    const expanded = state.expanded.has(incident.id);

    const chain = (incident.chain || []).length
        ? incident.chain
            .map(escapeHtml)
            .join('<span class="arrow">&#9656;</span>')
            .replace(/^/, "<span class='proc'>")
            .replace(/<span class="arrow">&#9656;<\/span>/g,
                "</span><span class='arrow'>&#9656;</span><span class='proc'>")
            .concat("</span>")
        : "<span class='proc'>chain unknown</span>";

    const techniques = (incident.techniques || [])
        .map((t) => `<span class="chip" data-technique="${escapeHtml(t)}" role="button" tabindex="0">${escapeHtml(t)}</span>`)
        .join("");

    const badge = incident.actionable
        ? `<span class="sev-tag"><svg class="ico"><use href="#i-alert"/></svg>${escapeHtml(severity)}</span>`
        : `<span class="watch">watching</span>`;

    const members = expanded ? membersHtml(incident) : "";

    return `
    <article class="inc${isFresh ? " fresh" : ""}" data-sev="${escapeHtml(severity)}">
      <div class="spine"></div>
      <div class="inc-body">
        <div class="inc-top">
          <span class="inc-id">${escapeHtml(incident.id)}</span>
          ${badge}
          <span class="inc-host">${escapeHtml(incident.host)}</span>
          <span class="inc-score">
            <b>${incident.score}</b><span>score</span>
          </span>
        </div>

        <div class="chain">${chain}</div>

        <div class="inc-meta">
          <span>${incident.detection_count} detection${incident.detection_count === 1 ? "" : "s"}</span>
          <span>${clockTime(incident.first_seen)} &ndash; ${clockTime(incident.last_seen)}</span>
          <div class="chips">${techniques}</div>
          <button class="drill" data-incident="${escapeHtml(incident.id)}">
            ${expanded ? "Hide detections" : "Show detections"}
          </button>
        </div>

        ${members}
      </div>
    </article>`;
}

/** Member detections of an incident, fetched on demand.
 *  Rendered from whatever is cached; the fetch fills it in and re-renders. */
function membersHtml(incident) {
    if (!incident._members) {
        return `<div class="members"><div class="member">
              <span class="member-title">Loading detections&hellip;</span>
            </div></div>`;
    }
    const rows = incident._members.map((d) => `
    <div class="member" data-sev="${escapeHtml(d.severity)}">
      <svg class="ico" style="color:var(--sev)"><use href="#${detectionIcon(d.rule_id)}"/></svg>
      <span class="member-id">${escapeHtml(d.rule_id)}</span>
      <span class="member-title">${escapeHtml(d.title)}</span>
      <span class="member-time">${clockTime(d.matched_at)}</span>
      ${d.command_line ? `<div class="cmd">${escapeHtml(d.command_line)}</div>` : ""}
      ${evidenceHtml(d)}
    </div>`).join("");
    return `<div class="members">${rows}</div>`;
}

/** Render the evidence panel for a detection that carries one.
 *
 *  Rule-based detections leave `evidence` empty — the rule is its own evidence,
 *  so there is nothing to show and this returns nothing. Statistical detections
 *  (beacon, discovery burst) fill it with the numbers behind the call, and the
 *  shape differs per detector, so this dispatches on which keys are present
 *  rather than on a type tag. That keeps a new detector's evidence renderable
 *  the moment it ships, without a matching enum to update here.
 */
function evidenceHtml(detection) {
    const evidence = detection.evidence;
    if (!evidence || Object.keys(evidence).length === 0) return "";

    // Beacon: periodicity metrics plus a regularity gauge.
    if ("regularity" in evidence) {
        const pct = Math.round((evidence.regularity ?? 0) * 100);
        return `
      <div class="evidence">
        <div class="evidence-head">Beacon analysis</div>
        <div class="metrics">
          ${metric(evidence.median_interval_seconds + "s", "Interval")}
          ${metric("±" + evidence.jitter_seconds + "s", "Jitter")}
          ${metric(evidence.connections, "Callbacks")}
          ${metric(pct + "%", "Regularity", true)}
        </div>
        <div class="gauge">
          <div class="gauge-track">
            <div class="gauge-fill" style="width:${pct}%"></div>
          </div>
        </div>
        <div class="evidence-list">
          <div class="row">${escapeHtml(evidence.destination)} · over ${evidence.observed_over_seconds}s</div>
        </div>
      </div>`;
    }

    // Discovery burst: distinct-technique count plus the sample commands.
    if ("distinct_techniques" in evidence) {
        const commands = (evidence.commands || [])
            .map((c) => `<div class="row">${escapeHtml(c)}</div>`)
            .join("");
        const techniques = (evidence.techniques || [])
            .map((t) => `<span class="chip" data-technique="${escapeHtml(t)}" role="button" tabindex="0">${escapeHtml(t)}</span>`)
            .join("");
        return `
      <div class="evidence">
        <div class="evidence-head">Reconnaissance analysis</div>
        <div class="metrics">
          ${metric(evidence.distinct_techniques, "Distinct techniques", true)}
          ${metric(evidence.span_seconds + "s", "Time span")}
        </div>
        <div class="techniques-inline">${techniques}</div>
        <div class="evidence-list" style="margin-top:8px">${commands}</div>
      </div>`;
    }

    return "";
}

/** One label/value cell in the metrics grid. */
function metric(value, label, accent = false) {
    return `
    <div class="metric">
      <span class="metric-value${accent ? " accent" : ""}">${escapeHtml(value)}</span>
      <span class="metric-label">${escapeHtml(label)}</span>
    </div>`;
}

function visibleIncidents() {
    const all = [...state.incidents.values()];
    const scoped = state.scope === "triage" ? all.filter((i) => i.actionable) : all;
    // Newest first: the analyst wants the freshest thing at the top of the queue.
    return scoped.sort((a, b) => new Date(b.last_seen) - new Date(a.last_seen));
}

function renderQueue(freshId = null) {
    const list = visibleIncidents();
    $("queue-count").textContent = list.length;

    if (!list.length) {
        const triaging = state.scope === "triage";
        $("queue").innerHTML = `
      <div class="empty">
        <div class="empty-mark">${triaging ? "Queue is clear" : "No incidents"}</div>
        <p>${triaging
                ? "Nothing has crossed the triage threshold. Switch to <b>All</b> to see what the engine is watching."
                : "The engine is listening. Send telemetry to <code>POST /ingest</code>, or fire an atomic on the lab VM."}</p>
      </div>`;
        return;
    }

    $("queue").innerHTML = list.map((i) => incidentHtml(i, i.id === freshId)).join("");

    $("queue").querySelectorAll(".drill").forEach((button) => {
        button.addEventListener("click", () => toggleDrill(button.dataset.incident));
    });
}

/** Expand or collapse an incident, fetching its detections the first time. */
async function toggleDrill(incidentId) {
    if (state.expanded.has(incidentId)) {
        state.expanded.delete(incidentId);
        renderQueue();
        return;
    }

    state.expanded.add(incidentId);
    renderQueue();

    const incident = state.incidents.get(incidentId);
    if (!incident || incident._members) return;

    try {
        const detail = await fetch(`/incidents/${incidentId}`).then((r) => r.json());
        incident._members = detail.detections || [];
    } catch {
        incident._members = [];
    }
    renderQueue();
}

/* ---------- Rendering: detection stream ---------- */

function renderStream(freshCount = 0) {
    const recent = state.detections.slice(-60).reverse();
    $("stream-count").textContent = state.detections.length;

    if (!recent.length) {
        $("stream").innerHTML = `<div class="empty empty-sm"><p>Nothing yet.</p></div>`;
        return;
    }

    $("stream").innerHTML = recent.map((d, index) => `
    <article class="det${index < freshCount ? " fresh" : ""}" data-sev="${escapeHtml(d.severity)}">
      <div class="spine"></div>
      <div class="det-body">
        <div class="det-top">
          <svg class="ico" style="color:var(--sev)"><use href="#${detectionIcon(d.rule_id)}"/></svg>
          <span class="det-id">${escapeHtml(d.rule_id)}</span>
          <span class="det-time">${clockTime(d.matched_at)}</span>
        </div>
        <div class="det-title" title="${escapeHtml(d.title)}">
          ${escapeHtml(baseName(d.parent_image))} &#9656; ${escapeHtml(baseName(d.image))}
        </div>
      </div>
    </article>`).join("");
}

/* ---------- Rendering: aggregates ---------- */

function renderStats() {
    const incidents = [...state.incidents.values()];
    const actionable = incidents.filter((i) => i.actionable);
    const hosts = new Set(incidents.map((i) => i.host).filter((h) => h && h !== "unknown"));

    const techniqueCounts = {};
    for (const detection of state.detections) {
        for (const technique of detection.attack || []) {
            techniqueCounts[technique] = (techniqueCounts[technique] || 0) + 1;
        }
    }

    $("s-incidents").textContent = incidents.length;
    $("s-actionable").textContent = actionable.length;
    $("s-actionable").classList.toggle("alarm", actionable.length > 0);
    $("s-detections").textContent = state.detections.length;
    $("s-hosts").textContent = hosts.size;
    $("s-techniques").textContent = Object.keys(techniqueCounts).length;

    if (state.detections.length) {
        $("s-last").textContent = clockTime(state.detections[state.detections.length - 1].matched_at);
    }

    // Severity distribution across detections, not incidents: this panel answers
    // "what is the engine seeing", while the queue answers "what should I do".
    const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
    for (const detection of state.detections) {
        const severity = (detection.severity || "medium").toLowerCase();
        if (severity in counts) counts[severity] += 1;
    }
    const peak = Math.max(1, ...Object.values(counts));

    $("bars").innerHTML = SEVERITIES.map((severity) => `
    <div class="bar-row">
      <span class="bar-label">${severity}</span>
      <div class="bar-track">
        <div class="bar-fill"
             style="--c:${SEVERITY_COLOR[severity]};width:${(counts[severity] / peak) * 100}%"></div>
      </div>
      <span class="bar-count">${counts[severity]}</span>
    </div>`).join("");

    const ranked = Object.entries(techniqueCounts).sort((a, b) => b[1] - a[1]).slice(0, 12);
    $("techniques").innerHTML = ranked.length
        ? ranked.map(([id, count]) => `
        <div class="tech-row">
          <span class="tech-id">${escapeHtml(id)}</span>
          <span class="tech-n">${count}</span>
        </div>`).join("")
        : `<div class="empty empty-sm"><p>None observed.</p></div>`;
}

/* ---------- Data ---------- */

/** Replay history from the database so a reload does not look like a fresh start. */
async function bootstrap() {
    try {
        const [health, incidents, detections] = await Promise.all([
            fetch("/health").then((r) => r.json()),
            fetch("/incidents?limit=200").then((r) => r.json()),
            fetch("/detections?limit=300").then((r) => r.json()),
        ]);

        $("engine").textContent =
            `engine: ${health.rules_loaded} rules \u00b7 ${health.processes_tracked} processes tracked`;

        for (const incident of incidents.items || []) {
            state.incidents.set(incident.id, incident);
        }
        state.detections = detections.items || [];

        renderQueue();
        renderStream();
        renderStats();
    } catch {
        $("engine").textContent = "engine: unreachable";
    }
}

/** Live feed. Reconnects on drop, because the console is expected to sit open
 *  on a wall display for days and a transient blip must not require a reload. */
function connect() {
    const scheme = location.protocol === "https:" ? "wss" : "ws";
    const socket = new WebSocket(`${scheme}://${location.host}/ws`);

    socket.onopen = () => {
        $("led").className = "led on";
        $("link-state").textContent = "live";
    };

    socket.onmessage = (message) => {
        const { type, data } = JSON.parse(message.data);

        if (type === "detection") {
            state.detections.push(data);
            renderStream(1);
        } else if (type === "incident") {
            // Preserve any already-fetched member list across the update, otherwise
            // an expanded incident collapses to a spinner every time it grows.
            const existing = state.incidents.get(data.id);
            if (existing?._members) {
                data._members = undefined;  // stale: refetch on next expand
            }
            state.incidents.set(data.id, data);
            renderQueue(data.id);
        }
        renderStats();
    };

    socket.onclose = () => {
        $("led").className = "led off";
        $("link-state").textContent = "reconnecting";
        setTimeout(connect, 3000);
    };

    socket.onerror = () => socket.close();
}

/* ---------- Controls ---------- */

document.querySelectorAll(".filter").forEach((button) => {
    button.addEventListener("click", () => {
        state.scope = button.dataset.scope;
        document.querySelectorAll(".filter").forEach((other) => {
            other.setAttribute("aria-pressed", String(other === button));
        });
        renderQueue();
    });
});

bootstrap();
connect();

/* ============================================================
   Technique detail modal

   Technique chips are regenerated on every render, so their click handling uses
   event delegation on the document rather than per-chip listeners that would be
   lost on the next repaint. Descriptions are fetched from /attack/{id} and
   cached: a technique's definition does not change between clicks, so the second
   open is instant and makes no request.
   ============================================================ */

const techniqueCache = new Map();

function techModalEls() {
    return {
        overlay: document.getElementById("tech-overlay"),
        id: document.getElementById("tech-id"),
        name: document.getElementById("tech-name"),
        tactics: document.getElementById("tech-tactics"),
        body: document.getElementById("tech-body"),
        link: document.getElementById("tech-link"),
    };
}

async function openTechnique(techniqueId) {
    const el = techModalEls();

    // Show the shell immediately with a loading state, so the panel appears the
    // instant the analyst clicks rather than after the network round trip.
    el.id.textContent = techniqueId;
    el.name.textContent = "";
    el.tactics.innerHTML = "";
    el.body.textContent = "Loading technique detail\u2026";
    el.body.classList.add("loading");
    el.link.href = `https://attack.mitre.org/techniques/${techniqueId.replace(".", "/")}`;
    el.overlay.classList.add("open");
    document.getElementById("tech-close").focus();

    let data = techniqueCache.get(techniqueId);
    if (!data) {
        try {
            const response = await fetch(`/attack/${techniqueId}`);
            if (!response.ok) throw new Error(String(response.status));
            data = await response.json();
            techniqueCache.set(techniqueId, data);
        } catch {
            el.body.classList.remove("loading");
            el.body.textContent =
                "No description available for this technique. Open it on the ATT&CK site below.";
            return;
        }
    }

    // Guard against a fast analyst clicking a second chip before the first
    // resolves: only paint if this technique is still the one on screen.
    if (el.id.textContent !== techniqueId) return;

    el.name.textContent = data.name || techniqueId;
    el.tactics.innerHTML = (data.tactics || [])
        .map((t) => `<span class="tactic">${escapeHtml(t.replace(/-/g, " "))}</span>`)
        .join("");
    el.body.classList.remove("loading");
    el.body.textContent = data.description || "No description provided.";
    if (data.url) el.link.href = data.url;
}

function closeTechnique() {
    document.getElementById("tech-overlay").classList.remove("open");
}

// Delegated activation: click, or Enter/Space on a focused chip.
document.addEventListener("click", (event) => {
    const chip = event.target.closest("[data-technique]");
    if (chip) openTechnique(chip.dataset.technique);
});
document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeTechnique();
    const chip = event.target.closest?.("[data-technique]");
    if (chip && (event.key === "Enter" || event.key === " ")) {
        event.preventDefault();
        openTechnique(chip.dataset.technique);
    }
});

// Close on overlay backdrop click or the close button.
document.addEventListener("DOMContentLoaded", () => {
    const overlay = document.getElementById("tech-overlay");
    overlay.addEventListener("click", (event) => {
        if (event.target === overlay) closeTechnique();
    });
    document.getElementById("tech-close").addEventListener("click", closeTechnique);
});