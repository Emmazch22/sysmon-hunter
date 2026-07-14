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
    viewFor: new Map(),     // incidentId -> "list" | "timeline" | "tree"
    timelineNode: new Map(), // incidentId -> index of the expanded timeline node
    scope: "triage",        // "triage" (actionable only) or "all"
    searchQuery: "",        // active search text; empty means no search
    searchResults: null,    // array of incident ids matching the search, or null when not searching
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

/* ============================================================
   Base64 decoding

   Attackers hide payloads in base64 constantly -- PowerShell -enc, encoded
   commands, config blobs. When a command line contains a base64 run, a small
   "decode" button is shown next to it; clicking it decodes and shows the result
   in a popup. Decoding is client-side: it is analysis, not something the server
   needs to do.
   ============================================================ */

const B64_RE = /[A-Za-z0-9+/]{16,}={0,2}/g;

/** Is this substring plausibly base64 worth offering to decode? Rejects hashes,
 *  low-variety padding, and anything not a clean base64 run. */
function looksLikeBase64(s) {
    if (s.length < 16 || s.length % 4 !== 0) return false;
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(s)) return false;
    if (/^[0-9a-f]+$/i.test(s) && s.length <= 64) return false;  // likely a hash
    if (new Set(s).size < 8) return false;                        // e.g. AAAA...
    return true;
}

/** Decode a base64 string, auto-detecting UTF-16LE (PowerShell -enc) vs UTF-8.
 *  Returns {text, printable, isUtf16} or null on failure. */
function decodeBase64(s) {
    try {
        const bytes = Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
        let nulls = 0;
        for (let i = 1; i < bytes.length; i += 2) if (bytes[i] === 0) nulls++;
        const isUtf16 = bytes.length > 4 && nulls > bytes.length / 4;
        const text = isUtf16
            ? new TextDecoder("utf-16le").decode(bytes)
            : new TextDecoder("utf-8", { fatal: false }).decode(bytes);
        const printable = [...text].filter((c) => {
            const code = c.charCodeAt(0);
            return code === 9 || code === 10 || code === 13 || (code >= 32 && code < 127) || code > 160;
        }).length;
        return { text, printable: printable / (text.length || 1) > 0.8, isUtf16 };
    } catch {
        return null;
    }
}

/** Find every base64 run in a string worth offering to decode. */
function findBase64(text) {
    const hits = [];
    for (const m of String(text).matchAll(B64_RE)) {
        if (looksLikeBase64(m[0])) hits.push(m[0]);
    }
    return hits;
}

// Cache of base64 strings by a short id, so the click handler can retrieve the
// full value without stuffing it into a DOM attribute.
const b64Cache = new Map();
let b64Counter = 0;

/** Render a command line, escaped, with a "decode" button after each base64 run
 *  it contains. Use this everywhere a command line is shown. */
function renderCommand(text) {
    const escaped = escapeHtml(text);
    const hits = findBase64(text);
    if (!hits.length) return escaped;

    // Append one decode button per distinct base64 run found.
    const buttons = [...new Set(hits)].map((b64) => {
        const id = "b64_" + (b64Counter++);
        b64Cache.set(id, b64);
        return `<button class="b64-btn" data-b64="${id}" title="Decode base64">&#9660; decode</button>`;
    }).join("");

    return `${escaped} ${buttons}`;
}

/** Word count for the notes limit -- splits on whitespace, ignoring empties. */
function countWords(text) {
    const t = String(text || "").trim();
    return t ? t.split(/\s+/).length : 0;
}

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
          ${badge}
          <span class="inc-name">${escapeHtml(incident.title || "Suspicious activity")}</span>
          <span class="inc-score">
            <b>${incident.score}</b><span>score</span>
          </span>
        </div>
        <div class="inc-sub">
          <span class="inc-id">${escapeHtml(incident.id)}</span>
          <span class="inc-host">${escapeHtml(incident.host)}</span>
        </div>

        <div class="chain">${chain}</div>

        <div class="inc-meta">
          <span>${incident.detection_count} detection${incident.detection_count === 1 ? "" : "s"}</span>
          <span>${clockTime(incident.first_seen)} &ndash; ${clockTime(incident.last_seen)}</span>
          <div class="chips">${techniques}</div>
          <button class="drill" data-incident="${escapeHtml(incident.id)}">
            ${expanded ? "Hide detections" : "Show detections"}
          </button>
          <a class="open-tab" href="/incident/${escapeHtml(incident.id)}" target="_blank" rel="noopener" title="Open full incident view in a new tab" aria-label="Open in new tab">
            <svg class="ico"><use href="#i-external"/></svg>
          </a>
        </div>

        ${members}
      </div>
    </article>`;
}

/** Build an SVG timeline of an incident's detections.
 *
 *  A horizontal spine with one node per detection in chronological order. The
 *  design choice: position is *sequential*, not proportional to wall-clock time,
 *  with the real gap printed between nodes. Proportional spacing collapses
 *  detections that fired seconds apart -- which in an attack chain is most of
 *  them -- into an unreadable pile. An analyst reading a chain wants the order
 *  and the pauses ("then, 19 minutes later..."), and this shows both without
 *  losing the fast steps.
 *
 *  Nodes inherit severity colour; criticals get a halo. It is the same picture
 *  an analyst sketches on paper during triage.
 */
function timelineSvg(detections, incidentId) {
    if (!detections.length) return "";

    const sorted = [...detections].sort(
        (a, b) => new Date(a.matched_at) - new Date(b.matched_at)
    );

    const rowH = 46;
    const spineX = 120;
    const width = 440;
    const top = 14;
    const height = top + sorted.length * rowH + 10;
    const y = (i) => top + i * rowH + rowH / 2;

    // Which node, if any, is expanded on this incident's timeline.
    const selected = state.timelineNode.get(incidentId);

    let svg = `<svg viewBox="0 0 ${width} ${height}" xmlns="http://www.w3.org/2000/svg" class="timeline-svg" role="img" aria-label="Incident timeline">`;
    svg += `<line x1="${spineX}" y1="${y(0)}" x2="${spineX}" y2="${y(sorted.length - 1)}" stroke="var(--border-hi)" stroke-width="1"/>`;

    sorted.forEach((d, i) => {
        const sev = (d.severity || "medium").toLowerCase();
        const color = `var(--sev-${sev})`;
        const cy = y(i);
        const isSelected = selected === i;

        if (i > 0) {
            const gapMs = new Date(d.matched_at) - new Date(sorted[i - 1].matched_at);
            const gap = humanGap(gapMs);
            if (gap) {
                svg += `<text x="${spineX}" y="${cy - rowH / 2 + 3}" fill="var(--text-mute)" font-size="8" font-family="monospace" text-anchor="middle">+${escapeHtml(gap)}</text>`;
            }
        }

        svg += `<text x="${spineX - 18}" y="${cy + 3}" fill="var(--text-mute)" font-size="9" font-family="monospace" text-anchor="end">${clockTime(d.matched_at)}</text>`;

        // Selected node gets a filled halo; criticals always get a faint one.
        if (isSelected) {
            svg += `<circle cx="${spineX}" cy="${cy}" r="10" fill="none" stroke="${color}" stroke-width="1.5"/>`;
        } else if (sev === "critical") {
            svg += `<circle cx="${spineX}" cy="${cy}" r="9" fill="none" stroke="${color}" stroke-width="1" opacity="0.4"/>`;
        }
        svg += `<circle cx="${spineX}" cy="${cy}" r="5" fill="${color}"/>`;

        svg += `<text x="${spineX + 16}" y="${cy - 2}" fill="${color}" font-size="11" font-weight="700" font-family="monospace">${escapeHtml(d.rule_id)}</text>`;
        svg += `<text x="${spineX + 16}" y="${cy + 11}" fill="var(--text-dim)" font-size="9" font-family="monospace">${escapeHtml(baseName(d.image))}</text>`;

        // A transparent hit area spanning the whole row, so the click target is the
        // entire band, not just the 5px dot. The chevron hints it is expandable.
        svg += `<rect x="0" y="${cy - rowH / 2}" width="${width}" height="${rowH}" fill="transparent" style="cursor:pointer" data-timeline-node="${i}" data-incident="${escapeHtml(incidentId)}"><title>Click for detail</title></rect>`;
        svg += `<text x="${width - 8}" y="${cy + 3}" fill="var(--text-mute)" font-size="10" text-anchor="end" style="pointer-events:none">${isSelected ? "\u25be" : "\u203a"}</text>`;
    });

    svg += `</svg>`;

    // Detail popup for the selected node, floated to the right of its row rather
    // than pushed below the timeline, so the sequence stays in view while an
    // analyst reads one step. Positioned by the node's vertical offset.
    let popup = "";
    if (selected != null && sorted[selected]) {
        const nodeY = y(selected);
        // As a fraction of the SVG height, so it tracks the node when the SVG scales.
        const topPct = (nodeY / height) * 100;
        popup = `<div class="tl-popup-anchor" style="top:${topPct}%">${timelineDetail(sorted[selected])}</div>`;
    }

    return `<div class="timeline-wrap"><div class="timeline-svg-col">${svg}</div>${popup}</div>`;
}

/** The expandable detail for one timeline node: the full forensic picture of
 *  that detection -- command line, user, privileges, parent process, hashes.
 *  This is what turns the timeline from a picture into an investigation tool:
 *  click a step, see exactly what ran and as whom. */
function timelineDetail(d) {
    const f = d.forensics || {};
    const rows = [];

    const push = (label, value) => {
        if (value) rows.push(
            `<div class="tl-detail-row"><span class="tl-detail-key">${escapeHtml(label)}</span>` +
            `<span class="tl-detail-val">${escapeHtml(value)}</span></div>`
        );
    };

    push("Rule", `${d.rule_id} — ${d.title || ""}`);
    push("Time", fmtFullTime(d.matched_at));
    push("Process", d.image);
    push("Parent", d.parent_image);
    push("User", f.user);
    push("Integrity", f.integrity_level);
    push("PID", f.process_id);
    push("Parent PID", f.parent_process_id);
    push("Working dir", f.current_directory);
    push("Logon ID", f.logon_id);
    push("Session", f.session_id);
    push("Destination", f.destination_ip ? `${f.destination_ip}:${f.destination_port || "?"}` + (f.destination_hostname ? ` (${f.destination_hostname})` : "") : "");
    push("Target", f.target_image);
    push("Access", f.granted_access);
    push("Registry key", f.registry_key);
    push("Named pipe", f.pipe_name);
    push("DNS query", f.dns_query);

    const cmd = d.command_line
        ? `<div class="tl-detail-cmd">${renderCommand(d.command_line)}</div>` : "";
    const parentCmd = f.parent_command_line
        ? `<div class="tl-detail-parentcmd"><span class="tl-detail-key">Parent cmd</span>${renderCommand(f.parent_command_line)}</div>` : "";
    // Hashes get a "Check" button: the strongest hash present is looked up on
    // VirusTotal. A flagged hash is the strongest signal the tool can surface --
    // it turns "a process ran" into "a known-malicious binary executed".
    let hashes = "";
    if (f.hashes) {
        const best = bestHash(f.hashes);
        hashes = `
      <div class="tl-detail-row" style="grid-column:1/-1">
        <span class="tl-detail-key">Hashes</span>
        <span class="tl-detail-val hash">${escapeHtml(f.hashes)}</span>
        ${best ? `<div class="enrich-slot" data-indicator="${escapeHtml(best)}" style="margin-top:6px">
          <button class="enrich-btn" data-enrich="${escapeHtml(best)}">Check hash reputation</button>
        </div>` : ""}
      </div>`;
    }

    const techniques = (d.attack || [])
        .map((t) => `<span class="chip" data-technique="${escapeHtml(t)}" role="button" tabindex="0">${escapeHtml(t)}</span>`)
        .join(" ");

    return `
    <div class="tl-detail" data-sev="${escapeHtml((d.severity || "medium").toLowerCase())}">
      <div class="tl-detail-grid">${rows.join("")}${hashes}</div>
      ${cmd}
      ${parentCmd}
      ${techniques ? `<div class="tl-detail-tech">${techniques}</div>` : ""}
    </div>`;
}

/** Pick the strongest hash (SHA256 > SHA1 > MD5) from a Sysmon Hashes string,
 *  mirroring the backend so the client enriches the same value the report would. */
function bestHash(raw) {
    const parts = {};
    for (const p of String(raw).split(",")) {
        const [k, v] = p.split("=");
        if (k && v) parts[k.trim().toLowerCase()] = v.trim();
    }
    return parts.sha256 || parts.sha1 || parts.md5 || null;
}

/** Full timestamp for the detail panel: date + time, not just the clock. */
function fmtFullTime(iso) {
    if (!iso) return "";
    return new Date(iso).toLocaleString("en-GB", { hour12: false });
}


/** Build an SVG of the incident's full process tree.
 *
 *  Unlike the chain (the ancestry of the one process that triggered a detection),
 *  this is every branch: a foothold that spawned several children shows all of
 *  them. Nodes that themselves fired a detection are marked, so the analyst sees
 *  both the shape of what ran and which parts were flagged.
 *
 *  Laid out as an indented tree rather than a graph -- process trees are strictly
 *  hierarchical, and indentation reads faster than edges for depth.
 */
function processTreeSvg(nodes, detections) {
    if (!nodes || !nodes.length) {
        return '<div class="tree-empty">No process tree captured for this incident.</div>';
    }

    // Which process GUIDs fired a detection, and the worst severity each reached.
    const flagged = {};
    for (const d of detections || []) {
        const g = (d.forensics && d.forensics.process_guid) || d.process_guid;
        // detections don't carry guid in the serializer; match on image name instead
        // as a fallback so at least the flagged styling has something to key on.
    }
    const flaggedNames = {};
    for (const d of detections || []) {
        const name = baseName(d.image);
        const sev = (d.severity || "medium").toLowerCase();
        const rank = ["info", "low", "medium", "high", "critical"];
        if (!flaggedNames[name] || rank.indexOf(sev) > rank.indexOf(flaggedNames[name])) {
            flaggedNames[name] = sev;
        }
    }

    const byParent = {};
    const guids = new Set(nodes.map((n) => n.guid));
    for (const n of nodes) (byParent[n.parent_guid] ||= []).push(n);
    const roots = nodes.filter((n) => !guids.has(n.parent_guid));

    // Flatten to rows in DFS order, tracking depth, so we can render as an
    // indented list of SVG rows of known height.
    const rows = [];
    const walk = (guid, depth) => {
        const node = nodes.find((n) => n.guid === guid);
        if (!node) return;
        rows.push({ node, depth });
        for (const child of byParent[guid] || []) walk(child.guid, depth + 1);
    };
    for (const r of roots) walk(r.guid, 0);

    const rowH = 26;
    const indent = 22;
    const width = 560;
    const height = rows.length * rowH + 12;

    let svg = `<svg viewBox="0 0 ${width} ${height}" xmlns="http://www.w3.org/2000/svg" class="tree-svg" role="img" aria-label="Process tree">`;

    rows.forEach((row, i) => {
        const { node, depth } = row;
        const x = 10 + depth * indent;
        const y = 12 + i * rowH;
        const sev = flaggedNames[node.name];
        const color = sev ? `var(--sev-${sev})` : "var(--text-dim)";

        // Connector: a short elbow from the parent's column down to this node.
        if (depth > 0) {
            const px = 10 + (depth - 1) * indent + 4;
            svg += `<path d="M${px} ${y - rowH + 4} L${px} ${y} L${x - 4} ${y}" fill="none" stroke="var(--border-hi)" stroke-width="1"/>`;
        }

        // Node dot: filled + haloed if it fired a detection, hollow if benign.
        if (sev) {
            svg += `<circle cx="${x}" cy="${y}" r="4" fill="${color}"/>`;
            if (sev === "critical") svg += `<circle cx="${x}" cy="${y}" r="7" fill="none" stroke="${color}" stroke-width="1" opacity="0.4"/>`;
        } else {
            svg += `<circle cx="${x}" cy="${y}" r="3.5" fill="none" stroke="${color}" stroke-width="1"/>`;
        }

        // Process name, coloured by whether it was flagged.
        const weight = sev ? "700" : "400";
        svg += `<text x="${x + 11}" y="${y + 3.5}" fill="${sev ? color : 'var(--text)'}" font-size="11" font-weight="${weight}" font-family="monospace">${escapeHtml(node.name)}</text>`;
    });

    svg += `</svg>`;

    const legend = `<div class="tree-legend">
    <span><span class="tree-dot flagged"></span> fired a detection</span>
    <span><span class="tree-dot benign"></span> benign (context)</span>
  </div>`;

    return svg + legend;
}

/** A compact human gap: "3s", "5m", "2h". Empty for sub-second gaps, which are
 *  noise on a timeline of attacker actions. */
function humanGap(ms) {
    const s = Math.round(ms / 1000);
    if (s < 1) return "";
    if (s < 60) return `${s}s`;
    const m = Math.round(s / 60);
    if (m < 60) return `${m}m`;
    const h = Math.round(m / 60);
    return `${h}h`;
}

/** Render the incident behavior profile: a narrative summary plus the ordered
 *  kill-chain phases. Fetched once and cached on the incident object, since it
 *  is derived from detections that do not change after the incident closes. */

function profileHtml(incident) {
    if (incident._profile === undefined) {
        // Not fetched yet: kick off the fetch and show a placeholder. The fetch
        // re-renders when it lands.
        incident._profile = null;
        fetch(`/incidents/${incident.id}/profile`)
            .then((r) => r.json())
            .then((data) => { incident._profile = data; renderQueue(); })
            .catch(() => { incident._profile = { summary: "", phases: [] }; });
        return `<div class="profile profile-loading">Profiling behavior\u2026</div>`;
    }
    if (!incident._profile || !incident._profile.phases.length) return "";

    const phases = incident._profile.phases.map((p) => `
    <div class="profile-phase">
      <span class="profile-tactic">${escapeHtml(p.tactic)}</span>
      <span class="profile-phrase">${escapeHtml(p.phrase)}</span>
      <span class="profile-tech">${(p.techniques || []).map((t) =>
        `<span class="chip" data-technique="${escapeHtml(t)}" role="button" tabindex="0">${escapeHtml(t)}</span>`).join("")}</span>
    </div>`).join("");

    return `
    <div class="profile">
      <div class="profile-head">Behavior profile</div>
      <div class="profile-summary">${escapeHtml(incident._profile.summary)}</div>
      <div class="profile-phases">${phases}</div>
    </div>`;
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
      ${d.command_line ? `<div class="cmd">${renderCommand(d.command_line)}</div>` : ""}
      ${evidenceHtml(d)}
    </div>`).join("");

    // A view toggle: the list is for detail, the timeline is for sequence. An
    // analyst reconstructing an attack wants to switch between "what exactly
    // fired" and "in what order it unfolded".
    const view = state.viewFor.get(incident.id) || "list";
    let body;
    if (view === "timeline") {
        body = `<div class="timeline">${timelineSvg(incident._members, incident.id)}</div>`;
    } else if (view === "tree") {
        body = `<div class="tree">${processTreeSvg(incident.process_tree, incident._members)}</div>`;
    } else {
        body = `<div class="members">${rows}</div>`;
    }

    const tab = (id, label) =>
        `<button class="view-tab${view === id ? " on" : ""}" data-view="${id}" data-incident="${escapeHtml(incident.id)}">${label}</button>`;

    return `
    ${profileHtml(incident)}
    <div class="member-views">
      ${tab("list", "List")}${tab("timeline", "Timeline")}${tab("tree", "Process tree")}
    </div>
    ${body}`;
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
        <div class="enrich-slot" data-indicator="${escapeHtml((evidence.destination || "").split(":")[0])}">
          <button class="enrich-btn" data-enrich="${escapeHtml((evidence.destination || "").split(":")[0])}">
            Check reputation
          </button>
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

    // An active search overrides the scope filter: when you search, you want to
    // search everything -- open and closed -- not just the current view.
    if (state.searchResults !== null) {
        const order = new Map(state.searchResults.map((id, i) => [id, i]));
        return all
            .filter((i) => order.has(i.id))
            .sort((a, b) => order.get(a.id) - order.get(b.id));  // keep server ranking
    }

    const scoped = state.scope === "triage" ? all.filter((i) => i.actionable) : all;
    return scoped.sort((a, b) => new Date(b.last_seen) - new Date(a.last_seen));
}

function renderQueue(freshId = null) {
    const list = visibleIncidents();
    $("queue-count").textContent = list.length;

    if (!list.length) {
        if (state.searchResults !== null) {
            $("queue").innerHTML = `
        <div class="empty">
          <div class="empty-mark">No matches</div>
          <p>Nothing matches <code>${escapeHtml(state.searchQuery)}</code>. Try a
          broader term, or a filter like <code>severity:critical</code>.</p>
        </div>`;
            return;
        }
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
            fetch("/incidents?limit=300").then((r) => r.json()),
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
        } else if (type === "reset") {
            // The server wiped the database (see /admin/database). Every
            // connected console gets this, not just the one that clicked
            // reset, so no analyst is left staring at a stale queue.
            state.incidents.clear();
            state.detections = [];
            state.expanded.clear();
            state.viewFor.clear();
            state.timelineNode.clear();
            state.searchResults = null;
            $("s-last").textContent = "--:--:--";
            renderQueue();
            renderStream();
            fetch("/health").then((r) => r.json()).then((health) => {
                $("engine").textContent =
                    `engine: ${health.rules_loaded} rules · ${health.processes_tracked} processes tracked`;
            }).catch(() => { });
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
   Settings menu

   One destructive action today: wipe the database. Confirmed with a native
   dialog because there is no undo -- every detection and incident is just
   gone, on every connected console (see the "reset" branch in connect()).
   ============================================================ */

document.addEventListener("DOMContentLoaded", () => {
    const btn = $("settings-btn");
    const menu = $("settings-menu");
    const resetBtn = $("reset-db-btn");
    if (!btn || !menu) return;

    const closeMenu = () => {
        menu.hidden = true;
        btn.setAttribute("aria-expanded", "false");
    };

    btn.addEventListener("click", (event) => {
        event.stopPropagation();
        const opening = menu.hidden;
        menu.hidden = !opening;
        btn.setAttribute("aria-expanded", String(opening));
    });

    menu.addEventListener("click", (event) => event.stopPropagation());

    document.addEventListener("click", () => closeMenu());
    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape") closeMenu();
    });

    if (resetBtn) {
        resetBtn.addEventListener("click", async () => {
            closeMenu();
            const ok = confirm(
                "Reset the database?\n\nThis permanently deletes every detection " +
                "and incident on record. This cannot be undone."
            );
            if (!ok) return;

            resetBtn.disabled = true;
            resetBtn.textContent = "Resetting…";
            try {
                const res = await fetch("/admin/database", { method: "DELETE" });
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                // The UI itself clears via the "reset" websocket broadcast, not
                // here -- that way this tab and every other open console update
                // the same way, from the same event.
            } catch (err) {
                alert("Reset failed: " + err.message);
            } finally {
                resetBtn.disabled = false;
                resetBtn.innerHTML =
                    '<svg class="ico"><use href="#i-trash"/></svg> Reset database';
            }
        });
    }
});

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

/** Render MITRE's markdown-ish description as safe HTML.
 *
 *  MITRE descriptions arrive with markdown links [label](url), literal <code>
 *  tags, and (Citation: ...) noise. Rendered with textContent they show as raw
 *  markup; rendered with innerHTML unescaped they are an XSS vector, because the
 *  text is third-party content. So: escape everything first, then re-introduce
 *  only the specific safe constructs -- and only http(s) links, never a
 *  javascript: URL smuggled into a [label](...) target.
 */
function renderAttackText(text) {
    let html = escapeHtml(text);

    // <code> tags survive escaping as &lt;code&gt;; restore them.
    html = html.replace(/&lt;code&gt;(.*?)&lt;\/code&gt;/g, "<code>$1</code>");

    // Citation markers add nothing to a definition and clutter the prose.
    html = html.replace(/\(Citation:[^)]*\)/g, "");

    // Markdown links -> anchors. Only http(s) targets are allowed. The URL was
    // escaped, so &amp; is restored inside href.
    html = html.replace(/\[([^\]]+)\]\((https?:\/\/[^)]+)\)/g, (match, label, url) => {
        const safeUrl = url.replace(/&amp;/g, "&");
        return `<a href="${safeUrl}" target="_blank" rel="noopener">${label}</a>`;
    });

    // Blank lines become paragraph breaks.
    html = html.replace(/\n\n+/g, "</p><p>");
    return `<p>${html}</p>`;
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
    el.body.innerHTML = renderAttackText(data.description || "No description provided.");
    if (data.url) el.link.href = data.url;
}

function closeTechnique() {
    document.getElementById("tech-overlay").classList.remove("open");
}

// Delegated activation: click, or Enter/Space on a focused chip.
document.addEventListener("click", (event) => {
    const chip = event.target.closest("[data-technique]");
    if (chip) openTechnique(chip.dataset.technique);

    // Expand or collapse a timeline node's detail.
    const node = event.target.closest("[data-timeline-node]");
    if (node) {
        const id = node.dataset.incident;
        const idx = parseInt(node.dataset.timelineNode, 10);
        if (state.timelineNode.get(id) === idx) state.timelineNode.delete(id);
        else state.timelineNode.set(id, idx);
        renderQueue();
        return;
    }

    // Switch an expanded incident between list / timeline / tree views.
    const tab = event.target.closest(".view-tab");
    if (tab) {
        state.viewFor.set(tab.dataset.incident, tab.dataset.view);
        renderQueue();
    }
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


/* ============================================================
   IOC enrichment

   The beacon evidence panel carries a "Check reputation" button for its
   destination IP. Enrichment is on-demand -- the analyst asks -- so this fires
   only on click, calls /enrich, and paints the result inline. Delegated, since
   the panel is regenerated on every render.
   ============================================================ */

const VERDICT_COLOR = {
    malicious: "var(--sev-critical)",
    suspicious: "var(--sev-high)",
    clean: "var(--sev-low)",
    unknown: "var(--text-mute)",
};

async function enrichIndicator(indicator, slot) {
    slot.innerHTML = `<div class="enrich-loading">Checking ${escapeHtml(indicator)}\u2026</div>`;

    let data;
    try {
        const response = await fetch(`/enrich?indicator=${encodeURIComponent(indicator)}`);
        if (!response.ok) throw new Error(String(response.status));
        data = await response.json();
    } catch {
        slot.innerHTML = `<div class="enrich-loading">Enrichment unavailable for ${escapeHtml(indicator)}.</div>`;
        return;
    }

    const verdictColor = VERDICT_COLOR[data.worst_verdict] || VERDICT_COLOR.unknown;
    const rows = data.providers.map((p) => {
        const dot = p.available ? VERDICT_COLOR[p.verdict] : "var(--text-mute)";
        const link = p.link
            ? `<a href="${p.link}" target="_blank" rel="noopener">view</a>`
            : "";
        return `
      <div class="enrich-provider">
        <span class="enrich-dot" style="background:${dot}"></span>
        <span class="enrich-name">${escapeHtml(p.provider)}</span>
        <span class="enrich-summary">${escapeHtml(p.summary)}</span>
        ${link}
      </div>`;
    }).join("");

    slot.innerHTML = `
    <div class="enrich-result">
      <div class="enrich-verdict" style="color:${verdictColor}">
        ${escapeHtml(data.worst_verdict)} \u00b7 ${escapeHtml(indicator)}
      </div>
      ${rows}
    </div>`;
}

document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-enrich]");
    if (!button) return;
    const slot = button.closest(".enrich-slot");
    enrichIndicator(button.dataset.enrich, slot);
});


/* ============================================================
   Search

   One box for free text and field filters. Typing runs a debounced query
   against /search; the queue then shows only matching incidents, ranked by the
   server. Clearing the box restores the normal triage/all view.
   ============================================================ */

let searchTimer = null;

function runSearch(raw) {
    const query = raw.trim();
    state.searchQuery = query;

    const clearBtn = document.getElementById("search-clear");
    if (clearBtn) clearBtn.hidden = query.length === 0;

    if (!query) {
        state.searchResults = null;
        hideSearchHint();
        renderQueue();
        return;
    }

    clearTimeout(searchTimer);
    searchTimer = setTimeout(async () => {
        try {
            const data = await fetch(`/search?q=${encodeURIComponent(query)}`).then((r) => r.json());
            // The search can surface incidents not currently in memory (e.g. filtered
            // out of the triage view); fold them in so they can be rendered.
            for (const result of data.results) {
                state.incidents.set(result.incident.id, {
                    ...state.incidents.get(result.incident.id),
                    ...result.incident,
                });
            }
            state.searchResults = data.results.map((r) => r.incident.id);
            showSearchHint(data);
            renderQueue();
        } catch {
            hideSearchHint();
        }
    }, 200);
}

function showSearchHint(data) {
    const hint = document.getElementById("search-hint");
    if (!hint) return;
    const p = data.parsed;
    const bits = [];
    if (p.text.length) bits.push(`text: ${p.text.map(escapeHtml).join(" ")}`);
    for (const [k, v] of Object.entries(p.filters)) bits.push(`${escapeHtml(k)}: ${escapeHtml(v)}`);
    hint.innerHTML = `${data.total} match${data.total === 1 ? "" : "es"}` +
        (bits.length ? ` &nbsp;·&nbsp; <span class="search-parsed">${bits.join(" &nbsp;·&nbsp; ")}</span>` : "");
    hint.hidden = false;
}

function hideSearchHint() {
    const hint = document.getElementById("search-hint");
    if (hint) hint.hidden = true;
}

document.addEventListener("DOMContentLoaded", () => {
    const input = document.getElementById("search-input");
    const clear = document.getElementById("search-clear");
    if (input) input.addEventListener("input", (e) => runSearch(e.target.value));
    if (clear) clear.addEventListener("click", () => {
        if (input) input.value = "";
        runSearch("");
        if (input) input.focus();
    });
    // Escape clears the search when the box is focused.
    if (input) input.addEventListener("keydown", (e) => {
        if (e.key === "Escape") { input.value = ""; runSearch(""); }
    });
});

/* ---- Base64 decode popup ---- */

function showB64Popup(encoded, decoded, button) {
    // Remove any existing popup.
    document.querySelectorAll(".b64-popup").forEach((p) => p.remove());

    const popup = document.createElement("div");
    popup.className = "b64-popup";

    if (!decoded) {
        popup.innerHTML = `<div class="b64-popup-head">Decode failed</div>
      <div class="b64-popup-body">This is not valid base64.</div>`;
    } else {
        const encoding = decoded.isUtf16 ? "UTF-16LE (PowerShell -enc)" : "UTF-8";
        const warn = decoded.printable ? "" :
            `<div class="b64-warn">Output looks binary, not text - showing best effort.</div>`;
        popup.innerHTML = `
      <div class="b64-popup-head">
        Decoded <span class="b64-enc">${escapeHtml(encoding)}</span>
        <button class="b64-close" aria-label="Close">&times;</button>
      </div>
      ${warn}
      <div class="b64-popup-body">${escapeHtml(decoded.text)}</div>
      <div class="b64-popup-src">${escapeHtml(encoded.slice(0, 60))}${encoded.length > 60 ? "..." : ""}</div>`;
    }

    document.body.appendChild(popup);

    // Position near the button, kept within the viewport.
    const rect = button.getBoundingClientRect();
    popup.style.top = `${window.scrollY + rect.bottom + 6}px`;
    const left = window.scrollX + rect.left;
    popup.style.left = `${Math.min(left, window.scrollX + window.innerWidth - 380)}px`;

    const close = popup.querySelector(".b64-close");
    if (close) close.addEventListener("click", () => popup.remove());
}

// Delegated: decode button click, and dismiss on outside click / Escape.
document.addEventListener("click", (event) => {
    const btn = event.target.closest("[data-b64]");
    if (btn) {
        event.stopPropagation();
        const encoded = b64Cache.get(btn.dataset.b64);
        showB64Popup(encoded, encoded ? decodeBase64(encoded) : null, btn);
        return;
    }
    if (!event.target.closest(".b64-popup")) {
        document.querySelectorAll(".b64-popup").forEach((p) => p.remove());
    }
});
document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") document.querySelectorAll(".b64-popup").forEach((p) => p.remove());
});


/* ---- Triage: status, classification, notes ---- */



// Notes: debounced autosave on input, so typing does not fire a request per key.