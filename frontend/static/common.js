"use strict";

/* ============================================================
   Shared rendering helpers.

   console.html, incident.html, and tree.html each render the same kind of
   content -- a detection's forensics, a process name, a timestamp -- and
   each grew its own copy of the handful of primitives that make that
   possible. This file is the one copy; every page loads it before its own
   script. Kept intentionally small: only the helpers that were already
   byte-for-byte identical (or a strict superset) across all three pages
   before this file existed. Anything with page-specific behavior --
   rendering a detection card, drawing an SVG tree -- stays where it is,
   since unifying those would mean picking one page's layout for all three.
   ============================================================ */

/** Escape untrusted strings before they touch innerHTML.
 *  Command lines are attacker-controlled by definition: an operator who names
 *  a process `<img onerror=...>` should not get script execution in the SOC. */
function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, (c) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
}

/** Reduce a full Windows (or POSIX) path to the bare executable name. */
function baseName(path) {
    if (!path) return "unknown";
    const parts = String(path).split(/[\\/]/);
    return parts[parts.length - 1] || String(path);
}

/** HH:MM:SS in the console's timezone-agnostic 24h format. Empty/missing
 *  input renders as "now" rather than "Invalid Date". */
function clockTime(iso) {
    const date = iso ? new Date(iso) : new Date();
    return date.toLocaleTimeString("en-GB", { hour12: false });
}

/** Full date + time, 24h format. Empty string for a missing timestamp --
 *  callers that want a different placeholder (e.g. incident.html's
 *  "unknown") supply their own fallback around this. */
function fmtFullTime(iso) {
    if (!iso) return "";
    return new Date(iso).toLocaleString("en-GB", { hour12: false });
}

/** A compact human gap: "3s", "5m", "2h". Empty for sub-second gaps, which
 *  are noise on a timeline of attacker actions. */
function humanGap(ms) {
    const s = Math.round(ms / 1000);
    if (s < 1) return "";
    if (s < 60) return `${s}s`;
    const m = Math.round(s / 60);
    if (m < 60) return `${m}m`;
    const h = Math.round(m / 60);
    return `${h}h`;
}
