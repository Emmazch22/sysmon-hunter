"""Incident report generation.

Produces a self-contained PDF an analyst can attach to a ticket or hand to an
incident-response lead. It is not a screenshot of the console -- it is the
investigation written down: what happened, in what order, who did it, with what
privileges, and every indicator worth pivoting on.

The report carries the console's identity deliberately. Same dark surface, same
"colour is signal, severity is the only saturated colour" rule. A report that
looks like the tool it came from reads as one coherent product, not a bolt-on.

reportlab is used over an HTML-to-PDF path because it needs no headless browser
in the container -- one fewer heavy dependency in a security tool's image.
"""

from __future__ import annotations

from datetime import datetime
from io import BytesIO
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Flowable,
    Frame,
    KeepTogether,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

# --- Palette, lifted from the console so the report is visibly the same tool ---
BG = colors.HexColor("#0B0F14")
SURFACE = colors.HexColor("#111821")
SURFACE_2 = colors.HexColor("#16202B")
BORDER = colors.HexColor("#1F2C3A")
TEXT = colors.HexColor("#C9D6E3")
TEXT_DIM = colors.HexColor("#7E90A3")
TEXT_MUTE = colors.HexColor("#55677A")
STRUCT = colors.HexColor("#3FB6C8")
ATTACK = colors.HexColor("#8C7BE0")

SEVERITY_COLOR = {
    "critical": colors.HexColor("#E4453D"),
    "high": colors.HexColor("#E8743B"),
    "medium": colors.HexColor("#DFA83C"),
    "low": colors.HexColor("#3FB6C8"),
    "info": colors.HexColor("#4A7FA5"),
}

# Human labels for the forensic field keys the serializer produces.
FORENSIC_LABELS = {
    "user": "User",
    "integrity_level": "Integrity level",
    "logon_id": "Logon ID",
    "session_id": "Session ID",
    "process_id": "PID",
    "parent_process_id": "Parent PID",
    "current_directory": "Working directory",
    "hashes": "Hashes",
    "original_file_name": "Original filename",
    "company": "Signer",
    "product": "Product",
    "destination_ip": "Destination IP",
    "destination_port": "Destination port",
    "destination_hostname": "Destination host",
    "target_image": "Target process",
    "target_filename": "Target file",
    "registry_key": "Registry key",
    "granted_access": "Granted access",
    "pipe_name": "Named pipe",
    "dns_query": "DNS query",
}


class SeverityBar(Flowable):
    """A thin full-width bar in the incident's severity colour. The report's
    equivalent of the console's severity spine -- the first thing the eye reads."""

    def __init__(self, color: colors.Color, width: float, height: float = 3) -> None:
        super().__init__()
        self.color = color
        self.width = width
        self.height = height

    def draw(self) -> None:
        self.canv.setFillColor(self.color)
        self.canv.rect(0, 0, self.width, self.height, fill=1, stroke=0)


def _styles() -> dict[str, ParagraphStyle]:
    """Paragraph styles on the dark theme. Built once per report."""
    base = getSampleStyleSheet()
    mono = "Courier"
    sans = "Helvetica"

    return {
        "title": ParagraphStyle(
            "title",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=20,
            textColor=TEXT,
            spaceAfter=2,
            alignment=TA_LEFT,
        ),
        "subtitle": ParagraphStyle(
            "subtitle", fontName=mono, fontSize=9, textColor=TEXT_MUTE, spaceAfter=14
        ),
        "h2": ParagraphStyle(
            "h2",
            fontName="Helvetica-Bold",
            fontSize=11,
            textColor=STRUCT,
            spaceBefore=16,
            spaceAfter=8,
            leading=14,
        ),
        "body": ParagraphStyle(
            "body", fontName=sans, fontSize=9.5, textColor=TEXT_DIM, leading=14
        ),
        "mono": ParagraphStyle(
            "mono", fontName=mono, fontSize=8.5, textColor=TEXT_DIM, leading=12
        ),
        "mono_dim": ParagraphStyle(
            "mono_dim", fontName=mono, fontSize=8, textColor=TEXT_MUTE, leading=11
        ),
        "label": ParagraphStyle(
            "label",
            fontName="Helvetica-Bold",
            fontSize=8,
            textColor=TEXT_MUTE,
            leading=11,
        ),
        "rule": ParagraphStyle(
            "rule", fontName="Courier-Bold", fontSize=9, textColor=TEXT, leading=12
        ),
    }


def _paint_background(canvas, doc) -> None:
    """Fill each page with the dark surface and stamp a footer."""
    canvas.saveState()
    canvas.setFillColor(BG)
    canvas.rect(0, 0, doc.pagesize[0], doc.pagesize[1], fill=1, stroke=0)
    # footer
    canvas.setFillColor(TEXT_MUTE)
    canvas.setFont("Courier", 7)
    canvas.drawString(18 * mm, 12 * mm, "SYSMON HUNTER — INCIDENT REPORT")
    canvas.drawRightString(doc.pagesize[0] - 18 * mm, 12 * mm, f"Page {doc.page}")
    canvas.restoreState()


def _kv_table(pairs: list[tuple[str, str]], styles: dict, col: float) -> Table:
    """A two-column key/value table on the dark theme."""
    rows = [
        [Paragraph(k, styles["label"]), Paragraph(_esc(v), styles["mono"])]
        for k, v in pairs
    ]
    table = Table(rows, colWidths=[38 * mm, col - 38 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), SURFACE),
                ("LINEBELOW", (0, 0), (-1, -2), 0.4, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    return table


def _esc(value: Any) -> str:
    """Escape text for reportlab's mini-markup, which treats < & > specially."""
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _severity_of(score: int) -> str:
    """Bucket a score the same way the engine does, for the header chip."""
    if score >= 14:
        return "critical"
    if score >= 8:
        return "high"
    if score >= 5:
        return "medium"
    if score >= 2:
        return "low"
    return "info"


def build_incident_report(
    incident: dict[str, Any], detections: list[dict[str, Any]]
) -> bytes:
    """Render a full incident report to PDF bytes.

    `incident` is a serialized IncidentRow; `detections` its serialized members,
    oldest first. Returns the PDF as bytes so the endpoint can stream it without
    ever touching disk.
    """
    styles = _styles()
    buffer = BytesIO()
    page_w, page_h = A4
    content_w = page_w - 36 * mm

    doc = BaseDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=20 * mm,
        title=f"Incident {incident['id']}",
        author="Sysmon Hunter",
    )
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="main")
    doc.addPageTemplates(
        [PageTemplate(id="dark", frames=[frame], onPage=_paint_background)]
    )

    severity = incident.get("severity") or _severity_of(incident.get("score", 0))
    sev_color = SEVERITY_COLOR.get(severity, SEVERITY_COLOR["medium"])

    story: list[Flowable] = []

    # --- Header ---
    story.append(SeverityBar(sev_color, content_w))
    story.append(Spacer(1, 10))
    story.append(
        Paragraph(_esc(incident.get("title") or "Suspicious activity"), styles["title"])
    )
    story.append(
        Paragraph(
            f"{severity.upper()} &nbsp;·&nbsp; score {incident.get('score', 0)} "
            f"&nbsp;·&nbsp; {incident.get('host', 'unknown')} "
            f"&nbsp;·&nbsp; incident {incident['id']}",
            styles["subtitle"],
        )
    )

    # --- Summary ---
    story.append(Paragraph("Summary", styles["h2"]))
    first = _fmt_time(incident.get("first_seen"))
    last = _fmt_time(incident.get("last_seen"))
    story.append(
        _kv_table(
            [
                ("Host", incident.get("host", "unknown")),
                ("Severity", f"{severity} (score {incident.get('score', 0)})"),
                ("Detections", str(incident.get("detection_count", len(detections)))),
                ("First seen", first),
                ("Last seen", last),
                ("Process chain", " -> ".join(incident.get("chain", [])) or "unknown"),
                (
                    "ATT and CK techniques",
                    ", ".join(incident.get("techniques", [])) or "none",
                ),
            ],
            styles,
            content_w,
        )
    )

    # --- Attack timeline ---
    story.append(Paragraph("Attack timeline", styles["h2"]))
    story.append(_timeline_table(detections, styles, content_w))

    # --- Per-detection detail with full forensics ---
    story.append(Paragraph("Detection detail", styles["h2"]))
    for i, det in enumerate(detections, 1):
        story.append(_detection_block(i, det, styles, content_w))
        story.append(Spacer(1, 8))

    doc.build(story)
    return buffer.getvalue()


def _fmt_time(iso: str | None) -> str:
    if not iso:
        return "unknown"
    try:
        return datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M:%S UTC")
    except ValueError:
        return iso


def _timeline_table(detections: list[dict], styles: dict, width: float) -> Table:
    """A compact chronological table: time, rule, severity, process."""
    header = [
        Paragraph("TIME", styles["label"]),
        Paragraph("RULE", styles["label"]),
        Paragraph("SEVERITY", styles["label"]),
        Paragraph("PROCESS", styles["label"]),
    ]
    rows = [header]
    for det in detections:
        sev = (det.get("severity") or "medium").lower()
        rows.append(
            [
                Paragraph(
                    _fmt_time(det.get("matched_at")).split(" ")[1]
                    if det.get("matched_at")
                    else "-",
                    styles["mono_dim"],
                ),
                Paragraph(_esc(det.get("rule_id", "-")), styles["rule"]),
                Paragraph(
                    f'<font color="{"#" + SEVERITY_COLOR.get(sev, TEXT_DIM).hexval()[2:]}">{sev}</font>',
                    styles["mono"],
                ),
                Paragraph(_esc(_basename(det.get("image"))), styles["mono"]),
            ]
        )

    table = Table(rows, colWidths=[22 * mm, 26 * mm, 24 * mm, width - 72 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), SURFACE_2),
                ("BACKGROUND", (0, 1), (-1, -1), SURFACE),
                ("LINEBELOW", (0, 0), (-1, -1), 0.4, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    return table


def _detection_block(n: int, det: dict, styles: dict, width: float) -> Flowable:
    """One detection's full detail: title, command line, and forensics.

    Wrapped in KeepTogether so a detection is never split across a page break --
    an analyst reading the report should see each finding whole.
    """
    sev = (det.get("severity") or "medium").lower()
    sev_color = SEVERITY_COLOR.get(sev, SEVERITY_COLOR["medium"])

    parts: list[Flowable] = [
        SeverityBar(sev_color, width, height=2),
        Spacer(1, 5),
        Paragraph(
            f'<font name="Courier-Bold" color="{"#" + sev_color.hexval()[2:]}">{_esc(det.get("rule_id"))}</font>'
            f"&nbsp;&nbsp;{_esc(det.get('title', ''))}",
            styles["body"],
        ),
    ]

    if det.get("command_line"):
        parts.append(Spacer(1, 4))
        parts.append(_code_box(det["command_line"], styles))

    # Forensics: only the fields this event actually carried.
    forensics = det.get("forensics") or {}
    if forensics:
        pairs = [(FORENSIC_LABELS.get(k, k), str(v)) for k, v in forensics.items()]
        parts.append(Spacer(1, 5))
        parts.append(_kv_table(pairs, styles, width))

    # Evidence (beacon/discovery statistical detail), if present.
    evidence = det.get("evidence") or {}
    if evidence:
        ev_pairs = [
            (k.replace("_", " ").title(), _fmt_evidence(v)) for k, v in evidence.items()
        ]
        parts.append(Spacer(1, 5))
        parts.append(Paragraph("Evidence", styles["label"]))
        parts.append(_kv_table(ev_pairs, styles, width))

    return KeepTogether(parts)


def _fmt_evidence(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(str(v) for v in value[:6])
    return str(value)


def _code_box(text: str, styles: dict) -> Table:
    """A command line in a monospace box, wrapped so long lines do not overflow."""
    para = Paragraph(f'<font name="Courier">$ {_esc(text)}</font>', styles["mono"])
    table = Table([[para]])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0A0E13")),
                ("LINEBELOW", (0, 0), (-1, -1), 0.4, BORDER),
                ("BOX", (0, 0), (-1, -1), 0.4, BORDER),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return table


def _basename(path: str | None) -> str:
    if not path:
        return "unknown"
    return path.replace("/", "\\").split("\\")[-1]
