"""
PDF Report Generator using ReportLab for CIRIP
(Cyber Incident Report Intelligence Platform)

Generates a professional, comprehensive, and downloadable threat intelligence PDF
for a given cyber incident record.

The report includes:
  1. Cover Page & Executive Overview (Branding, ID, Timestamps, Threat Overview)
  2. Original Incident Report & Language Intelligence (Detected Language, Translated Text)
  3. Incident Classification & Severity Analysis (with ML Probability Vector Chart)
  4. Threat Intelligence Score & Risk Breakdown (with Visual Score Gauge)
  5. Extracted Indicators of Compromise (IoCs) - Suspicious IPs, URLs, Domains, Emails, Hashes
  6. Detected Entities & Malware Information (Malware Families, Hashes, Users, Orgs, CVEs)
  7. Attack Method & MITRE ATT&CK Storyline (with Visual Attack Progression Flowchart)
  8. Affected Systems & Infrastructure Scope
  9. NLP Analysis & Explainable AI (TF-IDF Feature Weights & Contributions)
  10. AI-Generated Summary (Extractive / LLM with Source Attribution)
  11. Recommended Actions & Mitigation Strategy (Immediate, Containment, Recovery, Prevention)
  12. Threat Campaign Intelligence & Similar Incidents (if available)

All content is dynamically derived from the analyzed incident record.
"""

from __future__ import annotations
import io
import re
from datetime import datetime, timezone
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.graphics.shapes import Drawing, Rect, String, Line, Polygon, Group

# ── Colour palette ────────────────────────────────────────────────────────────
C_BG        = colors.HexColor("#0D1117")
C_PANEL     = colors.HexColor("#161B22")
C_CARD      = colors.HexColor("#1F2937")
C_ACCENT    = colors.HexColor("#3B82F6")
C_CYAN      = colors.HexColor("#22D3EE")
C_TEXT      = colors.HexColor("#E7ECF2")
C_MUTED     = colors.HexColor("#8A96A6")
C_BORDER    = colors.HexColor("#2A3649")
C_CRITICAL  = colors.HexColor("#EF4444")
C_HIGH      = colors.HexColor("#F97316")
C_MEDIUM    = colors.HexColor("#FACC15")
C_LOW       = colors.HexColor("#22C55E")
C_WHITE     = colors.white
C_BLACK     = colors.HexColor("#080B12")

SEV_COLOR = {
    "Critical": C_CRITICAL,
    "High":     C_HIGH,
    "Medium":   C_MEDIUM,
    "Low":      C_LOW,
}

W, H = A4  # 595.27 × 841.89 pts


# ── Styles ────────────────────────────────────────────────────────────────────

def _make_styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    s: dict[str, ParagraphStyle] = {}

    def add(name, **kw):
        s[name] = ParagraphStyle(name, **kw)

    add("cover_title",   fontSize=26, leading=32, textColor=C_WHITE,
        fontName="Helvetica-Bold", spaceAfter=6, alignment=TA_CENTER)
    add("cover_sub",     fontSize=13, leading=17, textColor=C_CYAN,
        fontName="Helvetica", spaceAfter=4, alignment=TA_CENTER)
    add("cover_badge",   fontSize=10, leading=14, textColor=C_ACCENT,
        fontName="Helvetica-Bold", spaceAfter=12, alignment=TA_CENTER)
    add("cover_meta",    fontSize=9, leading=14, textColor=C_TEXT,
        fontName="Helvetica", spaceAfter=3, alignment=TA_CENTER)
    add("cover_notice",  fontSize=8, leading=12, textColor=C_MUTED,
        fontName="Helvetica-Oblique", alignment=TA_CENTER)

    add("section_head",  fontSize=13, leading=18, textColor=C_ACCENT,
        fontName="Helvetica-Bold", spaceBefore=12, spaceAfter=5)
    add("sub_head",      fontSize=10, leading=15, textColor=C_CYAN,
        fontName="Helvetica-Bold", spaceBefore=7, spaceAfter=3)

    add("body",          fontSize=8.5, leading=12.5, textColor=C_TEXT,
        fontName="Helvetica", spaceAfter=4)
    add("body_bold",     fontSize=8.5, leading=12.5, textColor=C_WHITE,
        fontName="Helvetica-Bold", spaceAfter=3)
    add("body_code",     fontSize=8, leading=11, textColor=C_CYAN,
        fontName="Courier", spaceAfter=3)
    add("body_box",      fontSize=8.5, leading=12.5, textColor=C_TEXT,
        fontName="Helvetica")

    add("label",         fontSize=7.5, leading=11, textColor=C_MUTED,
        fontName="Helvetica-Oblique", spaceAfter=2)
    add("label_bold",    fontSize=8, leading=11, textColor=C_CYAN,
        fontName="Helvetica-Bold", spaceAfter=2)

    add("th",            fontSize=8, leading=11, textColor=C_WHITE,
        fontName="Helvetica-Bold")
    add("td",            fontSize=8, leading=11, textColor=C_TEXT,
        fontName="Helvetica")
    add("td_bold",       fontSize=8, leading=11, textColor=C_WHITE,
        fontName="Helvetica-Bold")
    add("td_code",       fontSize=7.5, leading=10, textColor=C_CYAN,
        fontName="Courier")
    add("td_muted",      fontSize=7.5, leading=10, textColor=C_MUTED,
        fontName="Helvetica")

    return s


# ── Table styling helpers ─────────────────────────────────────────────────────

def _table_style(header_color=C_ACCENT) -> TableStyle:
    return TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), header_color),
        ("TEXTCOLOR",     (0, 0), (-1, 0), C_WHITE),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0), 8),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_PANEL, C_BG]),
        ("TEXTCOLOR",     (0, 1), (-1, -1), C_TEXT),
        ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE",      (0, 1), (-1, -1), 8),
        ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ])


def _callout_style(border_color=C_ACCENT, bg_color=C_PANEL) -> TableStyle:
    return TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), bg_color),
        ("BOX",           (0, 0), (-1, -1), 1, border_color),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
    ])


# ── Page templates (Canvas Callbacks) ──────────────────────────────────────────

def _cover_page(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(C_BG)
    canvas.rect(0, 0, W, H, fill=True, stroke=False)
    # Top decorative header bar
    canvas.setFillColor(C_ACCENT)
    canvas.rect(0, H - 6 * mm, W, 6 * mm, fill=True, stroke=False)
    # Bottom footer line
    canvas.setStrokeColor(C_BORDER)
    canvas.setLineWidth(0.5)
    canvas.line(20 * mm, 12 * mm, W - 20 * mm, 12 * mm)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(C_MUTED)
    canvas.drawCentredString(
        W / 2, 8 * mm,
        "CIRIP — CYBER INCIDENT REPORT INTELLIGENCE PLATFORM  |  CONFIDENTIAL // TLP:AMBER"
    )
    canvas.restoreState()


def _add_page_number(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(C_BG)
    canvas.rect(0, 0, W, H, fill=True, stroke=False)

    # Top running header
    canvas.setFillColor(C_PANEL)
    canvas.rect(0, H - 13 * mm, W, 13 * mm, fill=True, stroke=False)
    canvas.setStrokeColor(C_ACCENT)
    canvas.setLineWidth(0.5)
    canvas.line(20 * mm, H - 13 * mm, W - 20 * mm, H - 13 * mm)
    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(C_CYAN)
    canvas.drawString(20 * mm, H - 9 * mm, "CIRIP — CYBER INCIDENT INTELLIGENCE REPORT")
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(C_MUTED)
    canvas.drawRightString(W - 20 * mm, H - 9 * mm, "CONFIDENTIAL // DEFENSIVE USE ONLY")

    # Bottom running footer
    canvas.setStrokeColor(C_BORDER)
    canvas.setLineWidth(0.5)
    canvas.line(20 * mm, 14 * mm, W - 20 * mm, 14 * mm)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(C_MUTED)
    page_num = getattr(canvas, "_pageNumber", doc.page)
    canvas.drawCentredString(
        W / 2, 9 * mm,
        f"Cyber Threat Intelligence & Fusion Platform  |  Page {page_num}"
    )
    canvas.restoreState()


# ── Visual Chart Generators (Pure ReportLab Drawing Flowables) ────────────────

def _create_threat_score_gauge(score: int, classification: str) -> Drawing:
    """Create a vector gauge bar showing the score and risk tier."""
    dw, dh = 480, 48
    d = Drawing(dw, dh)

    # Base track (dark)
    bar_x, bar_y, bar_w, bar_h = 10, 10, 460, 14
    d.add(Rect(bar_x, bar_y, bar_w, bar_h, fillColor=colors.HexColor("#1E293B"), strokeColor=C_BORDER, strokeWidth=0.5, rx=3, ry=3))

    # Gradient colored segments
    # 0-25: Low (Green)
    d.add(Rect(bar_x, bar_y, bar_w * 0.25, bar_h, fillColor=colors.HexColor("#22C55E33"), strokeColor=None))
    # 25-50: Moderate (Yellow)
    d.add(Rect(bar_x + bar_w * 0.25, bar_y, bar_w * 0.25, bar_h, fillColor=colors.HexColor("#FACC1533"), strokeColor=None))
    # 50-75: High (Orange)
    d.add(Rect(bar_x + bar_w * 0.50, bar_y, bar_w * 0.25, bar_h, fillColor=colors.HexColor("#F9731633"), strokeColor=None))
    # 75-100: Critical (Red)
    d.add(Rect(bar_x + bar_w * 0.75, bar_y, bar_w * 0.25, bar_h, fillColor=colors.HexColor("#EF444433"), strokeColor=None))

    # Active fill based on score
    score_clamped = max(0, min(100, score))
    fill_w = (score_clamped / 100.0) * bar_w
    if score_clamped >= 75:
        score_color = C_CRITICAL
    elif score_clamped >= 50:
        score_color = C_HIGH
    elif score_clamped >= 25:
        score_color = C_MEDIUM
    else:
        score_color = C_LOW

    if fill_w > 0:
        d.add(Rect(bar_x, bar_y, fill_w, bar_h, fillColor=score_color, strokeColor=None, rx=3, ry=3))

    # Top labels
    d.add(String(bar_x, 32, f"Threat Score: {score}/100", fontName="Helvetica-Bold", fontSize=9.5, fillColor=C_WHITE))
    d.add(String(bar_x + 130, 32, f"Tier: {classification}", fontName="Helvetica-Bold", fontSize=9.5, fillColor=score_color))

    # Segment markers
    for p, lbl in [(0, "0"), (25, "25"), (50, "50"), (75, "75"), (100, "100")]:
        lx = bar_x + (p / 100.0) * bar_w
        if p == 100:
            lx -= 10
        elif p > 0:
            lx -= 5
        d.add(String(lx, 0, lbl, fontName="Helvetica", fontSize=7, fillColor=C_MUTED))

    return d


def _create_probability_barchart(class_probs: dict[str, float]) -> Drawing:
    """Create a vector horizontal bar chart for ML classification probabilities."""
    if not class_probs:
        return Drawing(10, 10)

    # Sort descending
    sorted_items = sorted(class_probs.items(), key=lambda x: x[1], reverse=True)[:5]
    bar_count = len(sorted_items)
    row_h = 17
    dw = 480
    dh = bar_count * row_h + 16
    d = Drawing(dw, dh)

    d.add(String(10, dh - 10, "Class Probabilities (TF-IDF + Logistic Regression):", fontName="Helvetica-Bold", fontSize=8, fillColor=C_CYAN))

    max_bar_w = 260
    chart_x = 130

    palette = [C_ACCENT, C_CYAN, colors.HexColor("#8B5CF6"), C_LOW, C_HIGH]

    for idx, (label, prob) in enumerate(sorted_items):
        y = dh - 26 - (idx * row_h)
        # Class label
        d.add(String(10, y + 2, str(label)[:20], fontName="Helvetica", fontSize=7.5, fillColor=C_TEXT))
        # Background bar
        d.add(Rect(chart_x, y, max_bar_w, 9, fillColor=colors.HexColor("#1E293B"), strokeColor=None, rx=2, ry=2))
        # Active bar
        bw = max(2, prob * max_bar_w)
        col = palette[idx % len(palette)]
        d.add(Rect(chart_x, y, bw, 9, fillColor=col, strokeColor=None, rx=2, ry=2))
        # Percentage text
        d.add(String(chart_x + max_bar_w + 10, y + 1, f"{prob * 100:.1f}%", fontName="Helvetica-Bold", fontSize=7.5, fillColor=C_CYAN))

    return d


def _create_storyline_flowchart(stages: list[dict]) -> Drawing:
    """Create a visual vector attack chain showing stage progression and MITRE tactics."""
    if not stages:
        return Drawing(10, 10)

    display_stages = stages[:5]  # fit cleanly in page width
    n = len(display_stages)
    dw = 480
    dh = 42
    d = Drawing(dw, dh)

    box_w = min(82, (dw - 20 - (n - 1) * 16) / n)
    box_h = 32
    start_x = 10

    for i, st in enumerate(display_stages):
        x = start_x + i * (box_w + 16)
        y = 5

        # Stage box
        conf = st.get("confidence", 0)
        box_col = C_CRITICAL if conf >= 70 else (C_HIGH if conf >= 40 else C_CARD)
        border_col = C_ACCENT if conf < 40 else box_col

        d.add(Rect(x, y, box_w, box_h, fillColor=C_PANEL, strokeColor=border_col, strokeWidth=1, rx=4, ry=4))
        # Stage name
        name = st.get("name", f"Stage {i+1}")
        d.add(String(x + 4, y + 19, name[:12], fontName="Helvetica-Bold", fontSize=7, fillColor=C_WHITE))
        # MITRE tactic
        tactic = st.get("mitre_tactic", "—")
        d.add(String(x + 4, y + 8, tactic, fontName="Helvetica", fontSize=6.5, fillColor=C_CYAN))
        # Conf %
        d.add(String(x + box_w - 24, y + 8, f"{conf}%", fontName="Helvetica-Bold", fontSize=6.5, fillColor=C_MUTED))

        # Arrow to next
        if i < n - 1:
            ax = x + box_w + 2
            ay = y + box_h / 2
            d.add(Line(ax, ay, ax + 10, ay, strokeColor=C_ACCENT, strokeWidth=1.5))
            d.add(Polygon([ax + 8, ay - 3, ax + 12, ay, ax + 8, ay + 3], fillColor=C_ACCENT, strokeColor=None))

    return d


# ── Affected Systems Heuristic Extractor ──────────────────────────────────────

AFFECTED_SYSTEM_PATTERNS = [
    r"\b(?:customer|user|financial|sql|nosql|relational|mongo|postgres|oracle)?\s*database(?:s)?\b",
    r"\bweb\s*application(?:s)?\b",
    r"\bweb\s*server(?:s)?\b",
    r"\bdomain\s*controller(?:s)?\b",
    r"\bactive\s*directory\b",
    r"\bworkstation(?:s)?\b",
    r"\bendpoint(?:s)?\b",
    r"\blaptop(?:s)?\b",
    r"\bcloud\s*(?:storage|instance|infrastructure|server|environment|bucket|asset)\b",
    r"\bs3\s*bucket(?:s)?\b",
    r"\bkubernetes\s*(?:cluster|pod|node)?\b",
    r"\bproduction\s*server(?:s)?\b",
    r"\bfile\s*server(?:s)?\b",
    r"\bmail\s*server(?:s)?\b",
    r"\bexchange\s*server(?:s)?\b",
    r"\bapi\s*gateway(?:s)?\b",
    r"\bvpn\s*(?:gateway|server|concentrator)?\b",
    r"\bfirewall(?:s)?\b",
    r"\bpayment\s*(?:gateway|terminal|system|processor)\b",
    r"\bpos\s*terminal(?:s)?\b",
    r"\bdns\s*server(?:s)?\b",
    r"\bbackup\s*(?:server|system|repository)\b",
    r"\binternal\s*network(?:s)?\b",
    r"\bcorporate\s*network\b",
    r"\bhost(?:s)?\s+[A-Za-z0-9._-]+\b",
    r"\bserver(?:s)?\s+[A-Za-z0-9._-]+\b",
]

SYSTEM_REGEX = re.compile("|".join(AFFECTED_SYSTEM_PATTERNS), re.IGNORECASE)


def extract_affected_systems(text: str, entities: dict) -> list[str]:
    """Identify affected infrastructure, systems, or assets from text and entities."""
    found = set()
    for match in SYSTEM_REGEX.finditer(text):
        term = match.group(0).strip()
        if len(term) > 2:
            found.add(term.title())

    # Check organizations / hosts in entities
    for org in entities.get("organizations", []):
        if any(w in org.lower() for w in ["server", "db", "cloud", "center", "system", "infrastructure"]):
            found.add(org)

    # Fallbacks based on common keywords
    text_lower = text.lower()
    if "database" in text_lower and not any("database" in f.lower() for f in found):
        found.add("Database Storage")
    if "server" in text_lower and not any("server" in f.lower() for f in found):
        found.add("Internal Server(s)")
    if "network" in text_lower and not any("network" in f.lower() for f in found):
        found.add("Enterprise Network")

    return sorted(list(found)) if found else ["Undetermined / Enterprise Endpoint Infrastructure"]


# ── Main PDF Generation Function ──────────────────────────────────────────────

def generate_pdf(
    record: dict,
    report_data: dict | None = None,
    similar_incidents: list[dict] | None = None,
    campaign: dict | None = None,
    storyline: dict | None = None,
    threat_score: dict | None = None,
) -> bytes:
    """
    Generate a complete, professional cyber incident intelligence report PDF
    from the analyzed incident record. Returns raw PDF bytes.
    """
    buf = io.BytesIO()
    S = _make_styles()

    doc = BaseDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
    )

    # Frame definitions
    cover_frame = Frame(
        20 * mm, 15 * mm, W - 40 * mm, H - 30 * mm,
        id="cover_frame",
        leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0,
    )
    content_frame = Frame(
        20 * mm, 18 * mm, W - 40 * mm, H - 34 * mm,
        id="content_frame",
        leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0,
    )

    doc.addPageTemplates([
        PageTemplate(id="cover",   frames=cover_frame,   onPage=_cover_page),
        PageTemplate(id="content", frames=content_frame, onPage=_add_page_number),
    ])

    story: list[Any] = []

    # ── Safe Data Extraction with Fallbacks ───────────────────────────────────
    incident_id   = str(record.get("_id") or record.get("id") or "UNKNOWN-ID")
    title         = str(record.get("title") or "Cyber Security Incident")
    created_at    = str(record.get("created_at") or "")
    text          = str(record.get("text") or "")
    
    # Language info
    lang_info     = record.get("language_info") or {}
    det_lang_name = lang_info.get("detected_language_name", "English")
    det_lang_code = lang_info.get("detected_language_code", "en")
    orig_text     = lang_info.get("original_text") or text
    trans_text    = lang_info.get("translated_text")

    # Threat Type & Severity
    itype_dict    = record.get("incident_type") or {}
    itype_label   = str(itype_dict.get("label") or "Undetermined")
    itype_conf    = float(itype_dict.get("confidence") or 0.0)
    itype_probs   = itype_dict.get("class_probabilities") or {}
    itype_source  = str(itype_dict.get("source") or "ML prediction (TF-IDF + Logistic Regression)")

    sev_dict      = record.get("severity") or {}
    sev_label     = str(sev_dict.get("label") or "Medium")
    sev_conf      = float(sev_dict.get("confidence") or 0.0)
    sev_probs     = sev_dict.get("class_probabilities") or {}
    sev_source    = str(sev_dict.get("source") or "ML prediction (TF-IDF + Logistic Regression)")

    # IoCs & Entities
    iocs          = record.get("iocs") or {}
    entities      = record.get("entities") or {}

    # Summary
    summary_dict  = record.get("summary") or {}
    summary_text  = summary_dict.get("text") or "No incident summary available."
    summary_source= summary_dict.get("source") or "extractive (TF-IDF + TextRank)"

    # Mitigation
    mitigation    = record.get("mitigation") or {}
    rule_mit      = mitigation.get("rule_based") or {}
    llm_narrative = mitigation.get("llm_narrative")

    # Explainable AI
    xai           = record.get("explainable_ai") or {}

    # Threat score
    ts_dict       = threat_score or record.get("threat_score") or {}
    t_score       = int(ts_dict.get("score") if ts_dict.get("score") is not None else 50)
    t_class       = str(ts_dict.get("classification") or "Moderate Risk")
    t_breakdown   = ts_dict.get("breakdown") or []
    t_explanation = str(ts_dict.get("explanation") or "")

    # Storyline
    sl_dict       = storyline or record.get("attack_storyline") or {}
    sl_stages     = sl_dict.get("stages") or []
    sl_summary    = sl_dict.get("summary") or ""

    # Affected Systems
    affected_sys  = extract_affected_systems(text, entities)

    # Timestamps
    try:
        dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        created_fmt = dt.strftime("%d %B %Y, %H:%M:%S UTC")
    except Exception:
        created_fmt = created_at or "Recent"

    now_fmt = datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M:%S UTC")

    # ══════════════════════════════════════════════════════════════════════════
    # COVER PAGE
    # ══════════════════════════════════════════════════════════════════════════
    story.append(Spacer(1, 28 * mm))
    story.append(Paragraph("◆ CIRIP", S["cover_title"]))
    story.append(Paragraph("Cyber Incident Report Intelligence Platform", S["cover_sub"]))
    story.append(Paragraph("ADVANCED THREAT FUSION & DEFENSIVE INTELLIGENCE", S["cover_badge"]))
    story.append(HRFlowable(width="70%", color=C_ACCENT, thickness=1, hAlign="CENTER"))
    story.append(Spacer(1, 10 * mm))

    # Key Metadata Table
    meta_table_data = [
        [Paragraph("<b>Incident Title:</b>", S["th"]),     Paragraph(_esc(title), S["td"])],
        [Paragraph("<b>Incident ID:</b>", S["th"]),        Paragraph(_esc(incident_id), S["td_code"])],
        [Paragraph("<b>Threat Classification:</b>", S["th"]), Paragraph(f"<b>{_esc(itype_label)}</b> ({itype_conf * 100:.1f}% conf)", S["td"])],
        [Paragraph("<b>Severity Rating:</b>", S["th"]),    Paragraph(f"<font color='{SEV_COLOR.get(sev_label, C_TEXT).hexval()}'><b>{_esc(sev_label)}</b></font> ({sev_conf * 100:.1f}% conf)", S["td"])],
        [Paragraph("<b>Threat Intel Score:</b>", S["th"]), Paragraph(f"<b>{t_score}/100</b> — {_esc(t_class)}", S["td"])],
        [Paragraph("<b>Detected Language:</b>", S["th"]),   Paragraph(f"{_esc(det_lang_name)} ({_esc(det_lang_code)})", S["td"])],
        [Paragraph("<b>Incident Timestamp:</b>", S["th"]), Paragraph(_esc(created_fmt), S["td"])],
        [Paragraph("<b>Report Generated:</b>", S["th"]),   Paragraph(_esc(now_fmt), S["td"])],
    ]
    t_meta = Table(meta_table_data, colWidths=[52 * mm, 110 * mm])
    t_meta.setStyle(_table_style(header_color=C_CARD))
    story.append(t_meta)

    story.append(Spacer(1, 8 * mm))

    # Threat Score Visual Gauge on Cover
    story.append(_create_threat_score_gauge(t_score, t_class))
    story.append(Spacer(1, 10 * mm))

    # Confidentiality notice
    notice_text = (
        "<b>CLASSIFICATION: TLP:AMBER // CIRIP RESTRICTED</b><br/>"
        "This defensive intelligence document was automatically generated by the "
        "Cyber Incident Report Intelligence Platform (CIRIP). All predictions, extracted "
        "IoCs, entity mappings, and mitigation guidelines are derived directly from the analyzed "
        "telemetry and clearly labeled by detection method."
    )
    story.append(Paragraph(notice_text, S["cover_notice"]))

    # Transition to content template
    story.append(NextPageTemplate("content"))
    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════════════
    # PAGE 2+: EXECUTIVE SUMMARY & ORIGINAL INCIDENT REPORT
    # ══════════════════════════════════════════════════════════════════════════

    # ── 1. Executive Summary ──────────────────────────────────────────────
    _add_section_header(story, S, "1. Executive & AI-Generated Summary")
    story.append(Paragraph(_esc(summary_text), S["body"]))
    story.append(Paragraph(f"<i>Attribution: {_esc(summary_source)}</i>", S["label"]))

    # ── 2. Original Incident Report & Language Intelligence ───────────────
    _add_section_header(story, S, "2. Original Incident Report & Language Intelligence")

    lang_desc = f"<b>Detected Input Language:</b> {_esc(det_lang_name)} [ISO code: {_esc(det_lang_code)}]"
    if trans_text:
        lang_desc += " — <i>(Automated neural translation to English performed for downstream NLP & ML pipeline)</i>"
    story.append(Paragraph(lang_desc, S["body"]))

    # Original text box
    story.append(Paragraph("<b>Submitted Incident Text:</b>", S["label_bold"]))
    raw_box_data = [[Paragraph(_esc(orig_text), S["body_box"])]]
    raw_box = Table(raw_box_data, colWidths=[168 * mm])
    raw_box.setStyle(_callout_style(border_color=C_BORDER, bg_color=C_PANEL))
    story.append(raw_box)

    if trans_text:
        story.append(Spacer(1, 3 * mm))
        story.append(Paragraph("<b>Translated Text (English for ML Processing):</b>", S["label_bold"]))
        trans_box_data = [[Paragraph(_esc(trans_text), S["body_box"])]]
        trans_box = Table(trans_box_data, colWidths=[168 * mm])
        trans_box.setStyle(_callout_style(border_color=C_CYAN, bg_color=C_CARD))
        story.append(trans_box)

    # ── 3. Threat Classification & Severity Analysis ──────────────────────
    _add_section_header(story, S, "3. Incident Classification & Severity Analysis")
    
    class_table_data = [
        [Paragraph("Dimension", S["th"]), Paragraph("Predicted Value", S["th"]), Paragraph("Confidence", S["th"]), Paragraph("Engine / Model", S["th"])],
        [
            Paragraph("Incident Type", S["td"]),
            Paragraph(f"<b>{_esc(itype_label)}</b>", S["td"]),
            Paragraph(f"{itype_conf * 100:.1f}%", S["td"]),
            Paragraph(_esc(itype_source), S["td_muted"]),
        ],
        [
            Paragraph("Severity Level", S["td"]),
            Paragraph(f"<font color='{SEV_COLOR.get(sev_label, C_TEXT).hexval()}'><b>{_esc(sev_label)}</b></font>", S["td"]),
            Paragraph(f"{sev_conf * 100:.1f}%", S["td"]),
            Paragraph(_esc(sev_source), S["td_muted"]),
        ],
    ]
    t_class_tbl = Table(class_table_data, colWidths=[38 * mm, 45 * mm, 25 * mm, 60 * mm])
    t_class_tbl.setStyle(_table_style())
    story.append(t_class_tbl)

    # Class probabilities chart
    if itype_probs:
        story.append(Spacer(1, 3 * mm))
        story.append(_create_probability_barchart(itype_probs))

    # ── 4. Threat Intelligence Score & Breakdown ──────────────────────────
    _add_section_header(story, S, "4. Threat Intelligence Scoring & Risk Assessment")
    story.append(Paragraph(
        f"<b>Calculated Threat Score: {t_score} / 100</b> — Risk Classification: <b>{_esc(t_class)}</b>",
        S["body_bold"]
    ))
    if t_explanation:
        story.append(Paragraph(_esc(t_explanation), S["body"]))

    if t_breakdown:
        story.append(Spacer(1, 2 * mm))
        bd_rows = [
            [Paragraph("Risk Factor / Reason", S["th"]), Paragraph("Points", S["th"]), Paragraph("Category", S["th"])]
        ]
        for b in t_breakdown:
            pts = b.get("points", 0)
            sign = f"+{pts}" if pts > 0 else str(pts)
            bd_rows.append([
                Paragraph(_esc(b.get("reason", "—")), S["td"]),
                Paragraph(f"<b>{sign}</b>", S["td"]),
                Paragraph(_esc(b.get("category", "General")), S["td_muted"]),
            ])
        t_bd = Table(bd_rows, colWidths=[108 * mm, 25 * mm, 35 * mm])
        t_bd.setStyle(_table_style(header_color=C_CARD))
        story.append(t_bd)

    # ── 5. Indicators of Compromise (IoCs) ─────────────────────────────────
    _add_section_header(story, S, "5. Extracted Indicators of Compromise (IoCs)")
    story.append(Paragraph("<i>Detection method: Rule-based regular expression extraction</i>", S["label"]))

    # Specific subsections: Suspicious IPs, URLs, Domains, Emails, Hashes
    ipv4s = iocs.get("ipv4_addresses") or []
    ipv6s = iocs.get("ipv6_addresses") or []
    all_ips = ipv4s + ipv6s
    urls   = iocs.get("urls") or []
    domains= iocs.get("domains") or []
    emails = iocs.get("emails") or []
    cves   = iocs.get("cves") or []
    fhashes= iocs.get("file_hashes") or {}

    ioc_table_data = [
        [Paragraph("IoC Category", S["th"]), Paragraph("Observed Values in Telemetry", S["th"])]
    ]

    ioc_table_data.append([
        Paragraph("<b>Suspicious IP Addresses:</b>", S["td"]),
        Paragraph(_esc(", ".join(all_ips)) if all_ips else "<i>None detected</i>", S["td_code"] if all_ips else S["td_muted"])
    ])
    ioc_table_data.append([
        Paragraph("<b>Target / Host Domains:</b>", S["td"]),
        Paragraph(_esc(", ".join(domains[:10])) if domains else "<i>None detected</i>", S["td_code"] if domains else S["td_muted"])
    ])
    ioc_table_data.append([
        Paragraph("<b>Suspicious URLs:</b>", S["td"]),
        Paragraph(_esc(", ".join(urls[:8])) if urls else "<i>None detected</i>", S["td_code"] if urls else S["td_muted"])
    ])
    ioc_table_data.append([
        Paragraph("<b>Suspicious Email Addresses:</b>", S["td"]),
        Paragraph(_esc(", ".join(emails)) if emails else "<i>None detected</i>", S["td_code"] if emails else S["td_muted"])
    ])

    # Hashes
    hash_entries = []
    for ht in ("md5", "sha1", "sha256"):
        hvals = fhashes.get(ht) or []
        if hvals:
            hash_entries.append(f"<b>{ht.upper()}:</b> " + ", ".join(hvals[:3]))
    ioc_table_data.append([
        Paragraph("<b>Malware File Hashes:</b>", S["td"]),
        Paragraph("<br/>".join([_esc(h) for h in hash_entries]) if hash_entries else "<i>No file hashes extracted</i>", S["td_code"] if hash_entries else S["td_muted"])
    ])

    if cves:
        ioc_table_data.append([
            Paragraph("<b>Referenced CVEs:</b>", S["td"]),
            Paragraph(_esc(", ".join(cves)), S["td_code"])
        ])

    t_ioc = Table(ioc_table_data, colWidths=[50 * mm, 118 * mm])
    t_ioc.setStyle(_table_style())
    story.append(t_ioc)

    # ── 6. Detected Entities & Malware Information ─────────────────────────
    _add_section_header(story, S, "6. Detected Entities & Malware Information")
    story.append(Paragraph("<i>Detection method: Domain gazetteers + regex heuristics (Lightweight NER)</i>", S["label"]))

    malware_fams = entities.get("malware_families") or []
    attack_kws   = entities.get("attack_keywords") or []
    users        = entities.get("users") or []
    orgs         = entities.get("organizations") or []
    ent_cves     = entities.get("cves") or []

    ent_table_data = [
        [Paragraph("Entity Type", S["th"]), Paragraph("Extracted Entities", S["th"])]
    ]
    ent_table_data.append([
        Paragraph("<b>Malware Families:</b>", S["td"]),
        Paragraph(_esc(", ".join(malware_fams)) if malware_fams else "<i>No specific malware family detected in signature DB</i>", S["td_bold"] if malware_fams else S["td_muted"])
    ])
    ent_table_data.append([
        Paragraph("<b>Attack Keywords / Techniques:</b>", S["td"]),
        Paragraph(_esc(", ".join(attack_kws)) if attack_kws else "<i>None detected</i>", S["td"])
    ])
    ent_table_data.append([
        Paragraph("<b>Compromised / User Accounts:</b>", S["td"]),
        Paragraph(_esc(", ".join(users)) if users else "<i>No specific user accounts identified</i>", S["td"])
    ])
    ent_table_data.append([
        Paragraph("<b>Targeted Organizations:</b>", S["td"]),
        Paragraph(_esc(", ".join(orgs)) if orgs else "<i>No external organizations referenced</i>", S["td"])
    ])
    if ent_cves:
        ent_table_data.append([
            Paragraph("<b>Vulnerability IDs:</b>", S["td"]),
            Paragraph(_esc(", ".join(ent_cves)), S["td_code"])
        ])

    t_ent = Table(ent_table_data, colWidths=[50 * mm, 118 * mm])
    t_ent.setStyle(_table_style(header_color=C_CARD))
    story.append(t_ent)

    # ── 7. Attack Method & MITRE ATT&CK Storyline ─────────────────────────
    _add_section_header(story, S, "7. Attack Method & MITRE ATT&CK Storyline")
    if sl_summary:
        story.append(Paragraph(f"<b>Attack Progression:</b> {_esc(sl_summary)}", S["body_bold"]))

    if sl_stages:
        story.append(Spacer(1, 2 * mm))
        story.append(_create_storyline_flowchart(sl_stages))
        story.append(Spacer(1, 3 * mm))

        sl_table_data = [
            [Paragraph("Stage", S["th"]), Paragraph("MITRE Tactic", S["th"]), Paragraph("Evidence / Indicators", S["th"]), Paragraph("Confidence", S["th"])]
        ]
        for st in sl_stages:
            ev_list = st.get("evidence") or []
            ev_str = "; ".join(ev_list[:3]) or st.get("note") or "Inferred by incident pattern"
            sl_table_data.append([
                Paragraph(_esc(st.get("name", "—")), S["td"]),
                Paragraph(_esc(st.get("mitre_tactic", "—")), S["td_code"]),
                Paragraph(_esc(ev_str[:120]), S["td"]),
                Paragraph(f"{st.get('confidence', 0)}% ({_esc(st.get('evidence_label', 'inferred'))})", S["td_muted"]),
            ])
        t_sl = Table(sl_table_data, colWidths=[38 * mm, 25 * mm, 75 * mm, 30 * mm])
        t_sl.setStyle(_table_style())
        story.append(t_sl)
    else:
        story.append(Paragraph("Insufficient cross-stage indicators to construct a multi-stage attack storyline.", S["body"]))

    # ── 8. Affected Systems & Infrastructure Scope ────────────────────────
    _add_section_header(story, S, "8. Affected Systems & Infrastructure Scope")
    story.append(Paragraph(
        "Identified assets, hosts, databases, and network components potentially impacted:",
        S["body"]
    ))
    sys_rows = [
        [Paragraph("Affected System / Asset", S["th"]), Paragraph("Impact Scope & Status", S["th"])]
    ]
    for sys_item in affected_sys:
        sys_rows.append([
            Paragraph(f"• <b>{_esc(sys_item)}</b>", S["td"]),
            Paragraph(f"Targeted or referenced in {itype_label} incident telemetry", S["td_muted"]),
        ])
    t_sys = Table(sys_rows, colWidths=[65 * mm, 103 * mm])
    t_sys.setStyle(_table_style(header_color=C_CARD))
    story.append(t_sys)

    # ── 9. NLP Analysis & Explainable AI (XAI) ────────────────────────────
    _add_section_header(story, S, "9. NLP Analysis & Explainable AI (XAI)")
    story.append(Paragraph(
        "<i>Feature contributions calculated via TF-IDF weight × Logistic Regression coefficient for predicted class:</i>",
        S["label"]
    ))

    itype_feats = xai.get("incident_type_top_features") or []
    if itype_feats:
        xai_rows = [
            [Paragraph("Feature Word / N-Gram", S["th"]), Paragraph("TF-IDF Weight", S["th"]), Paragraph("Model Contribution", S["th"])]
        ]
        for f in itype_feats[:6]:
            w = f.get("tfidf_weight", 0.0)
            c = f.get("contribution", 0.0)
            xai_rows.append([
                Paragraph(_esc(f.get("feature", "—")), S["td_code"]),
                Paragraph(f"{w:.4f}", S["td"]),
                Paragraph(f"+{c:.4f}" if c > 0 else f"{c:.4f}", S["td_bold"] if c > 0.1 else S["td"]),
            ])
        t_xai = Table(xai_rows, colWidths=[68 * mm, 50 * mm, 50 * mm])
        t_xai.setStyle(_table_style())
        story.append(t_xai)
    else:
        story.append(Paragraph("Explainable AI feature weights unavailable.", S["body"]))

    # ── 10. Recommended Actions & Mitigation Strategy ─────────────────────
    _add_section_header(story, S, "10. Recommended Actions & Mitigation Strategy")

    actions = [
        ("Immediate Response", rule_mit.get("immediate_response") or []),
        ("Containment Measures", rule_mit.get("containment") or []),
        ("Recovery Procedures", rule_mit.get("recovery") or []),
        ("Long-Term Prevention", rule_mit.get("prevention") or []),
    ]

    for label, items in actions:
        if items:
            story.append(Paragraph(f"<b>{label}:</b>", S["sub_head"]))
            for it in items:
                story.append(Paragraph(f"• {_esc(it)}", S["body"]))

    sev_guidance = rule_mit.get("severity_guidance")
    if sev_guidance:
        story.append(Spacer(1, 2 * mm))
        story.append(Paragraph(f"<b>Severity Operational Guidance:</b> {_esc(sev_guidance)}", S["body_bold"]))

    if llm_narrative:
        story.append(Spacer(1, 2 * mm))
        story.append(Paragraph("<b>AI Strategic Advisory:</b>", S["sub_head"]))
        story.append(Paragraph(_esc(llm_narrative), S["body"]))

    # ── 11. Campaign Intelligence & Similar Incidents ─────────────────────
    if campaign or similar_incidents:
        _add_section_header(story, S, "11. Cross-Incident Correlations & Campaign Intel")

        if campaign:
            c_name = campaign.get("name", "Unknown Campaign")
            c_lvl  = campaign.get("threat_level", "Medium")
            c_cnt  = campaign.get("incident_count", 1)
            story.append(Paragraph(
                f"<b>Threat Campaign Affiliation:</b> {_esc(c_name)} "
                f"(Threat Level: <b>{_esc(c_lvl)}</b>, Spanning {c_cnt} incident(s))",
                S["body_bold"]
            ))

        if similar_incidents:
            story.append(Spacer(1, 2 * mm))
            story.append(Paragraph("<b>Top Correlated Historical Incidents:</b>", S["label_bold"]))
            sim_rows = [
                [Paragraph("Historical Incident Title", S["th"]), Paragraph("Type", S["th"]), Paragraph("Severity", S["th"]), Paragraph("Similarity", S["th"])]
            ]
            for si in similar_incidents[:5]:
                stitle = si.get("title") or si.get("incident_title") or "Historical Incident"
                stype  = si.get("incident_type") or "—"
                ssev   = si.get("severity") or "—"
                score_val = si.get("similarity_score", si.get("confidence", 0.0))
                sim_str = f"{float(score_val) * 100:.1f}%" if isinstance(score_val, (int, float)) else "—"
                sim_rows.append([
                    Paragraph(_esc(stitle[:45]), S["td"]),
                    Paragraph(_esc(stype), S["td"]),
                    Paragraph(_esc(ssev), S["td"]),
                    Paragraph(sim_str, S["td_code"]),
                ])
            t_sim = Table(sim_rows, colWidths=[68 * mm, 38 * mm, 32 * mm, 30 * mm])
            t_sim.setStyle(_table_style(header_color=C_CARD))
            story.append(t_sim)

    # ── BUILD DOCUMENT ────────────────────────────────────────────────────
    doc.build(story)
    return buf.getvalue()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _add_section_header(story: list, S: dict, title: str):
    story.append(Spacer(1, 3 * mm))
    story.append(HRFlowable(width="100%", color=C_ACCENT, thickness=0.75, spaceBefore=4, spaceAfter=4))
    story.append(Paragraph(title, S["section_head"]))


def _esc(text: Any) -> str:
    """Escape XML special chars safely for ReportLab Paragraph."""
    if text is None:
        return "—"
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
        .replace("\n", "<br/>")
    )
