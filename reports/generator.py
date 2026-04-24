"""
PDF report generator for pentest engagements using ReportLab.
Generates professional penetration testing reports with:
- Cover page (branded via ReportTemplate)
- Executive summary with risk score
- Findings summary table (grouped by host)
- Detailed findings with CVSS vectors
- Remediation recommendations
"""
import io
import math
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from xml.sax.saxutils import escape as xml_escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, Image,
)
from reportlab.lib.enums import TA_CENTER


def _esc(text):
    """Escape text for ReportLab XML-based Paragraph."""
    if not text:
        return ''
    return xml_escape(str(text))


# Severity colors are intentionally fixed — red means critical in every
# pentest report, and shouldn't be themeable. Brand (cover, headers, rules)
# comes from the ReportTemplate instead.
SEVERITY_COLORS = {
    'critical': colors.HexColor('#E24B4A'),
    'high': colors.HexColor('#D85A30'),
    'medium': colors.HexColor('#EF9F27'),
    'low': colors.HexColor('#378ADD'),
    'info': colors.HexColor('#888780'),
}


@dataclass
class _Brand:
    """Resolved brand kit used by the generator — colors, logos, boilerplate.

    Populated from a ReportTemplate if one is picked (explicitly, via the
    engagement's client, or the global default); otherwise a hard-coded
    fallback matching the original look.
    """
    primary: colors.Color
    accent: colors.Color
    template_logo_path: str | None
    client_logo_path: str | None
    preamble: str
    disclaimer: str
    footer_text: str


def _resolve_template(engagement, template=None):
    """Pick a ReportTemplate. Explicit arg > client default > global default.
    Returns None if nothing is configured — caller falls back to built-in.
    """
    if template is not None:
        return template
    from engagements.models import Client  # avoid circular import
    client = getattr(engagement, 'client', None)
    if client and client.default_report_template_id:
        return client.default_report_template
    from .models import ReportTemplate
    return ReportTemplate.objects.filter(is_default=True).first()


def _build_brand(engagement, template):
    """Materialize a _Brand from the template (or defaults)."""
    if template:
        primary = colors.HexColor(template.primary_color)
        accent = colors.HexColor(template.accent_color)
        tpl_logo = template.cover_logo.path if template.cover_logo else None
        preamble = template.preamble_markdown
        disclaimer = template.disclaimer_markdown
        footer = template.footer_text
    else:
        primary = colors.HexColor('#534AB7')
        accent = colors.HexColor('#378ADD')
        tpl_logo = None
        preamble = ''
        disclaimer = ''
        footer = ''

    client = getattr(engagement, 'client', None)
    client_logo = None
    if client and getattr(client, 'logo', None):
        try:
            client_logo = client.logo.path
        except (ValueError, FileNotFoundError):
            client_logo = None

    return _Brand(
        primary=primary, accent=accent,
        template_logo_path=tpl_logo, client_logo_path=client_logo,
        preamble=preamble, disclaimer=disclaimer, footer_text=footer,
    )


def _footer_drawer(footer_text: str, accent: colors.Color):
    """Return an onPage callback that paints `footer_text` + page # on every page."""
    def _draw(canvas, doc):
        canvas.saveState()
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(colors.HexColor('#666666'))
        if footer_text:
            canvas.drawString(20 * mm, 12 * mm, footer_text[:200])
        page_str = f'Page {doc.page}'
        canvas.drawRightString(A4[0] - 20 * mm, 12 * mm, page_str)
        canvas.setStrokeColor(accent)
        canvas.setLineWidth(0.5)
        canvas.line(20 * mm, 15 * mm, A4[0] - 20 * mm, 15 * mm)
        canvas.restoreState()
    return _draw


def _logo_flowable(path: str, max_width=2.2 * inch, max_height=1.1 * inch):
    """Scale a logo to fit within the given box without distortion."""
    try:
        img = Image(path)
    except Exception:
        return None
    if img.imageWidth <= 0 or img.imageHeight <= 0:
        return None
    ratio = min(max_width / img.imageWidth, max_height / img.imageHeight, 1.0)
    img.drawWidth = img.imageWidth * ratio
    img.drawHeight = img.imageHeight * ratio
    img.hAlign = 'CENTER'
    return img


def generate_report_pdf(engagement, report_type='full', template=None, cover_only=False):
    """Generate a PDF report for the given engagement. Returns bytes.

    ``template`` overrides the resolved ReportTemplate; when absent, the
    engagement's client default is used, else the library's default, else
    a hard-coded brand. ``cover_only=True`` renders just the cover page as
    a preview for the template picker.
    """
    template = _resolve_template(engagement, template)
    brand = _build_brand(engagement, template)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        topMargin=25 * mm, bottomMargin=25 * mm,
        leftMargin=20 * mm, rightMargin=20 * mm,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    styles.add(ParagraphStyle(
        'CoverTitle', parent=styles['Title'], fontSize=28, spaceAfter=12,
        textColor=colors.HexColor('#1a1a1a'), alignment=TA_CENTER
    ))
    styles.add(ParagraphStyle(
        'CoverSubtitle', parent=styles['Normal'], fontSize=14,
        textColor=colors.HexColor('#666666'), alignment=TA_CENTER, spaceAfter=6
    ))
    styles.add(ParagraphStyle(
        'SectionHeading', parent=styles['Heading1'], fontSize=18,
        textColor=colors.HexColor('#1a1a1a'), spaceBefore=20, spaceAfter=10,
        borderWidth=0, borderPadding=0,
    ))
    styles.add(ParagraphStyle(
        'SubHeading', parent=styles['Heading2'], fontSize=14,
        textColor=colors.HexColor('#333333'), spaceBefore=14, spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        'BodyText2', parent=styles['Normal'], fontSize=10,
        leading=14, spaceAfter=8,
    ))

    elements = []

    # ── Cover page ──
    for logo_path in (brand.client_logo_path, brand.template_logo_path):
        if not logo_path:
            continue
        img = _logo_flowable(logo_path)
        if img is not None:
            elements.append(Spacer(1, 1 * inch))
            elements.append(img)
            elements.append(Spacer(1, 0.3 * inch))
            break
    else:
        elements.append(Spacer(1, 2 * inch))

    elements.append(Paragraph('PENETRATION TEST REPORT', styles['CoverTitle']))
    elements.append(Spacer(1, 0.3 * inch))
    elements.append(HRFlowable(width='60%', color=brand.primary, thickness=2))
    elements.append(Spacer(1, 0.3 * inch))
    elements.append(Paragraph(_esc(engagement.name), styles['CoverSubtitle']))
    elements.append(Paragraph(f'Client: {_esc(engagement.client_name)}', styles['CoverSubtitle']))
    elements.append(Paragraph(
        f'Type: {engagement.get_engagement_type_display()}', styles['CoverSubtitle']
    ))
    elements.append(Spacer(1, 0.5 * inch))
    date_range = ''
    if engagement.start_date and engagement.end_date:
        date_range = f'{engagement.start_date.strftime("%B %d, %Y")} — {engagement.end_date.strftime("%B %d, %Y")}'
    elif engagement.start_date:
        date_range = f'Started: {engagement.start_date.strftime("%B %d, %Y")}'
    elements.append(Paragraph(date_range, styles['CoverSubtitle']))
    elements.append(Paragraph(
        f'Generated: {datetime.now().strftime("%B %d, %Y")}', styles['CoverSubtitle']
    ))
    elements.append(Spacer(1, 0.5 * inch))
    elements.append(Paragraph('CONFIDENTIAL', ParagraphStyle(
        'Conf', parent=styles['Normal'], fontSize=12, alignment=TA_CENTER,
        textColor=colors.HexColor('#E24B4A'), fontName='Helvetica-Bold',
    )))

    if cover_only:
        doc.build(
            elements,
            onFirstPage=_footer_drawer(brand.footer_text, brand.accent),
            onLaterPages=_footer_drawer(brand.footer_text, brand.accent),
        )
        buffer.seek(0)
        return buffer.getvalue()

    elements.append(PageBreak())

    # Findings query — deferred until past the cover-only bailout so the
    # template preview endpoint can render with an unsaved engagement stub.
    findings = engagement.findings.all().order_by(
        models_severity_order(), '-cvss_score'
    )

    # ── Table of contents placeholder ──
    elements.append(Paragraph('Table of contents', styles['SectionHeading']))
    toc_items = ['1. Executive summary', '2. Scope', '3. Findings summary',
                 '4. Detailed findings', '5. Remediation recommendations']
    for item in toc_items:
        elements.append(Paragraph(item, styles['BodyText2']))
    elements.append(PageBreak())

    # ── 1. Executive summary ──
    elements.append(Paragraph('1. Executive summary', styles['SectionHeading']))

    if brand.preamble:
        for line in brand.preamble.splitlines():
            if line.strip():
                elements.append(Paragraph(_esc(line.strip()), styles['BodyText2']))
        elements.append(Spacer(1, 8))

    total = findings.count()
    crit = findings.filter(severity='critical').count()
    high = findings.filter(severity='high').count()
    med = findings.filter(severity='medium').count()
    low = findings.filter(severity='low').count()
    info = findings.filter(severity='info').count()

    exec_text = (
        f'A {engagement.get_engagement_type_display().lower()} was conducted against '
        f'{engagement.client_name} targeting the agreed-upon scope. '
        f'A total of <b>{total}</b> findings were identified: '
        f'<font color="#E24B4A"><b>{crit} critical</b></font>, '
        f'<font color="#D85A30"><b>{high} high</b></font>, '
        f'<font color="#EF9F27"><b>{med} medium</b></font>, '
        f'<font color="#378ADD"><b>{low} low</b></font>, and '
        f'<font color="#888780"><b>{info} informational</b></font>.'
    )
    elements.append(Paragraph(exec_text, styles['BodyText2']))

    if engagement.description:
        elements.append(Spacer(1, 8))
        elements.append(Paragraph(_esc(engagement.description), styles['BodyText2']))

    elements.append(Spacer(1, 12))

    # Severity summary table
    summary_data = [
        ['Severity', 'Count'],
        ['Critical', str(crit)],
        ['High', str(high)],
        ['Medium', str(med)],
        ['Low', str(low)],
        ['Informational', str(info)],
        ['Total', str(total)],
    ]
    summary_table = Table(summary_data, colWidths=[120, 60])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), brand.primary),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('ALIGN', (1, 0), (1, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -2), [colors.white, colors.HexColor('#f8f8f8')]),
        ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor('#f0f0f0')),
        ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(summary_table)
    elements.append(PageBreak())

    # ── 2. Scope ──
    elements.append(Paragraph('2. Scope', styles['SectionHeading']))
    elements.append(Paragraph('<b>In-scope targets:</b>', styles['BodyText2']))
    for target in engagement.scope_targets:
        elements.append(Paragraph(f'&bull; {_esc(target)}', styles['BodyText2']))

    if engagement.out_of_scope:
        elements.append(Spacer(1, 8))
        elements.append(Paragraph('<b>Out-of-scope:</b>', styles['BodyText2']))
        for target in engagement.out_of_scope.splitlines():
            if target.strip():
                elements.append(Paragraph(f'&bull; {_esc(target.strip())}', styles['BodyText2']))

    if engagement.rules_of_engagement:
        elements.append(Spacer(1, 8))
        elements.append(Paragraph('<b>Rules of engagement:</b>', styles['BodyText2']))
        elements.append(Paragraph(_esc(engagement.rules_of_engagement), styles['BodyText2']))
    elements.append(PageBreak())

    # ── Risk score ──
    risk_score = calculate_engagement_risk_score(findings)

    elements.append(Spacer(1, 12))
    risk_label, risk_color = _risk_label(risk_score)
    elements.append(Paragraph(
        f'Overall risk score: <font color="{risk_color}"><b>{risk_score:.1f}/10 ({risk_label})</b></font>',
        styles['BodyText2'],
    ))
    elements.append(PageBreak())

    # ── 3. Findings summary (grouped by host) ──
    elements.append(Paragraph('3. Findings summary', styles['SectionHeading']))

    if total > 0:
        # Group findings by host
        host_groups = _group_findings_by_host(findings)

        # Per-host risk summary table
        elements.append(Paragraph('<b>Risk by asset</b>', styles['BodyText2']))
        host_summary_data = [['Asset', 'Findings', 'Highest', 'Risk Score']]
        for host_label, host_findings in host_groups:
            host_risk = calculate_engagement_risk_score(host_findings)
            worst = host_findings[0]  # already sorted by severity
            host_summary_data.append([
                Paragraph(_esc(host_label[:50]), styles['BodyText2']),
                str(len(host_findings)),
                worst.get_severity_display(),
                f'{host_risk:.1f}',
            ])

        host_summary_table = Table(host_summary_data, colWidths=[200, 55, 65, 65])
        host_summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), brand.primary),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f8f8')]),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        elements.append(host_summary_table)
        elements.append(Spacer(1, 16))

        # Full findings table
        elements.append(Paragraph('<b>All findings</b>', styles['BodyText2']))
        findings_table_data = [['#', 'Title', 'Severity', 'CVSS', 'Status']]
        for i, f in enumerate(findings, 1):
            findings_table_data.append([
                str(i),
                Paragraph(_esc(f.title[:80]), styles['BodyText2']),
                f.get_severity_display(),
                f'{f.cvss_score:.1f}' if f.cvss_score else 'N/A',
                f.get_status_display(),
            ])

        col_widths = [25, 250, 65, 45, 75]
        findings_table = Table(findings_table_data, colWidths=col_widths)
        table_style = [
            ('BACKGROUND', (0, 0), (-1, 0), brand.primary),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (0, 0), (0, -1), 'CENTER'),
            ('ALIGN', (3, 0), (3, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f8f8')]),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]
        for i, f in enumerate(findings, 1):
            sev_color = SEVERITY_COLORS.get(f.severity, colors.gray)
            table_style.append(('TEXTCOLOR', (2, i), (2, i), sev_color))
            table_style.append(('FONTNAME', (2, i), (2, i), 'Helvetica-Bold'))

        findings_table.setStyle(TableStyle(table_style))
        elements.append(findings_table)
    else:
        elements.append(Paragraph('No findings were identified.', styles['BodyText2']))
    elements.append(PageBreak())

    # ── 4. Detailed findings (grouped by host) ──
    if report_type in ('full', 'technical'):
        elements.append(Paragraph('4. Detailed findings', styles['SectionHeading']))

        if total > 0:
            host_groups = _group_findings_by_host(findings)
            finding_num = 0

            for host_label, host_findings in host_groups:
                # Host header
                host_risk = calculate_engagement_risk_score(host_findings)
                hr_label, hr_color = _risk_label(host_risk)
                elements.append(Paragraph(
                    f'<b>{_esc(host_label)}</b> &mdash; '
                    f'<font color="{hr_color}">{hr_label} ({host_risk:.1f})</font> &mdash; '
                    f'{len(host_findings)} finding{"s" if len(host_findings) != 1 else ""}',
                    styles['SubHeading'],
                ))
                elements.append(HRFlowable(
                    width='100%', color=brand.primary, thickness=1,
                ))
                elements.append(Spacer(1, 6))

                for f in host_findings:
                    finding_num += 1
                    sev_color = SEVERITY_COLORS.get(f.severity, colors.gray)
                    elements.append(Paragraph(
                        f'{finding_num}. {_esc(f.title)}', styles['SubHeading']
                    ))

                    info_data = [
                        ['Severity', f.get_severity_display()],
                        ['CVSS Score', f'{f.cvss_score:.1f}' if f.cvss_score else 'N/A'],
                        ['CVSS Vector', f.cvss_vector_string],
                        ['Status', f.get_status_display()],
                    ]
                    if f.host:
                        location = _esc(f.host)
                        if f.port:
                            location += f':{f.port}'
                        info_data.append(['Host', location])
                    if f.url:
                        info_data.append(['URL', _esc(f.url[:100])])
                    if f.endpoint:
                        method_str = f'{f.http_method} ' if f.http_method else ''
                        info_data.append(['Endpoint', f'{method_str}{_esc(f.endpoint)}'])
                    if f.parameter:
                        info_data.append(['Parameter', _esc(f.parameter)])
                    if f.cwe_id:
                        info_data.append(['CWE', f.cwe_id])
                    if f.affected_hosts:
                        info_data.append(['Other Hosts', _esc(f.affected_hosts[:200])])
                    if f.tool_source:
                        info_data.append(['Discovered By', f.tool_source])

                    info_table = Table(info_data, colWidths=[100, 360])
                    info_table.setStyle(TableStyle([
                        ('FONTSIZE', (0, 0), (-1, -1), 9),
                        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                        ('TEXTCOLOR', (1, 0), (1, 0), sev_color),
                        ('FONTNAME', (1, 0), (1, 0), 'Helvetica-Bold'),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dddddd')),
                        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f5f5f5')),
                        ('TOPPADDING', (0, 0), (-1, -1), 4),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                        ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ]))
                    elements.append(info_table)
                    elements.append(Spacer(1, 8))

                    elements.append(Paragraph('<b>Description</b>', styles['BodyText2']))
                    elements.append(Paragraph(_esc(f.description), styles['BodyText2']))

                    if f.proof_of_concept:
                        elements.append(Paragraph('<b>Proof of Concept</b>', styles['BodyText2']))
                        elements.append(Paragraph(
                            _esc(f.proof_of_concept).replace('\n', '<br/>'), styles['BodyText2']
                        ))

                    if f.remediation:
                        elements.append(Paragraph('<b>Remediation</b>', styles['BodyText2']))
                        elements.append(Paragraph(_esc(f.remediation), styles['BodyText2']))

                    if f.references:
                        elements.append(Paragraph('<b>References</b>', styles['BodyText2']))
                        for ref in f.references.splitlines():
                            if ref.strip():
                                elements.append(Paragraph(f'&bull; {_esc(ref.strip())}', styles['BodyText2']))

                    elements.append(HRFlowable(
                        width='100%', color=colors.HexColor('#eeeeee'), thickness=0.5
                    ))
                    elements.append(Spacer(1, 10))

                elements.append(PageBreak())

    # ── Disclaimer ──
    if brand.disclaimer:
        elements.append(Paragraph('Disclaimer', styles['SectionHeading']))
        for line in brand.disclaimer.splitlines():
            if line.strip():
                elements.append(Paragraph(_esc(line.strip()), styles['BodyText2']))

    # Build
    footer_cb = _footer_drawer(brand.footer_text, brand.accent)
    doc.build(elements, onFirstPage=footer_cb, onLaterPages=footer_cb)
    buffer.seek(0)
    return buffer.getvalue()


def models_severity_order():
    """Return a Case expression for ordering findings by severity."""
    from django.db.models import Case, When, Value, IntegerField
    return Case(
        When(severity='critical', then=Value(0)),
        When(severity='high', then=Value(1)),
        When(severity='medium', then=Value(2)),
        When(severity='low', then=Value(3)),
        When(severity='info', then=Value(4)),
        output_field=IntegerField(),
    )


def _group_findings_by_host(findings):
    """Group findings by their host field. Returns list of (host_label, [findings])."""
    groups = defaultdict(list)
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}

    for f in findings:
        host_label = f.host
        if not host_label and f.affected_hosts:
            host_label = f.affected_hosts.split('\n')[0].strip()
        if not host_label:
            host_label = 'General'
        groups[host_label].append(f)

    # Sort groups: highest-risk host first
    sorted_groups = sorted(
        groups.items(),
        key=lambda item: min(severity_order.get(f.severity, 99) for f in item[1]),
    )
    return sorted_groups


def calculate_engagement_risk_score(findings):
    """Calculate an aggregate risk score (0-10) for a set of findings.

    Uses a weighted formula that considers:
    - Severity distribution (critical findings weigh more)
    - Volume of open/confirmed findings
    - Highest individual CVSS score
    """
    severity_weights = {
        'critical': 10.0,
        'high': 7.5,
        'medium': 4.5,
        'low': 2.0,
        'info': 0.5,
    }

    if hasattr(findings, '__iter__') and not hasattr(findings, 'count'):
        finding_list = list(findings)
    else:
        finding_list = list(findings.all()) if hasattr(findings, 'all') else list(findings)

    if not finding_list:
        return 0.0

    # Only count open/confirmed findings for risk
    active = [f for f in finding_list if f.status in ('open', 'confirmed')]
    if not active:
        # All remediated/accepted — low residual risk
        return max(0.5, len(finding_list) * 0.1)

    # Weighted severity score
    weighted_sum = sum(severity_weights.get(f.severity, 0) for f in active)
    avg_weighted = weighted_sum / len(active)

    # Peak CVSS
    peak_cvss = max((f.cvss_score or 0) for f in active)

    # Volume factor: more active findings = higher risk, with diminishing returns
    volume_factor = min(1.0 + math.log10(max(len(active), 1)) * 0.3, 1.8)

    # Blend: 40% average severity, 40% peak CVSS, 20% volume-adjusted
    score = (avg_weighted * 0.4 + peak_cvss * 0.4 + avg_weighted * volume_factor * 0.2)

    return min(round(score, 1), 10.0)


def _risk_label(score):
    """Return (label, hex_color) for a risk score."""
    if score >= 9.0:
        return 'Critical', '#E24B4A'
    elif score >= 7.0:
        return 'High', '#D85A30'
    elif score >= 4.0:
        return 'Medium', '#EF9F27'
    elif score >= 0.1:
        return 'Low', '#378ADD'
    return 'Info', '#888780'
