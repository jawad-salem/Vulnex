"""
PDF report generator for pentest engagements using ReportLab.
Generates professional penetration testing reports with:
- Cover page
- Executive summary
- Findings summary table
- Detailed findings with CVSS vectors
- Remediation recommendations
"""
import io
from datetime import datetime
from xml.sax.saxutils import escape as xml_escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable
)
from reportlab.lib.enums import TA_CENTER


def _esc(text):
    """Escape text for ReportLab XML-based Paragraph."""
    if not text:
        return ''
    return xml_escape(str(text))


SEVERITY_COLORS = {
    'critical': colors.HexColor('#E24B4A'),
    'high': colors.HexColor('#D85A30'),
    'medium': colors.HexColor('#EF9F27'),
    'low': colors.HexColor('#378ADD'),
    'info': colors.HexColor('#888780'),
}


def generate_report_pdf(engagement, report_type='full'):
    """Generate a PDF report for the given engagement. Returns bytes."""
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
    findings = engagement.findings.all().order_by(
        models_severity_order(), '-cvss_score'
    )

    # ── Cover page ──
    elements.append(Spacer(1, 2 * inch))
    elements.append(Paragraph('PENETRATION TEST REPORT', styles['CoverTitle']))
    elements.append(Spacer(1, 0.3 * inch))
    elements.append(HRFlowable(width='60%', color=colors.HexColor('#534AB7'), thickness=2))
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
    elements.append(PageBreak())

    # ── Table of contents placeholder ──
    elements.append(Paragraph('Table of contents', styles['SectionHeading']))
    toc_items = ['1. Executive summary', '2. Scope', '3. Findings summary',
                 '4. Detailed findings', '5. Remediation recommendations']
    for item in toc_items:
        elements.append(Paragraph(item, styles['BodyText2']))
    elements.append(PageBreak())

    # ── 1. Executive summary ──
    elements.append(Paragraph('1. Executive summary', styles['SectionHeading']))
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
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#534AB7')),
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

    # ── 3. Findings summary ──
    elements.append(Paragraph('3. Findings summary', styles['SectionHeading']))

    if total > 0:
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
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#534AB7')),
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
        # Color severity column
        for i, f in enumerate(findings, 1):
            sev_color = SEVERITY_COLORS.get(f.severity, colors.gray)
            table_style.append(('TEXTCOLOR', (2, i), (2, i), sev_color))
            table_style.append(('FONTNAME', (2, i), (2, i), 'Helvetica-Bold'))

        findings_table.setStyle(TableStyle(table_style))
        elements.append(findings_table)
    else:
        elements.append(Paragraph('No findings were identified.', styles['BodyText2']))
    elements.append(PageBreak())

    # ── 4. Detailed findings ──
    if report_type in ('full', 'technical'):
        elements.append(Paragraph('4. Detailed findings', styles['SectionHeading']))
        for i, f in enumerate(findings, 1):
            sev_color = SEVERITY_COLORS.get(f.severity, colors.gray)
            elements.append(Paragraph(
                f'{i}. {f.title}', styles['SubHeading']
            ))

            # Info box
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

    # Build
    doc.build(elements)
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

