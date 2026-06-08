"""Markdown → ReportLab flowables for the PDF generator.

Finding bodies are stored as Markdown and rendered to sanitized HTML by
``vulns.templatetags.vulns_extras.render_markdown`` (the same pipeline the web
UI uses). This module walks that sanitized HTML and lowers it into ReportLab
``Paragraph`` / ``Table`` / ``HRFlowable`` flowables so the PDF matches the live
rendering.

Lives in ``reports`` rather than the templatetag because it is PDF-generation
logic, not template rendering — only ``reports.generator`` imports it.
"""
from html.parser import HTMLParser
from xml.sax.saxutils import escape as xml_escape
import re

from vulns.templatetags.vulns_extras import render_markdown


class _PlatypusBuilder(HTMLParser):
    """Walk sanitized HTML and emit a list of (kind, payload) tuples that the
    ReportLab generator can lower into flowables. Keeping this independent of
    ReportLab itself makes it easy to unit-test.

    Emitted shapes:
      ('para', html_inline, style_hint)         e.g. style_hint in
          {'body','h1',…,'h6','pre','blockquote','li','oli'}
      ('hr',)
      ('table', [[cell_html, …], …], has_header)
    """

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.blocks: list[tuple] = []
        self._stack: list[str] = []  # nesting of block elements
        self._inline: list[str] = []  # current inline-html buffer
        # List ordering — push 'ul'/'ol' on encounter, track <ol> counters.
        self._list_kinds: list[str] = []
        self._list_counters: list[int] = []
        # Tables
        self._cur_table: list[list[str]] | None = None
        self._cur_row: list[str] | None = None
        self._table_has_header: bool = False

    # — helpers —
    def _flush_para(self, style: str = 'body'):
        text = ''.join(self._inline).strip()
        self._inline = []
        if not text:
            return
        self.blocks.append(('para', text, style))

    def _push_inline(self, s: str):
        self._inline.append(s)

    # — handler overrides —
    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)
        if tag in ('strong', 'b'):
            self._push_inline('<b>')
        elif tag in ('em', 'i'):
            self._push_inline('<i>')
        elif tag == 'code':
            # Inline code gets the courier face inside paragraphs; <pre><code>
            # is handled by the surrounding <pre> rule.
            if self._stack and self._stack[-1] == 'pre':
                return
            self._push_inline('<font face="Courier">')
        elif tag == 'a':
            # Escape &, <, > and " so the URL is a well-formed XML attribute for
            # ReportLab's paragraph parser — a bare '&' (e.g. ?a=1&b=2) would
            # otherwise raise and abort PDF generation.
            href = xml_escape(attr_dict.get('href', ''), {'"': '&quot;'})
            self._push_inline(f'<link href="{href}" color="#378ADD">')
        elif tag == 'br':
            self._push_inline('<br/>')
        elif tag in ('p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'pre', 'blockquote'):
            self._flush_para()
            self._stack.append(tag)
        elif tag in ('ul', 'ol'):
            self._flush_para()
            self._list_kinds.append(tag)
            self._list_counters.append(0)
        elif tag == 'li':
            self._flush_para()
            self._stack.append('li')
            kind = self._list_kinds[-1] if self._list_kinds else 'ul'
            if kind == 'ol':
                self._list_counters[-1] += 1
                num = self._list_counters[-1]
                self._push_inline(f'<b>{num}.</b>&nbsp;')
            else:
                self._push_inline('&bull;&nbsp;')
        elif tag == 'hr':
            self._flush_para()
            self.blocks.append(('hr',))
        elif tag == 'table':
            self._flush_para()
            self._cur_table = []
            self._table_has_header = False
            self._stack.append('table')
        elif tag == 'thead':
            self._table_has_header = True
        elif tag == 'tr':
            self._cur_row = []
        elif tag in ('td', 'th'):
            self._flush_para()
            self._stack.append(tag)

    def handle_endtag(self, tag):
        if tag in ('strong', 'b'):
            self._push_inline('</b>')
        elif tag in ('em', 'i'):
            self._push_inline('</i>')
        elif tag == 'code':
            if self._stack and self._stack[-1] == 'pre':
                return
            self._push_inline('</font>')
        elif tag == 'a':
            self._push_inline('</link>')
        elif tag in ('p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote'):
            self._flush_para(style=tag if tag != 'p' else 'body')
            if self._stack and self._stack[-1] == tag:
                self._stack.pop()
        elif tag == 'pre':
            # Preserve whitespace by replacing newlines with <br/> inside the
            # courier-wrapped block.
            text = ''.join(self._inline)
            self._inline = []
            if text:
                # Convert tabs and runs of spaces to nbsp so indentation holds.
                text = text.replace('\t', '    ')
                lines = text.split('\n')
                wrapped = '<br/>'.join(
                    re.sub(r' {2,}', lambda m: '&nbsp;' * len(m.group()), ln)
                    for ln in lines
                )
                self.blocks.append((
                    'para',
                    f'<font face="Courier" size="9">{wrapped}</font>',
                    'pre',
                ))
            if self._stack and self._stack[-1] == 'pre':
                self._stack.pop()
        elif tag == 'li':
            self._flush_para(style='li')
            if self._stack and self._stack[-1] == 'li':
                self._stack.pop()
        elif tag in ('ul', 'ol'):
            if self._list_kinds:
                self._list_kinds.pop()
                self._list_counters.pop()
        elif tag == 'table':
            if self._cur_table is not None:
                self.blocks.append(('table', self._cur_table, self._table_has_header))
            self._cur_table = None
            self._cur_row = None
            self._table_has_header = False
            if self._stack and self._stack[-1] == 'table':
                self._stack.pop()
        elif tag == 'tr':
            if self._cur_row is not None and self._cur_table is not None:
                self._cur_table.append(self._cur_row)
            self._cur_row = None
        elif tag in ('td', 'th'):
            text = ''.join(self._inline).strip()
            self._inline = []
            if self._cur_row is not None:
                self._cur_row.append(text)
            if self._stack and self._stack[-1] == tag:
                self._stack.pop()

    def handle_data(self, data):
        if not data:
            return
        # Escape XML so the inline buffer stays well-formed for ReportLab's
        # paragraph parser. Whitespace inside <pre> is preserved separately by
        # the </pre> handler.
        self._push_inline(xml_escape(data))


def markdown_to_platypus(raw: str, styles, brand_primary=None):
    """Convert raw Markdown to a list of ReportLab flowables.

    Falls back to a single Paragraph with newlines→<br/> when the input has
    no markdown structure, so plain-text findings keep their old look.
    """
    # Lazy import — keeps this module importable from contexts that don't have
    # ReportLab on the path (tests, type checkers).
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import HRFlowable, Paragraph, Spacer, Table, TableStyle

    if not raw:
        return []

    rendered = render_markdown(raw)
    if not rendered:
        return []

    parser = _PlatypusBuilder()
    parser.feed(rendered)
    parser.close()
    # Flush any trailing inline buffer (e.g. bare text without surrounding <p>).
    parser._flush_para()

    body_style = styles['BodyText2']
    heading_styles = {
        'h1': ParagraphStyle(
            'MdH1', parent=body_style, fontSize=14, leading=18,
            spaceBefore=8, spaceAfter=4, fontName='Helvetica-Bold',
        ),
        'h2': ParagraphStyle(
            'MdH2', parent=body_style, fontSize=12.5, leading=16,
            spaceBefore=6, spaceAfter=3, fontName='Helvetica-Bold',
        ),
        'h3': ParagraphStyle(
            'MdH3', parent=body_style, fontSize=11, leading=15,
            spaceBefore=5, spaceAfter=2, fontName='Helvetica-Bold',
        ),
    }
    for k in ('h4', 'h5', 'h6'):
        heading_styles[k] = heading_styles['h3']

    pre_style = ParagraphStyle(
        'MdPre', parent=body_style, fontSize=9, leading=12,
        leftIndent=10, backColor=colors.HexColor('#f5f5f5'),
        borderPadding=4, spaceAfter=6,
    )
    quote_style = ParagraphStyle(
        'MdQuote', parent=body_style, fontSize=10, leading=14,
        leftIndent=14, textColor=colors.HexColor('#555555'),
        spaceAfter=6,
    )
    list_style = ParagraphStyle(
        'MdLi', parent=body_style, leftIndent=14, spaceAfter=2,
    )

    flowables: list = []
    accent = brand_primary or colors.HexColor('#cccccc')

    for block in parser.blocks:
        kind = block[0]
        if kind == 'para':
            _, html_inline, style_hint = block
            if style_hint in heading_styles:
                flowables.append(Paragraph(html_inline, heading_styles[style_hint]))
            elif style_hint == 'pre':
                flowables.append(Paragraph(html_inline, pre_style))
            elif style_hint == 'blockquote':
                flowables.append(Paragraph(html_inline, quote_style))
            elif style_hint == 'li':
                flowables.append(Paragraph(html_inline, list_style))
            else:
                flowables.append(Paragraph(html_inline, body_style))
        elif kind == 'hr':
            flowables.append(Spacer(1, 4))
            flowables.append(HRFlowable(width='100%', color=accent, thickness=0.5))
            flowables.append(Spacer(1, 4))
        elif kind == 'table':
            _, rows, has_header = block
            if not rows:
                continue
            # Wrap each cell in a Paragraph so it wraps inside narrow columns.
            data = [
                [Paragraph(cell or '', body_style) for cell in row]
                for row in rows
            ]
            tbl = Table(data, hAlign='LEFT')
            tstyle = [
                ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#cccccc')),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]
            if has_header:
                tstyle.append(('BACKGROUND', (0, 0), (-1, 0), accent))
                tstyle.append(('TEXTCOLOR', (0, 0), (-1, 0), colors.white))
                tstyle.append(('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'))
            tbl.setStyle(TableStyle(tstyle))
            flowables.append(tbl)
            flowables.append(Spacer(1, 6))

    return flowables
