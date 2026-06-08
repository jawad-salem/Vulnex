"""Finding-import service.

Scanner-tool and CSV import logic extracted from ``vulns.views``: the parser
registry, dedup classification, bulk commit, and CSV parsing/validation. The
view layer handles the two-step preview/confirm flow and session plumbing; the
actual parsing and writing lives here.
"""
import csv

from ..models import Finding
from ..parsers import (
    parse_burp_xml,
    parse_nessus_xml,
    parse_nikto_json,
    parse_nuclei_json,
    parse_semgrep_json,
    parse_zap_json,
)

# Tool name → parser callable. The upload form's ``tool`` choices must stay in
# sync with these keys.
PARSERS = {
    'nuclei': parse_nuclei_json,
    'nikto': parse_nikto_json,
    'burp': parse_burp_xml,
    'nessus': parse_nessus_xml,
    'zap': parse_zap_json,
    'semgrep': parse_semgrep_json,
}

# Upper bound on entries the interactive preview will hold in the session.
IMPORT_PREVIEW_LIMIT = 1000

# Columns the CSV importer accepts. Subset of the export columns — derived/audit
# columns (cvss_vector_string, created_at, due_date, sla_status) are dropped
# even if present so we don't tempt operators into setting them by hand.
CSV_IMPORT_COLUMNS = {
    'title', 'severity', 'cvss_score', 'status', 'host', 'port', 'url',
    'endpoint', 'http_method', 'parameter', 'description',
    'proof_of_concept', 'remediation', 'cwe_id', 'tool_source',
    'affected_hosts', 'references',
}
CSV_IMPORT_REQUIRED = {'title', 'severity'}
CSV_IMPORT_DROPPED = {'cvss_vector_string', 'created_at', 'due_date', 'sla_status'}


def classify_import(engagement, findings_data):
    """Split parser output into (new_items, duplicate_items) using the
    (title, host, port, endpoint, parameter) dedup key against existing
    findings. Returns lists of plain dicts so they're JSON-serialisable
    for session storage.
    """
    existing_keys = set(
        engagement.findings.values_list(
            'title', 'host', 'port', 'endpoint', 'parameter',
        )
    )
    new_items, dup_items = [], []
    seen_in_batch = set()
    for fd in findings_data:
        dedup_key = (
            fd.get('title', ''),
            fd.get('host', ''),
            fd.get('port'),
            fd.get('endpoint', ''),
            fd.get('parameter', ''),
        )
        # JSON-friendly version (tuples can't survive session round-trip)
        if dedup_key in existing_keys or dedup_key in seen_in_batch:
            dup_items.append(fd)
        else:
            seen_in_batch.add(dedup_key)
            new_items.append(fd)
    return new_items, dup_items


def commit_import(engagement, user, tool, new_items):
    """Bulk-create findings from a pre-classified ``new_items`` payload."""
    model_fields = {f.name for f in Finding._meta.get_fields()}
    created = 0
    for fd in new_items:
        clean = {k: v for k, v in fd.items() if k in model_fields}
        Finding.objects.create(
            engagement=engagement,
            found_by=user,
            tool_source=tool.capitalize(),
            **clean,
        )
        created += 1
    return created


def parse_csv_findings(content):
    """Parse a CSV upload into ``(rows, row_errors, header_errors)``.

    ``rows`` are dicts ready for ``classify_import`` / ``commit_import``.
    ``row_errors`` is a list of ``{'row': N, 'error': str}`` for rows that
    failed validation (skipped from the import). ``header_errors`` is a list
    of fatal header-level errors that abort the import entirely.
    """
    valid_severities = {s for s, _ in Finding.Severity.choices}
    valid_statuses = {s for s, _ in Finding.Status.choices}
    header_errors = []

    try:
        text = content.decode('utf-8-sig')  # tolerate BOM from Excel exports
    except UnicodeDecodeError:
        return [], [], ['CSV must be UTF-8 encoded.']

    reader = csv.DictReader(text.splitlines())
    if reader.fieldnames is None:
        return [], [], ['CSV is empty or has no header row.']

    headers = {h.strip() for h in reader.fieldnames if h}
    missing_required = CSV_IMPORT_REQUIRED - headers
    if missing_required:
        header_errors.append(
            f'Missing required column(s): {", ".join(sorted(missing_required))}.'
        )
    unknown = headers - CSV_IMPORT_COLUMNS - CSV_IMPORT_DROPPED
    if unknown:
        header_errors.append(
            f'Unknown column(s): {", ".join(sorted(unknown))}. '
            f'Allowed: {", ".join(sorted(CSV_IMPORT_COLUMNS))}.'
        )
    if header_errors:
        return [], [], header_errors

    rows = []
    row_errors = []
    for idx, raw in enumerate(reader, start=2):  # row 1 is the header
        row = {
            (k.strip() if k else ''): (v.strip() if isinstance(v, str) else v)
            for k, v in raw.items()
            if k and k.strip() in CSV_IMPORT_COLUMNS
        }
        title = row.get('title', '')
        severity = row.get('severity', '').lower()
        if not title:
            row_errors.append({'row': idx, 'error': 'title is required'})
            continue
        if severity not in valid_severities:
            row_errors.append({
                'row': idx,
                'error': f'severity "{row.get("severity", "")}" is invalid '
                         f'(allowed: {", ".join(sorted(valid_severities))})',
            })
            continue
        row['severity'] = severity

        status = (row.get('status') or '').lower()
        if status:
            if status not in valid_statuses:
                row_errors.append({
                    'row': idx,
                    'error': f'status "{row.get("status", "")}" is invalid '
                             f'(allowed: {", ".join(sorted(valid_statuses))})',
                })
                continue
            row['status'] = status
        else:
            row.pop('status', None)

        port_str = row.get('port', '')
        if port_str:
            try:
                row['port'] = int(port_str)
            except ValueError:
                row_errors.append({'row': idx, 'error': f'port "{port_str}" is not a number'})
                continue
        else:
            row.pop('port', None)

        cvss_str = row.get('cvss_score', '')
        if cvss_str:
            try:
                row['cvss_score'] = float(cvss_str)
            except ValueError:
                row_errors.append({'row': idx, 'error': f'cvss_score "{cvss_str}" is not a number'})
                continue
        else:
            row.pop('cvss_score', None)

        rows.append(row)

    return rows, row_errors, []
