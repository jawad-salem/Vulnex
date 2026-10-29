"""Spreadsheet-facing exports treat user-controlled formula prefixes as text."""
import unicodedata


def csv_cell(value):
    if not isinstance(value, str):
        return value
    normalized = unicodedata.normalize('NFKC', value).lstrip()
    if normalized.startswith(('=', '+', '-', '@')) or value.startswith(('\t', '\r', '\n')):
        return "'" + value
    return value
