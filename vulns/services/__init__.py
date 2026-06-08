"""Domain services for the vulns app.

Business logic that used to live inside ``vulns/views.py`` — finding merges and
scanner/CSV imports. Views orchestrate HTTP; these modules do the work, so they
can be unit-tested and reused (e.g. from the REST API) without a request.
"""
