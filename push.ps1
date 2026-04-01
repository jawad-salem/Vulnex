git add -A
git commit -m "Add real scanners, UI polish, restructure recon/findings, fix logout and RBAC

- Replace simulated scans with real Python-based scanners (port scan, subdomain enum, tech detect, DNS enum, WHOIS, dir brute)
- Move Nmap import from Findings to Recon section (infrastructure vs vulnerabilities)
- Add dedicated Reports dashboard with sidebar navigation
- Add delete functionality for findings and scans with confirmation pages
- Fix logout 405 error (Django 5+ requires POST)
- Restrict /admin to superusers and admin role only
- Add toast notifications with auto-dismiss, mobile sidebar toggle, pagination, loading spinners
- Add hover/transition micro-interactions and empty state icons
- Fix ReportLab XML escape issue in PDF generation
- Fix scan_detail template dict lookup

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"

git push origin main
