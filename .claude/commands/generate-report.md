Generate a diagnostic report from the latest session.

Usage: /generate-report [audience] [format]

Audiences: technical, it-professional, executive
Formats: pdf, html, markdown

Example: /generate-report executive pdf

Steps:
1. Parse audience and format parameters
2. Check for existing diagnostic session
3. If no session, run quick diagnostics first
4. Generate report using SuperSleuthReportGenerator
5. Apply appropriate language translation for audience
6. Format report in requested format
7. Save report to reports/ directory
8. Display report location and preview
9. Offer to open report in browser/viewer