# FRIS Cyber Dashboard

**FRIS — Firmware Risk Intelligence System — Powered by Blockchain and AI Agents**

A responsive, dark cybersecurity dashboard prototype inspired by modern SOC/incident-monitoring interfaces, adapted to the FRIS firmware-security project.

## Files
- `index.html` — dashboard structure
- `style.css` — responsive dark UI
- `script.js` — interactive frontend demo

## Run
Open `index.html` in a browser. For best results, publish it using GitHub Pages (HTTPS enables the browser SHA-256 demonstration).

## Included UI sections
- Security overview KPI cards
- Incident timeline
- Findings by severity
- Firmware file selection preview
- Example component inventory
- Three proposed AI agent roles
- Local SHA-256 demonstration for a demo label
- Sample report download
- Search, settings and mobile layout

## Important prototype limitations
This is a **frontend prototype**, not a production security scanner. All metrics, timeline events, and component records are illustrative. Selecting a file only displays its name and size; file contents are not uploaded, extracted, or scanned. No real AI agent or NVD API is connected. The hash button hashes a fixed demo label, not the selected firmware, and does not submit a blockchain transaction. A production build needs a secure backend, isolated firmware-analysis workers, validated component/CVE matching, access controls, report generation, and a blockchain or append-only audit integration.

For audit privacy, a production design should generally store hashes and carefully selected metadata, not entire firmware images or confidential reports.
