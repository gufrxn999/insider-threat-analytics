# Insider Threat Analytics

A local-first prototype for finding unusual user activity in organizational audit events. It converts event logs into per-user daily behavior, compares each day with that user's preceding activity, and explains elevated scores with readable signals.

The app generates synthetic demo data on first launch. It does not train a deep-learning model, connect to company systems, or make decisions about employees.

## What it does

- Validates a documented CSV event schema and drops invalid rows.
- Aggregates events by user and day.
- Builds a personal baseline from up to 28 prior active days, requiring at least 7.
- Flags unusual after-hours activity, external email, removable-media use, privilege changes, data movement, device counts, and access to sensitive-looking resources.
- Shows a review queue, risk trend, and reasons in a Streamlit dashboard.
- Includes deterministic synthetic events with a deliberately unusual demo day.

The scores and thresholds are illustrative triage rules, not a validated risk model. A high score means a reviewer should examine the underlying events; it does not establish malicious intent. Days without enough history are marked **Insufficient history**, not Low risk.

## Run locally

Python 3.11 or newer is recommended.

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt
streamlit run app.py
```

The dashboard creates synthetic demo events locally on first launch. Upload a CSV from the sidebar to analyze another dataset locally. Uploaded files are read in memory and are not written to disk. The maximum upload size is 25 MB.

Regenerate the demo data with:

```bash
PYTHONPATH=src python -m insider_threat.demo_data
```

## Event CSV schema

All columns below are required. Timestamps should include a timezone when possible; they are normalized to UTC. `event_type` values are free-form, with these values used by the current rules: 

## Automated checks

Run the focused analytics regression checks with:

PYTHONPATH=src python -m unittest discover -s tests
`external_email`, `usb_copy`, and `privilege_change`.

| Column | Meaning | Example |
|---|---|---|
| `timestamp` | Event time | `2025-01-01T22:14:00Z` |
| `user_id` | Pseudonymous user identifier | `employee-01` |
| `event_type` | Normalized activity type | `file_access` |
| `resource` | Resource label or path | `restricted/payroll` |
| `bytes_transferred` | Nonnegative byte count | `1024` |
| `device_id` | Pseudonymous device identifier | `device-01` |
| `department` | Broad team label | `Finance` |

Sensitive-resource detection currently uses resource names containing `confidential`, `restricted`, `payroll`, `customer-data`, or `source-code`. Update this list to match an organization's approved data classification labels; avoid sending document contents to this tool.

## How the score works

For each user-day, the app looks at the user's preceding 28 calendar days. It requires at least 7 prior active days. Positive signals are compared with a robust median and median absolute deviation threshold; removable-media use and privilege changes also have explicit rules. Signal weights are added and capped at 100:

- High: 60–100
- Moderate: 30–59
- Low: 0–29

These are starting defaults for a demo. They need calibration against representative, consented, appropriately governed data and review by security and privacy stakeholders before any operational use.

## Privacy and safe use

- The included events are synthetic. Do not commit real employee logs, credentials, customer information, or personally identifying data.
- Use pseudonymous identifiers, access controls, short retention periods, and documented notice and approval appropriate to your organization.
- Keep a human reviewer in the loop. Do not use a score as the sole basis for disciplinary, employment, or access decisions.
- This app is not production-ready: it has no authentication, audit trail, tenant isolation, model monitoring, or alert-response workflow.

## Project layout

```text
app.py
src/insider_threat/analytics.py   # validation, aggregation, explainable scoring
src/insider_threat/demo_data.py   # synthetic event generator
data/demo_events.csv              # generated locally and ignored by Git
requirements.txt
```
