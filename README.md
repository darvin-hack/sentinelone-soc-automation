# SentinelOne Limited-Rule False-Positive Automation

This project polls SentinelOne Cloud Detection alerts and sets the analyst
verdict to `FALSE_POSITIVE` only when the alert's exact `ruleInfo.id` is on the
allowlist. It does not resolve incidents, close alerts, assign analysts, or
change any other rule.

No rule is approved by default. Add only explicitly approved rule IDs through
the `S1_ALLOWED_RULE_IDS` environment variable.

## Safety defaults

- Dry-run is enabled.
- Only alerts created during the last 15 minutes are eligible.
- Already-false-positive alerts are skipped.
- A maximum of 20 alerts can be changed per cycle.
- Every eligible attempt is recorded in `audit_log.csv`.
- The result is retrieved and verified after each live update.

## VS Code setup (Windows PowerShell)

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Set environment variables for the current PowerShell session. Do not save the
real token in GitHub or inside the Python file.

```powershell
$env:S1_BASE_URL="https://YOUR-TENANT.sentinelone.net"
$env:S1_API_TOKEN="PASTE_THE_TOKEN_HERE"
$env:S1_ALLOWED_RULE_IDS="PASTE_APPROVED_RULE_ID"
$env:S1_DRY_RUN="true"
$env:S1_RUN_ONCE="true"
python main.py
```

Review `audit_log.csv`. When every selected alert belongs to the expected rule,
enable live mode:

```powershell
$env:S1_DRY_RUN="false"
$env:S1_RUN_ONCE="false"
python main.py
```

Stop the continuous process with `Ctrl+C`.

## Required permissions

- Permission to retrieve Cloud Detection alerts.
- `Custom Alerts.updateAnalystVerdict` to update the verdict.

Use a dedicated least-privilege API/service account.

## API operations

```text
GET  /web/api/v2.1/cloud-detection/alerts
POST /web/api/v2.1/cloud-detection/alerts/analyst-verdict
```

The update body in `set_false_positive()` uses SentinelOne's standard action
format:

```json
{
  "filter": {"ids": ["ALERT_ID"]},
  "data": {"analystVerdict": "FALSE_POSITIVE"}
}
```

Before live use, compare this with the **Request Body Example** in the API
explorer for your exact console version. If it differs, update only the `body`
inside `set_false_positive()`.

## Important behavior

The script fetches pages without using `analystVerdict=FALSE_POSITIVE`. That
filter would return alerts that are already false positive, which is the
opposite of the intended selection. Instead, the script checks the verdict
locally and skips completed alerts.

The 15-minute lookback prevents the first live run from modifying old alerts.
Increase `S1_LOOKBACK_MINUTES` only after approval.
