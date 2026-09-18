"""Safely mark approved SentinelOne Cloud Detection alerts as false positive."""

from __future__ import annotations

import csv
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests


BASE_URL = os.getenv("S1_BASE_URL", "https://YOUR-TENANT.sentinelone.net").rstrip("/")
API_TOKEN = os.getenv("S1_API_TOKEN", "").strip()
ALLOWED_RULE_IDS = {
    value.strip()
    for value in os.getenv("S1_ALLOWED_RULE_IDS", "").split(",")
    if value.strip()
}
DRY_RUN = os.getenv("S1_DRY_RUN", "true").lower() in {"1", "true", "yes", "on"}
RUN_ONCE = os.getenv("S1_RUN_ONCE", "false").lower() in {"1", "true", "yes", "on"}
POLL_SECONDS = max(15, int(os.getenv("S1_POLL_SECONDS", "60")))
LOOKBACK_MINUTES = max(1, int(os.getenv("S1_LOOKBACK_MINUTES", "15")))
MAX_UPDATES_PER_CYCLE = max(1, int(os.getenv("S1_MAX_UPDATES_PER_CYCLE", "20")))
REQUEST_TIMEOUT = max(5, int(os.getenv("S1_REQUEST_TIMEOUT", "30")))
PAGE_LIMIT = min(1000, max(1, int(os.getenv("S1_PAGE_LIMIT", "200"))))

ALERTS_PATH = "/web/api/v2.1/cloud-detection/alerts"
VERDICT_PATH = "/web/api/v2.1/cloud-detection/alerts/analyst-verdict"
AUDIT_PATH = Path(os.getenv("S1_AUDIT_FILE", "audit_log.csv"))


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def write_audit(alert: dict[str, Any], action: str, detail: str) -> None:
    info = alert.get("alertInfo") or {}
    rule = alert.get("ruleInfo") or {}
    agent = alert.get("agentDetectionInfo") or {}
    new_file = not AUDIT_PATH.exists()
    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with AUDIT_PATH.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        if new_file:
            writer.writerow([
                "timestamp_utc", "alert_id", "rule_id", "rule_name", "endpoint",
                "previous_verdict", "action", "detail"
            ])
        writer.writerow([
            utc_now().isoformat(), info.get("alertId", ""), rule.get("id", ""),
            rule.get("name", ""), agent.get("name", ""),
            info.get("analystVerdict", ""), action, detail
        ])


class SentinelOneClient:
    def __init__(self) -> None:
        if not API_TOKEN:
            raise RuntimeError("S1_API_TOKEN is missing. Add it to your local .env/session.")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"ApiToken {API_TOKEN}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        })

    def request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        url = f"{BASE_URL}{path}"
        last_error: Exception | None = None
        for attempt in range(4):
            try:
                response = self.session.request(method, url, timeout=REQUEST_TIMEOUT, **kwargs)
            except requests.RequestException as exc:
                last_error = exc
                if attempt == 3:
                    raise
                time.sleep(2 ** attempt)
                continue

            if response.status_code == 401:
                raise RuntimeError("SentinelOne returned 401. Check the token and permissions.")
            if response.status_code == 429 or response.status_code >= 500:
                if attempt == 3:
                    response.raise_for_status()
                retry_after = response.headers.get("Retry-After")
                time.sleep(float(retry_after) if retry_after else 2 ** attempt)
                continue
            response.raise_for_status()
            return response
        raise RuntimeError(f"Request failed: {last_error}")

    def iter_alerts(self):
        cursor: str | None = None
        while True:
            params: dict[str, Any] = {"limit": PAGE_LIMIT}
            if cursor:
                params["cursor"] = cursor
            payload = self.request("GET", ALERTS_PATH, params=params).json()
            for alert in payload.get("data") or []:
                yield alert
            cursor = (payload.get("pagination") or {}).get("nextCursor")
            if not cursor:
                break

    def set_false_positive(self, alert_id: str) -> None:
        # This follows SentinelOne's standard action-body format. If the local
        # API explorer shows a different request example, adjust only this body.
        body = {
            "filter": {"ids": [alert_id]},
            "data": {"analystVerdict": "FALSE_POSITIVE"},
        }
        self.request("POST", VERDICT_PATH, json=body)

    def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        payload = self.request("GET", ALERTS_PATH, params={"ids": alert_id, "limit": 1}).json()
        data = payload.get("data") or []
        return data[0] if data else None


def eligible(alert: dict[str, Any], cutoff: datetime) -> tuple[bool, str]:
    info = alert.get("alertInfo") or {}
    rule = alert.get("ruleInfo") or {}
    alert_id = str(info.get("alertId") or "")
    rule_id = str(rule.get("id") or "")
    verdict = str(info.get("analystVerdict") or "").upper()
    created = parse_timestamp(info.get("createdAt") or info.get("reportedAt"))

    if not alert_id:
        return False, "missing alert ID"
    if rule_id not in ALLOWED_RULE_IDS:
        return False, "rule not allowlisted"
    if verdict == "FALSE_POSITIVE":
        return False, "already false positive"
    if not created:
        return False, "missing/invalid creation timestamp"
    if created < cutoff:
        return False, "outside lookback window"
    return True, "eligible"


def run_cycle(client: SentinelOneClient) -> None:
    cutoff = utc_now() - timedelta(minutes=LOOKBACK_MINUTES)
    changed = 0
    matched = 0

    for alert in client.iter_alerts():
        ok, reason = eligible(alert, cutoff)
        if not ok:
            continue
        matched += 1
        info = alert.get("alertInfo") or {}
        rule = alert.get("ruleInfo") or {}
        alert_id = str(info["alertId"])

        if DRY_RUN:
            logging.info("DRY RUN alert=%s rule=%s (%s)", alert_id, rule.get("name"), rule.get("id"))
            write_audit(alert, "DRY_RUN", "Would set FALSE_POSITIVE")
            continue

        if changed >= MAX_UPDATES_PER_CYCLE:
            logging.warning("Update cap reached; remaining eligible alerts will wait.")
            break

        try:
            client.set_false_positive(alert_id)
            verified = client.get_alert(alert_id)
            verdict = str(((verified or {}).get("alertInfo") or {}).get("analystVerdict") or "").upper()
            if verdict != "FALSE_POSITIVE":
                raise RuntimeError(f"verification returned verdict={verdict or 'missing'}")
            changed += 1
            logging.info("UPDATED alert=%s rule=%s", alert_id, rule.get("name"))
            write_audit(alert, "UPDATED", "Verified FALSE_POSITIVE")
        except Exception as exc:
            logging.exception("Failed to update alert=%s", alert_id)
            write_audit(alert, "ERROR", str(exc)[:500])

    logging.info("Cycle complete: eligible=%d updated=%d dry_run=%s", matched, changed, DRY_RUN)


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        client = SentinelOneClient()
        while True:
            run_cycle(client)
            if RUN_ONCE:
                return 0
            time.sleep(POLL_SECONDS)
    except KeyboardInterrupt:
        logging.info("Stopped by user")
        return 0
    except Exception as exc:
        logging.exception("Automation stopped: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
