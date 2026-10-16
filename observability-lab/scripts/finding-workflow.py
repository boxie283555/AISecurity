#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import time
import urllib.request
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def otlp_value(value: Any) -> dict[str, Any]:
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": value}
    if isinstance(value, float):
        return {"doubleValue": value}
    return {"stringValue": str(value)}


def send_otlp_logs(endpoint: str, service_name: str, records: list[dict[str, Any]]) -> None:
    payload = {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": service_name}},
                        {"key": "deployment.environment", "value": {"stringValue": "ai-security-lab"}},
                    ]
                },
                "scopeLogs": [
                    {
                        "scope": {"name": "finding-workflow"},
                        "logRecords": [
                            {
                                "timeUnixNano": str(time.time_ns()),
                                "severityText": "INFO",
                                "body": {"stringValue": json.dumps(record, ensure_ascii=False, separators=(",", ":"))},
                                "attributes": [
                                    {"key": key.replace("_", "."), "value": otlp_value(value)}
                                    for key, value in record.items()
                                    if isinstance(value, (str, int, float, bool))
                                ],
                            }
                            for record in records
                        ],
                    }
                ],
            }
        ]
    }
    request = urllib.request.Request(
        f"{endpoint.rstrip('/')}/v1/logs",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        response.read()


def main() -> int:
    parser = argparse.ArgumentParser(description="Emit AI finding workflow events to OpenTelemetry/Loki.")
    parser.add_argument("--workflow", default="config/finding-workflow.json")
    parser.add_argument("--otlp-endpoint", default="http://127.0.0.1:4318")
    parser.add_argument("--finding-id", required=True)
    parser.add_argument("--status", required=True)
    parser.add_argument("--owner", default="")
    parser.add_argument("--note", default="")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--case-id", default="")
    parser.add_argument("--category", default="")
    parser.add_argument("--severity", default="")
    parser.add_argument("--app", default="app-codex")
    parser.add_argument("--model", default="")
    args = parser.parse_args()

    workflow = load_json(Path(args.workflow))
    valid_statuses = {item["status"] for item in workflow.get("statuses", [])}
    if args.status not in valid_statuses:
        raise SystemExit(f"invalid status {args.status!r}; valid statuses: {', '.join(sorted(valid_statuses))}")

    owner = args.owner or workflow.get("default_owners", {}).get(args.category, "ai-platform")
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    record = {
        "message": "ai_finding_workflow",
        "event": "ai_finding_workflow",
        "finding_id": args.finding_id,
        "status": args.status,
        "workflow_stage": args.status,
        "owner": owner,
        "note": args.note,
        "run_id": args.run_id,
        "case_id": args.case_id,
        "category": args.category,
        "severity": args.severity,
        "app_id": args.app,
        "model": args.model,
        "action": "manual_workflow_update",
        "timestamp": now,
    }
    send_otlp_logs(args.otlp_endpoint, "ai-risk-workflow", [record])
    print(f"finding_id={args.finding_id} status={args.status} owner={owner} sent to {args.otlp_endpoint}/v1/logs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
