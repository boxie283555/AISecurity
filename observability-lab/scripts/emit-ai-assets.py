#!/usr/bin/env python3
import argparse
import json
import time
import urllib.error
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


def otlp_log_record(event: dict[str, Any]) -> dict[str, Any]:
    now_ns = str(time.time_ns())
    attrs = [
        {"key": key.replace("_", "."), "value": otlp_value(value)}
        for key, value in event.items()
        if isinstance(value, (str, int, float, bool))
    ]
    return {
        "timeUnixNano": now_ns,
        "severityText": "INFO",
        "body": {"stringValue": json.dumps(event, ensure_ascii=False, separators=(",", ":"))},
        "attributes": attrs,
    }


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
                        "scope": {"name": "ai-asset-registry"},
                        "logRecords": [otlp_log_record(record) for record in records],
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


def build_asset_events(registry: dict[str, Any]) -> list[dict[str, Any]]:
    asset_events: list[dict[str, Any]] = []
    type_counts: dict[str, int] = {}
    environment = registry.get("environment", "ai-security-lab")
    for asset_type in ("apps", "models", "gateways", "data_sources", "tools"):
        normalized_asset_type = asset_type.rstrip("s")
        for item in registry.get(asset_type, []):
            purpose = item.get("business_purpose") or item.get("purpose") or ""
            type_counts[normalized_asset_type] = type_counts.get(normalized_asset_type, 0) + 1
            asset_events.append(
                {
                    "message": "ai_asset_inventory",
                    "event": "ai_asset_inventory",
                    "environment": environment,
                    "asset_type": normalized_asset_type,
                    "asset_id": item.get("asset_id", "unknown"),
                    "asset_name": item.get("name", "unknown"),
                    "owner": item.get("owner", "unknown"),
                    "risk_level": item.get("risk_level", "unknown"),
                    "status": item.get("status", "unknown"),
                    "department": item.get("department", ""),
                    "purpose": purpose,
                    "classification": item.get("classification", ""),
                    "provider": item.get("provider", ""),
                    "gateway": item.get("gateway", ""),
                    "base_url": item.get("base_url", ""),
                    "upstream": item.get("upstream", ""),
                    "default_model": item.get("default_model", ""),
                    "deployment_type": item.get("deployment_type", ""),
                    "data_region": item.get("data_region", ""),
                    "storage": item.get("storage", ""),
                    "controls": ",".join(item.get("controls", [])),
                    "approved_for": ",".join(item.get("approved_for", [])),
                    "contains_personal_data": item.get("contains_personal_data", ""),
                }
            )

    events = list(asset_events)
    events.append(
        {
            "message": "ai_asset_inventory_summary",
            "event": "ai_asset_inventory_summary",
            "environment": environment,
            "asset_count": len(asset_events),
            "high_risk_count": sum(1 for event in asset_events if event.get("risk_level") == "high"),
        }
    )
    for asset_type, count in sorted(type_counts.items()):
        events.append(
            {
                "message": "ai_asset_inventory_type_summary",
                "event": "ai_asset_inventory_type_summary",
                "environment": environment,
                "asset_type": asset_type,
                "asset_type_count": count,
            }
        )
    return events


def main() -> int:
    parser = argparse.ArgumentParser(description="Emit AI asset inventory events to Loki through OTLP.")
    parser.add_argument("--assets", default="config/ai-assets.json")
    parser.add_argument("--otlp-endpoint", default="http://127.0.0.1:4318")
    parser.add_argument("--service-name", default="ai-governance-registry")
    args = parser.parse_args()

    registry = load_json(Path(args.assets))
    events = build_asset_events(registry)
    try:
        send_otlp_logs(args.otlp_endpoint, args.service_name, events)
    except urllib.error.URLError as exc:
        raise SystemExit(f"failed to send OTLP logs: {exc}") from exc

    print(f"sent {len(events)} asset inventory events to {args.otlp_endpoint}/v1/logs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
