#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


def loki_query_range(base_url: str, query: str, limit: int = 1000) -> list[tuple[int, dict[str, Any]]]:
    params = urllib.parse.urlencode({"query": query, "limit": str(limit), "direction": "BACKWARD"})
    url = f"{base_url.rstrip('/')}/loki/api/v1/query_range?{params}"
    with urllib.request.urlopen(url, timeout=30) as response:
        payload = json.loads(response.read().decode("utf-8"))
    records: list[tuple[int, dict[str, Any]]] = []
    for stream in payload.get("data", {}).get("result", []):
        for timestamp, line in stream.get("values", []):
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            records.append((int(timestamp), record))
    return sorted(records, key=lambda item: item[0])


def latest_run_id(loki_url: str) -> str:
    records = loki_query_range(
        loki_url,
        '{service_name="ai-model-eval-runner"} | json | event="ai_model_eval_summary"',
        limit=10,
    )
    if not records:
        raise SystemExit("no ai_model_eval_summary records found in Loki")
    return records[-1][1]["run_id"]


def md(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ")


def table(headers: list[str], rows: list[list[Any]]) -> str:
    if not rows:
        return "_No records found._\n"
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(md(item) for item in row) + " |")
    return "\n".join(lines) + "\n"


def latest_by_key(records: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for record in records:
        value = record.get(key) or record.get("asset_name") or record.get("name")
        latest[str(value)] = record
    return list(latest.values())


def otlp_value(value: Any) -> dict[str, Any]:
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": value}
    if isinstance(value, float):
        return {"doubleValue": value}
    return {"stringValue": str(value)}


def send_report_event(endpoint: str, record: dict[str, Any]) -> None:
    payload = {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "ai-compliance-report"}},
                        {"key": "deployment.environment", "value": {"stringValue": "ai-security-lab"}},
                    ]
                },
                "scopeLogs": [
                    {
                        "scope": {"name": "generate-ai-security-report"},
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
    parser = argparse.ArgumentParser(description="Generate an AI security governance report from Loki evidence.")
    parser.add_argument("--loki-url", default="http://127.0.0.1:3100")
    parser.add_argument("--otlp-endpoint", default="http://127.0.0.1:4318")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--output-dir", default="reports")
    parser.add_argument("--emit-event", action="store_true")
    args = parser.parse_args()

    run_id = args.run_id or latest_run_id(args.loki_url)
    evals = [record for _, record in loki_query_range(args.loki_url, f'{{service_name="ai-model-eval-runner"}} | json | event="ai_model_eval" | run_id="{run_id}"')]
    findings = [record for _, record in loki_query_range(args.loki_url, f'{{service_name="ai-model-eval-runner"}} | json | event="ai_risk_finding" | run_id="{run_id}"')]
    workflows = [
        record
        for _, record in loki_query_range(
            args.loki_url,
            '{service_name=~"ai-model-eval-runner|ai-risk-workflow"} | json | event="ai_finding_workflow"',
        )
        if record.get("run_id") == run_id or any(record.get("finding_id") == finding.get("finding_id") for finding in findings)
    ]
    summaries = [record for _, record in loki_query_range(args.loki_url, f'{{service_name="ai-model-eval-runner"}} | json | event="ai_model_eval_summary" | run_id="{run_id}"', limit=10)]
    assets = latest_by_key(
        [record for _, record in loki_query_range(args.loki_url, '{service_name="ai-governance-registry"} | json | event="ai_asset_inventory"', limit=500)],
        "asset_id",
    )
    summary = summaries[-1] if summaries else {}

    generated_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"ai-security-report-{run_id}.md"

    content = [
        f"# AI Security Governance Report\n",
        f"- Generated at: `{generated_at}`",
        f"- Run ID: `{run_id}`",
        f"- App: `{summary.get('app_id', '')}`",
        f"- Model: `{summary.get('model', '')}`",
        f"- Cases: `{summary.get('case_count', len(evals))}`",
        f"- Passed: `{summary.get('pass_count', sum(1 for item in evals if item.get('result') == 'pass'))}`",
        f"- Failed: `{summary.get('fail_count', len(findings))}`",
        f"- Infra errors: `{summary.get('infra_error_count', sum(1 for item in evals if item.get('result') == 'infra_error'))}`",
        "\n## AI Assets\n",
        table(
            ["#", "Asset", "Type", "Owner", "Risk", "Status", "Purpose"],
            [[idx, item.get("asset_name") or item.get("name"), item.get("asset_type"), item.get("owner"), item.get("risk_level"), item.get("status"), item.get("purpose")] for idx, item in enumerate(assets, 1)],
        ),
        "\n## Red Team Cases And Blue Team Detection\n",
        table(
            ["#", "Case", "Category", "Control", "Red Team", "Blue Detector", "Result", "Reason", "Trace"],
            [
                [
                    idx,
                    item.get("case_id"),
                    item.get("category"),
                    item.get("control_id"),
                    item.get("red_team_tactic"),
                    item.get("blue_team_detector"),
                    item.get("result"),
                    item.get("reason"),
                    item.get("trace_id"),
                ]
                for idx, item in enumerate(evals, 1)
            ],
        ),
        "\n## Open Risk Findings\n",
        table(
            ["#", "Finding ID", "Case", "Risk", "Owner", "Due", "Status", "Recommended Fix", "Evidence"],
            [
                [
                    idx,
                    item.get("finding_id"),
                    item.get("case_id"),
                    item.get("risk_level"),
                    item.get("owner"),
                    item.get("due_date"),
                    item.get("status"),
                    item.get("recommended_fix"),
                    item.get("request_id"),
                ]
                for idx, item in enumerate(findings, 1)
            ],
        ),
        "\n## Remediation Workflow Events\n",
        table(
            ["#", "Finding ID", "Status", "Owner", "Action", "Note", "Time"],
            [[idx, item.get("finding_id"), item.get("status"), item.get("owner"), item.get("action"), item.get("note"), item.get("timestamp")] for idx, item in enumerate(workflows, 1)],
        ),
        "\n## Remaining Production Gaps\n",
        "- This lab records governance evidence in Loki, but does not yet provide WORM storage, cryptographic signatures, formal approval workflow, or enterprise IAM integration.\n",
        "- Prompt and response capture must be paired with DLP, masking, RBAC, retention, and legal review before production use.\n",
    ]
    output_path.write_text("\n".join(content), encoding="utf-8")

    if args.emit_event:
        send_report_event(
            args.otlp_endpoint,
            {
                "message": "ai_compliance_report",
                "event": "ai_compliance_report",
                "run_id": run_id,
                "report_path": str(output_path),
                "case_count": len(evals),
                "finding_count": len(findings),
                "generated_at": generated_at,
                "status": "generated",
            },
        )
    print(f"report_path={output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
