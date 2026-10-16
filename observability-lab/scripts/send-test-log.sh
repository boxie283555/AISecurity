#!/usr/bin/env bash
set -euo pipefail

OTLP_HTTP_ENDPOINT="${OTLP_HTTP_ENDPOINT:-http://127.0.0.1:4318}"
NOW_NANO="$(date +%s)000000000"

curl -sS -X POST "${OTLP_HTTP_ENDPOINT}/v1/logs" \
  -H "Content-Type: application/json" \
  -d @- <<JSON
{
  "resourceLogs": [
    {
      "resource": {
        "attributes": [
          {"key": "service.name", "value": {"stringValue": "ai-audit-demo"}},
          {"key": "deployment.environment", "value": {"stringValue": "ai-security-lab"}}
        ]
      },
      "scopeLogs": [
        {
          "scope": {"name": "manual-test"},
          "logRecords": [
            {
              "timeUnixNano": "${NOW_NANO}",
              "severityText": "INFO",
              "body": {
                "stringValue": "AI audit demo event: user=lab-user app=ccswitch model=gpt-5.5 status=success input_tokens=128 output_tokens=64 cost_usd=0.0012"
              },
              "attributes": [
                {"key": "event.type", "value": {"stringValue": "ai.request"}},
                {"key": "ai.user", "value": {"stringValue": "lab-user"}},
                {"key": "ai.app", "value": {"stringValue": "ccswitch"}},
                {"key": "ai.model", "value": {"stringValue": "gpt-5.5"}},
                {"key": "ai.status", "value": {"stringValue": "success"}}
              ]
            }
          ]
        }
      ]
    }
  ]
}
JSON

echo
echo "Sent one OTLP log record to ${OTLP_HTTP_ENDPOINT}/v1/logs"
