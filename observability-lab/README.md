# OpenTelemetry + Prometheus + Loki + Tempo + Grafana Lab

This is a small Docker Compose stack for AI security observability experiments.

## Components

- OpenTelemetry Collector: receives OTLP on `4317` and `4318`
- AI Audit Proxy: OpenAI-compatible proxy on `18080`
- Prometheus: stores metrics on `9090`
- Loki: stores logs on `3100`
- Tempo: stores traces on `3200`
- Grafana: dashboards on `3000`

## Start

```bash
cd observability-lab
docker compose up -d
```

Open Grafana:

```text
http://192.168.20.170:3000
user: admin
password: admin
```

For an experiment, change the Grafana password after first login if the VM is reachable by other users.

## Send Test Log

```bash
chmod +x scripts/send-test-log.sh
./scripts/send-test-log.sh
```

Then open Grafana:

- Explore -> Loki -> query `{service_name="ai-audit-demo"}`
- Dashboard -> AI Security Lab

## Integrating SubToAPI / Unity-AI

There are two integration modes.

### Mode A: telemetry from the gateway

Point AI gateway telemetry directly to:

```text
OTLP gRPC: http://192.168.20.170:4317
OTLP HTTP: http://192.168.20.170:4318
```

### Mode C: put AI Audit Proxy in front of SubToAPI

Traffic path:

```text
CCSwitch -> AI Audit Proxy -> SubToAPI / Unity-AI -> model backend
```

Default addresses in this lab:

```text
AI Audit Proxy: http://192.168.20.170:18080
SubToAPI upstream: http://192.168.20.241:8080
```

In CCSwitch, set the OpenAI-compatible base URL to:

```text
http://192.168.20.170:18080
```

Do not append `/v1` in CCSwitch for this lab. CCSwitch appends request paths
such as `/v1/responses` itself.

The proxy forwards requests to `SUBTOAPI_BASE_URL`, while producing:

- Prometheus metrics at `http://192.168.20.170:18080/metrics`
- OpenTelemetry traces to Tempo through the collector
- OpenTelemetry logs to Loki through the collector
- Redacted audit metadata with `request_id` and `trace_id`

Useful environment variables:

```text
SUBTOAPI_BASE_URL=http://192.168.20.241:8080
AUDIT_HASH_SALT=change-me-in-real-use
AUDIT_CAPTURE_BODY=false
AUDIT_MAX_CAPTURE_CHARS=800
MODEL_PRICE_PER_1M_JSON={"my-model":{"input":1.0,"output":3.0}}
```

Keep `AUDIT_CAPTURE_BODY=false` unless you are deliberately testing prompt/response capture. Even when enabled, the proxy redacts common sensitive fields and patterns before logging.

Recommended event fields:

```text
request_id
trace_id
user_id or user_id_hash
api_key_id
app
model
provider
endpoint
status
latency_ms
input_tokens
output_tokens
cost_usd
dlp_action
risk_level
prompt_audit_result
```

Do not send raw API keys, authorization headers, cookies, or secrets into telemetry.

## Small-Scale DLP Engine

The Audit Proxy includes a lightweight DLP engine for lab experiments. Policies
live in `config/dlp-policies.json` and are loaded when the proxy starts.

Current actions:

- `audit_only`: record a DLP event but continue the request.
- `mask`: replace matched content with a configured replacement.
- `block`: return HTTP `451` and record the DLP event.

Current stages:

- `input`: user prompt/request body before forwarding to the upstream gateway.
- `output`: model response before returning to the client.

Useful environment variables:

```text
DLP_ENABLED=true
DLP_BLOCK_INPUT=false
DLP_BLOCK_OUTPUT=true
DLP_MASK_INPUT=true
DLP_MASK_OUTPUT=true
DLP_CAPTURE_SNIPPETS=true
DLP_SNIPPET_CHARS=800
```

DLP emits:

```text
ai_dlp_event logs in Loki
ai_dlp_events_total metrics in Prometheus
```

The `AI Audit Gateway` dashboard includes DLP event totals, blocked/masked
counts, rule/category rates and DLP event details.

## Useful URLs

```text
Grafana:    http://192.168.20.170:3000
Prometheus: http://192.168.20.170:9090
Loki:       http://192.168.20.170:3100
Tempo:      http://192.168.20.170:3200
AuditProxy: http://192.168.20.170:18080
OTLP HTTP:  http://192.168.20.170:4318
OTLP gRPC:  192.168.20.170:4317
```

## AI Asset Inventory And Model Safety Eval

This lab includes a lightweight AI governance layer for experiments:

- `config/ai-assets.json`: AI apps, models, gateways, data sources and tools.
- `config/model-eval-cases.json`: baseline, prompt injection, multi-turn prompt injection,
  jailbreak, hallucination, unsafe content, privacy leakage, RAG poisoning, RAG citation
  hallucination, tool abuse, agent toolchain abuse, file/database access violation,
  cross-user data leakage, data exfiltration, context cost attack, over-refusal and
  business-rule bypass eval cases.
- `scripts/emit-ai-assets.py`: emits asset inventory events to Loki through OTLP.
- `scripts/model-eval-runner.py`: sends eval cases through Audit Proxy and emits eval evidence.
- Grafana dashboard: `AI Governance - Assets and Model Evals`.

Emit the asset inventory:

```bash
cd observability-lab
./scripts/emit-ai-assets.py --otlp-endpoint http://192.168.20.170:4318
```

Run a dry-run eval without calling the model:

```bash
cd observability-lab
./scripts/model-eval-runner.py \
  --audit-proxy http://192.168.20.170:18080 \
  --otlp-endpoint http://192.168.20.170:4318 \
  --dry-run
```

Run a real eval when you have a SubToAPI-compatible key:

```bash
cd observability-lab
export AI_EVAL_API_KEY="replace-with-eval-only-key"
./scripts/model-eval-runner.py \
  --audit-proxy http://192.168.20.170:18080 \
  --otlp-endpoint http://192.168.20.170:4318 \
  --model gpt-5.5
```

Use a low-privilege evaluation key. Do not use personal production keys for
automated safety testing.

## AI Security Governance Automation

The lab now has an experimental closed-loop governance workflow:

- Red-team automation: `scripts/model-eval-runner.py` runs the eval case library.
- Blue-team detection: the runner classifies refusal, blocking, leakage and hallucination results.
- Risk intake: failed cases automatically emit `ai_risk_finding` records with `finding_id`, owner, due date and recommended fix.
- Remediation workflow: `scripts/finding-workflow.py` emits status updates such as `assigned`, `fixed`, `retest_requested`, `retest_passed` and `closed`.
- Report generation: `scripts/generate-ai-security-report.py` creates a Markdown evidence report from Loki and emits an `ai_compliance_report` event.

Update a finding status:

```bash
./scripts/finding-workflow.py \
  --otlp-endpoint http://192.168.20.170:4318 \
  --finding-id finding-example \
  --status assigned \
  --owner ai-security \
  --note "Assigned for guardrail remediation"
```

Retest one fixed finding:

```bash
./scripts/model-eval-runner.py \
  --audit-proxy http://192.168.20.170:18080 \
  --otlp-endpoint http://192.168.20.170:4318 \
  --model gpt-5.5 \
  --case-id pi-001 \
  --retest-of finding-pi-001-example
```

Generate a report for a run:

```bash
./scripts/generate-ai-security-report.py \
  --loki-url http://192.168.20.170:3100 \
  --otlp-endpoint http://192.168.20.170:4318 \
  --run-id replace-with-run-id \
  --emit-event
```

This is still a lab workflow. Production use still needs WORM or immutable
storage, enterprise IAM/RBAC, formal approval records, retention/deletion policy
enforcement, report signing and backup/restore controls.
