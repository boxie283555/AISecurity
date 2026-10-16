import asyncio
import html
import hashlib
import json
import logging
import os
import re
import time
import uuid
from typing import Any

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import SpanKind, Status, StatusCode
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest


SERVICE_NAME = os.getenv("SERVICE_NAME", "ai-audit-proxy")
UPSTREAM_BASE_URL = os.getenv("UPSTREAM_BASE_URL", "http://192.168.20.241:8080").rstrip("/")
OTLP_ENDPOINT = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4318").rstrip("/")
HASH_SALT = os.getenv("AUDIT_HASH_SALT", "change-me")
ADMIN_PASSWORD = os.getenv("AUDIT_ADMIN_PASSWORD", "")
CAPTURE_BODY = os.getenv("AUDIT_CAPTURE_BODY", "false").lower() == "true"
MAX_CAPTURE_CHARS = int(os.getenv("AUDIT_MAX_CAPTURE_CHARS", "800"))
CAPTURE_GUARDRAIL_SNIPPETS = os.getenv("AUDIT_CAPTURE_GUARDRAIL_SNIPPETS", "true").lower() == "true"
GUARDRAIL_SNIPPET_CHARS = int(os.getenv("AUDIT_GUARDRAIL_SNIPPET_CHARS", "1200"))
SHARED_TOKEN = os.getenv("AUDIT_PROXY_TOKEN", "")
STREAM_IDLE_TIMEOUT = float(os.getenv("AUDIT_STREAM_IDLE_TIMEOUT", "300"))
GUARDRAILS_ENABLED = os.getenv("GUARDRAILS_ENABLED", "true").lower() == "true"
GUARDRAIL_BLOCK_INPUT = os.getenv("GUARDRAIL_BLOCK_INPUT", "true").lower() == "true"
GUARDRAIL_BLOCK_OUTPUT = os.getenv("GUARDRAIL_BLOCK_OUTPUT", "true").lower() == "true"
GUARDRAIL_BANNED_KEYWORDS = [
    item.strip()
    for item in os.getenv("GUARDRAIL_BANNED_KEYWORDS", "种族").split(",")
    if item.strip()
]
GUARDRAIL_BANNED_KEYWORD_STAGES = {
    item.strip().lower()
    for item in os.getenv("GUARDRAIL_BANNED_KEYWORD_STAGES", "output").split(",")
    if item.strip()
}
GUARDRAIL_MAX_STREAM_BYTES = int(os.getenv("GUARDRAIL_MAX_STREAM_BYTES", str(2 * 1024 * 1024)))
DLP_ENABLED = os.getenv("DLP_ENABLED", "true").lower() == "true"
DLP_POLICIES_PATH = os.getenv("DLP_POLICIES_PATH", "/app/config/dlp-policies.json")
DLP_BLOCK_INPUT = os.getenv("DLP_BLOCK_INPUT", "true").lower() == "true"
DLP_BLOCK_OUTPUT = os.getenv("DLP_BLOCK_OUTPUT", "true").lower() == "true"
DLP_MASK_INPUT = os.getenv("DLP_MASK_INPUT", "true").lower() == "true"
DLP_MASK_OUTPUT = os.getenv("DLP_MASK_OUTPUT", "true").lower() == "true"
DLP_CAPTURE_SNIPPETS = os.getenv("DLP_CAPTURE_SNIPPETS", "true").lower() == "true"
DLP_SNIPPET_CHARS = int(os.getenv("DLP_SNIPPET_CHARS", "800"))

DEFAULT_PRICES_PER_1M = {
    "gpt-4o": {"input": 5.0, "output": 15.0},
    "gpt-4o-mini": {"input": 0.15, "output": 0.6},
    "gpt-5": {"input": 1.25, "output": 10.0},
    "gpt-5-mini": {"input": 0.25, "output": 2.0},
    "claude-3-5-sonnet": {"input": 3.0, "output": 15.0},
    "claude-sonnet-4": {"input": 3.0, "output": 15.0},
}


def _load_prices() -> dict[str, dict[str, float]]:
    raw = os.getenv("MODEL_PRICE_PER_1M_JSON", "")
    if not raw:
        return DEFAULT_PRICES_PER_1M
    try:
        configured = json.loads(raw)
        return {**DEFAULT_PRICES_PER_1M, **configured}
    except json.JSONDecodeError:
        return DEFAULT_PRICES_PER_1M


PRICES_PER_1M = _load_prices()

resource = Resource.create(
    {
        "service.name": SERVICE_NAME,
        "deployment.environment": os.getenv("DEPLOYMENT_ENVIRONMENT", "ai-security-lab"),
    }
)

trace_provider = TracerProvider(resource=resource)
trace_provider.add_span_processor(
    BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{OTLP_ENDPOINT}/v1/traces"))
)
trace.set_tracer_provider(trace_provider)
tracer = trace.get_tracer(SERVICE_NAME)

log_provider = LoggerProvider(resource=resource)
log_provider.add_log_record_processor(
    BatchLogRecordProcessor(OTLPLogExporter(endpoint=f"{OTLP_ENDPOINT}/v1/logs"))
)

audit_logger = logging.getLogger("audit")
audit_logger.setLevel(logging.INFO)
audit_logger.addHandler(LoggingHandler(level=logging.INFO, logger_provider=log_provider))

app = FastAPI(title="AI Audit Proxy", version="0.1.0")

REQUESTS = Counter(
    "ai_audit_requests_total",
    "AI API requests observed by the audit proxy.",
    ["method", "route", "model", "status_class"],
)
ERRORS = Counter(
    "ai_audit_errors_total",
    "AI API proxy errors.",
    ["route", "model", "error_type"],
)
TOKENS = Counter(
    "ai_audit_tokens_total",
    "AI API tokens observed or estimated by the audit proxy.",
    ["model", "type"],
)
COST = Counter(
    "ai_audit_cost_usd_total",
    "Estimated AI API cost in USD.",
    ["model"],
)
LATENCY = Histogram(
    "ai_audit_latency_seconds",
    "AI API upstream latency observed by the audit proxy.",
    ["method", "route", "model"],
    buckets=(0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 120),
)
GUARDRAILS = Counter(
    "ai_guardrail_events_total",
    "AI safety guardrail events observed by the audit proxy.",
    ["stage", "action", "rule", "model", "route"],
)
DLP_EVENTS = Counter(
    "ai_dlp_events_total",
    "AI DLP events observed by the audit proxy.",
    ["stage", "action", "category", "severity", "rule", "model", "route"],
)

SENSITIVE_KEYS = {
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "password",
    "secret",
    "token",
    "access_token",
    "refresh_token",
}
STRUCTURAL_TEXT_SKIP_KEYS = {
    "id",
    "call_id",
    "previous_response_id",
    "response_id",
    "conversation_id",
    "item_id",
    "output_index",
    "content_index",
}
REDACTION_PATTERNS = [
    (re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"), "[email]"),
    (re.compile(r"\b1[3-9]\d{9}\b"), "[phone]"),
    (re.compile(r"\b\d{17}[\dXx]\b"), "[cn_id]"),
    (re.compile(r"(?<![\w-])(?:\d[ ]*){16,19}(?![\w-])"), "[card]"),
    (re.compile(r"(?i)(sk-[A-Za-z0-9_\-]{16,})"), "[api_key]"),
]
PROMPT_INJECTION_PATTERNS = [
    ("ignore_previous_instructions", re.compile(r"(?is)\b(ignore|disregard|forget)\b.{0,80}\b(previous|prior|above|system|developer)\b.{0,80}\b(instructions?|messages?|prompt)\b")),
    ("reveal_system_prompt", re.compile(r"(?is)\b(reveal|print|show|dump|exfiltrate)\b.{0,80}\b(system|developer)\b.{0,80}\b(prompt|message|instructions?)\b")),
    ("jailbreak", re.compile(r"(?is)\b(jailbreak|DAN mode|developer mode)\b")),
    ("ignore_cn_instructions", re.compile(r"(?s)(忽略|无视|忘记).{0,40}(之前|以上|系统|开发者).{0,40}(指令|提示|消息)")),
    ("reveal_cn_system_prompt", re.compile(r"(?s)(泄露|显示|打印|输出|告诉我).{0,40}(系统|开发者).{0,40}(提示词|指令|消息)")),
    ("jailbreak_cn", re.compile(r"(越狱|破解限制|绕过安全|绕过限制)")),
]

DEFAULT_DLP_POLICIES = {
    "schema_version": "builtin",
    "default_action": "audit_only",
    "rules": [
        {
            "rule_id": "dlp-openai-api-key",
            "category": "secret",
            "severity": "high",
            "stages": ["input", "output"],
            "patterns": [r"sk-[A-Za-z0-9_-]{16,}"],
            "action": "block",
            "replacement": "[api_key]",
        },
        {
            "rule_id": "dlp-cn-phone",
            "category": "personal_data",
            "severity": "medium",
            "stages": ["input", "output"],
            "patterns": [r"\b1[3-9][0-9]{9}\b"],
            "action": "mask",
            "replacement": "[phone]",
        },
        {
            "rule_id": "dlp-cn-id",
            "category": "personal_data",
            "severity": "high",
            "stages": ["input", "output"],
            "patterns": [r"\b[1-9][0-9]{5}(18|19|20)[0-9]{2}[0-9]{7}[0-9Xx]\b"],
            "action": "block",
            "replacement": "[cn_id]",
        },
    ],
}


def _load_dlp_policies() -> dict[str, Any]:
    if not DLP_ENABLED:
        return {"schema_version": "disabled", "default_action": "audit_only", "rules": []}
    try:
        with open(DLP_POLICIES_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return DEFAULT_DLP_POLICIES


def _compile_dlp_rules(policy: dict[str, Any]) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    default_action = str(policy.get("default_action") or "audit_only")
    for item in policy.get("rules", []):
        compiled_patterns = []
        for pattern in item.get("patterns", []):
            try:
                compiled_patterns.append(re.compile(str(pattern)))
            except re.error:
                continue
        rules.append(
            {
                "rule_id": str(item.get("rule_id") or item.get("name") or "dlp-rule"),
                "name": str(item.get("name") or item.get("rule_id") or "DLP rule"),
                "category": str(item.get("category") or "unknown"),
                "severity": str(item.get("severity") or "medium"),
                "stages": {str(stage).lower() for stage in item.get("stages", ["input", "output"])},
                "patterns": compiled_patterns,
                "keywords": [str(keyword) for keyword in item.get("keywords", []) if str(keyword)],
                "action": str(item.get("action") or default_action).lower(),
                "replacement": str(item.get("replacement") or "[redacted]"),
            }
        )
    return rules


DLP_POLICY = _load_dlp_policies()
DLP_RULES = _compile_dlp_rules(DLP_POLICY)


def _admin_allowed(request: Request) -> bool:
    if not ADMIN_PASSWORD:
        return False
    supplied = request.headers.get("x-admin-password") or request.query_params.get("admin_password", "")
    return supplied == ADMIN_PASSWORD


def _reload_dlp_policy() -> None:
    global DLP_POLICY, DLP_RULES
    DLP_POLICY = _load_dlp_policies()
    DLP_RULES = _compile_dlp_rules(DLP_POLICY)


def _validate_dlp_policy(policy: Any) -> tuple[bool, str]:
    if not isinstance(policy, dict):
        return False, "policy must be a JSON object"
    rules = policy.get("rules")
    if not isinstance(rules, list):
        return False, "policy.rules must be a list"
    for index, rule in enumerate(rules, 1):
        if not isinstance(rule, dict):
            return False, f"rule {index} must be an object"
        if not rule.get("rule_id"):
            return False, f"rule {index} missing rule_id"
        if rule.get("action") not in {"audit_only", "mask", "block"}:
            return False, f"rule {rule.get('rule_id')} has invalid action"
        stages = rule.get("stages", [])
        if not isinstance(stages, list) or not set(stages).issubset({"input", "output"}):
            return False, f"rule {rule.get('rule_id')} has invalid stages"
        for pattern in rule.get("patterns", []):
            try:
                re.compile(str(pattern))
            except re.error as exc:
                return False, f"rule {rule.get('rule_id')} has invalid regex: {exc}"
    return True, "ok"


def _hash(value: str) -> str:
    return hashlib.sha256(f"{HASH_SALT}:{value}".encode()).hexdigest()[:16]


def _safe_route(path: str) -> str:
    if path.startswith("v1/responses"):
        return "/v1/responses"
    if path.startswith("v1/chat/completions"):
        return "/v1/chat/completions"
    if path.startswith("v1/completions"):
        return "/v1/completions"
    if path.startswith("v1/embeddings"):
        return "/v1/embeddings"
    return f"/{path.split('/')[0]}" if path else "/"


def _redact_string(value: str, max_chars: int = MAX_CAPTURE_CHARS) -> str:
    redacted = value
    for pattern, replacement in REDACTION_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    if len(redacted) > max_chars:
        return f"{redacted[:max_chars]}...[truncated]"
    return redacted


def _guardrail_text_field(field_name: str, text: str) -> dict[str, str]:
    if not CAPTURE_GUARDRAIL_SNIPPETS or not text:
        return {}
    return {field_name: _redact_string(text, GUARDRAIL_SNIPPET_CHARS)}


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            key_lower = str(key).lower().replace("-", "_")
            if key_lower in SENSITIVE_KEYS or any(word in key_lower for word in SENSITIVE_KEYS):
                result[key] = "[redacted]"
            else:
                result[key] = _redact(item)
        return result
    if isinstance(value, list):
        return [_redact(item) for item in value[:20]]
    if isinstance(value, str):
        return _redact_string(value)
    return value


def _scan_dlp(text: str, stage: str) -> list[dict[str, str]]:
    if not DLP_ENABLED or not text:
        return []
    stage = stage.lower()
    findings: list[dict[str, str]] = []
    for rule in DLP_RULES:
        if stage not in rule["stages"]:
            continue
        for pattern in rule["patterns"]:
            for match in pattern.finditer(text):
                findings.append(
                    {
                        "stage": stage,
                        "rule_id": rule["rule_id"],
                        "category": rule["category"],
                        "severity": rule["severity"],
                        "action": rule["action"],
                        "match_type": "pattern",
                        "match": _redact_string(match.group(0), 80),
                        "replacement": rule["replacement"],
                    }
                )
                break
        lowered = text.lower()
        for keyword in rule["keywords"]:
            if keyword.lower() in lowered:
                findings.append(
                    {
                        "stage": stage,
                        "rule_id": rule["rule_id"],
                        "category": rule["category"],
                        "severity": rule["severity"],
                        "action": rule["action"],
                        "match_type": "keyword",
                        "match": _redact_string(keyword, 80),
                        "replacement": rule["replacement"],
                    }
                )
    return findings


def _dlp_effective_action(findings: list[dict[str, str]], stage: str) -> str:
    if not findings:
        return "none"
    actions = {finding.get("action", "audit_only") for finding in findings}
    if "block" in actions and ((stage == "input" and DLP_BLOCK_INPUT) or (stage == "output" and DLP_BLOCK_OUTPUT)):
        return "blocked"
    if ("mask" in actions or "block" in actions) and (
        (stage == "input" and DLP_MASK_INPUT) or (stage == "output" and DLP_MASK_OUTPUT)
    ):
        return "masked"
    return "audit_only"


def _mask_dlp_text(text: str, stage: str) -> str:
    if not DLP_ENABLED or not text:
        return text
    masked = text
    stage = stage.lower()
    for rule in DLP_RULES:
        if stage not in rule["stages"] or rule["action"] not in {"mask", "block"}:
            continue
        replacement = rule["replacement"]
        for pattern in rule["patterns"]:
            masked = pattern.sub(replacement, masked)
        for keyword in rule["keywords"]:
            masked = re.sub(re.escape(keyword), replacement, masked, flags=re.IGNORECASE)
    return masked


def _mask_dlp_value(value: Any, stage: str) -> Any:
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            key_lower = str(key).lower()
            if key_lower in STRUCTURAL_TEXT_SKIP_KEYS or key_lower.endswith("_id"):
                result[key] = item
            else:
                result[key] = _mask_dlp_value(item, stage)
        return result
    if isinstance(value, list):
        return [_mask_dlp_value(item, stage) for item in value]
    if isinstance(value, str):
        return _mask_dlp_text(value, stage)
    return value


def _dlp_text_field(field_name: str, text: str) -> dict[str, str]:
    if not DLP_CAPTURE_SNIPPETS or not text:
        return {}
    return {field_name: _redact_string(text, DLP_SNIPPET_CHARS)}


def _dlp_event_fields(findings: list[dict[str, str]]) -> dict[str, Any]:
    return {
        "dlp_rules": sorted({finding["rule_id"] for finding in findings}),
        "dlp_categories": sorted({finding["category"] for finding in findings}),
        "dlp_severities": sorted({finding["severity"] for finding in findings}),
        "dlp_matches": [finding["match"] for finding in findings[:5]],
        "dlp_match_count": len(findings),
    }


def _extract_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return " ".join(_extract_text(item) for item in value)
    if isinstance(value, dict):
        if "text" in value:
            return _extract_text(value["text"])
        if "content" in value:
            return _extract_text(value["content"])
        return " ".join(
            _extract_text(item)
            for key, item in value.items()
            if str(key).lower() not in STRUCTURAL_TEXT_SKIP_KEYS and not str(key).lower().endswith("_id")
        )
    return ""


def _scan_guardrails(text: str, stage: str) -> list[dict[str, str]]:
    if not GUARDRAILS_ENABLED or not text:
        return []
    findings: list[dict[str, str]] = []
    if stage in GUARDRAIL_BANNED_KEYWORD_STAGES:
        for keyword in GUARDRAIL_BANNED_KEYWORDS:
            if keyword and keyword in text:
                findings.append(
                    {
                        "stage": stage,
                        "rule": "banned_keyword",
                        "match": _redact_string(keyword),
                    }
                )
    if stage == "input":
        for rule, pattern in PROMPT_INJECTION_PATTERNS:
            if pattern.search(text):
                findings.append(
                    {
                        "stage": stage,
                        "rule": f"prompt_injection:{rule}",
                        "match": rule,
                    }
                )
    return findings


def _request_text(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""
    return _extract_text(payload.get("messages")) or _extract_text(payload.get("input")) or _extract_text(payload)


def _response_text(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""
    return _extract_text(payload.get("output")) or _extract_text(payload.get("choices")) or _extract_text(payload)


def _request_metadata(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {"model": "unknown", "stream": False, "input_tokens_estimated": 0}
    messages = payload.get("messages") or []
    prompt_text = _extract_text(messages) or _extract_text(payload.get("input"))
    return {
        "model": str(payload.get("model") or "unknown"),
        "stream": bool(payload.get("stream")),
        "input_tokens_estimated": max(1, len(prompt_text) // 4) if prompt_text else 0,
    }


def _as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _usage_from_response(payload: Any) -> dict[str, int]:
    if not isinstance(payload, dict):
        return {}
    usage = payload.get("usage") or {}
    if not usage and isinstance(payload.get("response"), dict):
        usage = payload["response"].get("usage") or {}
    input_details = usage.get("prompt_tokens_details") or usage.get("input_tokens_details") or {}
    output_details = usage.get("completion_tokens_details") or usage.get("output_tokens_details") or {}
    return {
        "input_tokens": _as_int(usage.get("prompt_tokens") or usage.get("input_tokens")),
        "output_tokens": _as_int(usage.get("completion_tokens") or usage.get("output_tokens")),
        "total_tokens": _as_int(usage.get("total_tokens")),
        "cached_tokens": _as_int(
            input_details.get("cached_tokens")
            or usage.get("cached_tokens")
            or usage.get("cache_read_input_tokens")
        ),
        "reasoning_tokens": _as_int(
            output_details.get("reasoning_tokens")
            or usage.get("reasoning_tokens")
        ),
    }


def _usage_audit_fields(
    usage: dict[str, int],
    input_token_source: str,
    output_token_source: str,
) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "input_token_source": input_token_source,
        "output_token_source": output_token_source,
    }
    if usage.get("total_tokens"):
        fields["usage_total_tokens"] = usage["total_tokens"]
    if usage.get("cached_tokens"):
        fields["cached_tokens"] = usage["cached_tokens"]
    if usage.get("reasoning_tokens"):
        fields["reasoning_tokens"] = usage["reasoning_tokens"]
    return fields


def _estimate_output_tokens(payload: Any) -> int:
    if not isinstance(payload, dict):
        return 0
    choices = payload.get("choices") or []
    text = _extract_text(choices)
    return max(1, len(text) // 4) if text else 0


def _cost(model: str, input_tokens: int, output_tokens: int) -> float:
    matched = None
    model_lower = model.lower()
    for name, price in PRICES_PER_1M.items():
        if name in model_lower:
            matched = price
            break
    if matched is None:
        return 0.0
    return ((input_tokens * matched["input"]) + (output_tokens * matched["output"])) / 1_000_000


def _status_class(status_code: int) -> str:
    return f"{status_code // 100}xx"


def _copy_headers(headers: dict[str, str]) -> dict[str, str]:
    blocked = {"host", "content-length", "connection", "keep-alive", "proxy-authenticate", "proxy-authorization"}
    return {key: value for key, value in headers.items() if key.lower() not in blocked}


def _client_identity(request: Request) -> dict[str, str]:
    auth = request.headers.get("authorization", "")
    user_id = request.headers.get("x-user-id") or request.headers.get("x-audit-user") or "unknown"
    return {
        "user_id_hash": _hash(user_id) if user_id != "unknown" else "unknown",
        "api_key_id": _hash(auth.replace("Bearer ", "")[-24:]) if auth else "none",
        "client_ip": request.client.host if request.client else "unknown",
    }


def _audit_log(event: dict[str, Any]) -> None:
    line = {"message": "ai_audit_event", **event}
    audit_logger.info(json.dumps(line, ensure_ascii=False, separators=(",", ":")))


def _audit_guardrail(event: dict[str, Any]) -> None:
    line = {**event, "message": "ai_guardrail_event", "event": "ai_guardrail_event"}
    audit_logger.warning(json.dumps(line, ensure_ascii=False, separators=(",", ":")))


def _audit_dlp(event: dict[str, Any]) -> None:
    line = {**event, "message": "ai_dlp_event", "event": "ai_dlp_event"}
    audit_logger.warning(json.dumps(line, ensure_ascii=False, separators=(",", ":")))


def _record_dlp_metrics(
    findings: list[dict[str, str]],
    action: str,
    model: str,
    route: str,
) -> None:
    for finding in findings:
        DLP_EVENTS.labels(
            finding["stage"],
            action,
            finding["category"],
            finding["severity"],
            finding["rule_id"],
            model,
            route,
        ).inc()


def _guardrail_error(stage: str, findings: list[dict[str, str]], request_id: str, trace_id: str) -> JSONResponse:
    rules = sorted({finding["rule"] for finding in findings})
    return JSONResponse(
        {
            "error": {
                "message": f"AI safety guardrail blocked {stage}.",
                "type": "guardrail_violation",
                "code": "ai_safety_blocked",
                "rules": rules,
            },
            "request_id": request_id,
            "trace_id": trace_id,
        },
        status_code=451,
        headers={"x-request-id": request_id, "x-trace-id": trace_id, "x-guardrail-action": "blocked"},
    )


def _dlp_error(stage: str, findings: list[dict[str, str]], request_id: str, trace_id: str) -> JSONResponse:
    rules = sorted({finding["rule_id"] for finding in findings})
    return JSONResponse(
        {
            "error": {
                "message": f"DLP policy blocked {stage}.",
                "type": "dlp_violation",
                "code": "ai_dlp_blocked",
                "rules": rules,
            },
            "request_id": request_id,
            "trace_id": trace_id,
        },
        status_code=451,
        headers={"x-request-id": request_id, "x-trace-id": trace_id, "x-dlp-action": "blocked"},
    )


async def _parse_json_body(body: bytes, content_type: str) -> Any:
    if not body or "application/json" not in content_type.lower():
        return None
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return None


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": SERVICE_NAME, "upstream": UPSTREAM_BASE_URL}


@app.get("/config")
async def config() -> dict[str, Any]:
    return {
        "service": SERVICE_NAME,
        "upstream": UPSTREAM_BASE_URL,
        "guardrails": {
            "enabled": GUARDRAILS_ENABLED,
            "block_input": GUARDRAIL_BLOCK_INPUT,
            "block_output": GUARDRAIL_BLOCK_OUTPUT,
            "banned_keywords": GUARDRAIL_BANNED_KEYWORDS,
            "banned_keyword_stages": sorted(GUARDRAIL_BANNED_KEYWORD_STAGES),
            "max_stream_bytes": GUARDRAIL_MAX_STREAM_BYTES,
        },
        "audit": {
            "capture_body": CAPTURE_BODY,
            "max_capture_chars": MAX_CAPTURE_CHARS,
            "capture_guardrail_snippets": CAPTURE_GUARDRAIL_SNIPPETS,
            "guardrail_snippet_chars": GUARDRAIL_SNIPPET_CHARS,
        },
        "dlp": {
            "enabled": DLP_ENABLED,
            "policies_path": DLP_POLICIES_PATH,
            "policy_schema_version": DLP_POLICY.get("schema_version"),
            "rule_count": len(DLP_RULES),
            "block_input": DLP_BLOCK_INPUT,
            "block_output": DLP_BLOCK_OUTPUT,
            "mask_input": DLP_MASK_INPUT,
            "mask_output": DLP_MASK_OUTPUT,
            "capture_snippets": DLP_CAPTURE_SNIPPETS,
            "snippet_chars": DLP_SNIPPET_CHARS,
        },
        "otlp_endpoint": OTLP_ENDPOINT,
    }


@app.get("/home", response_class=HTMLResponse)
async def home() -> HTMLResponse:
    dlp_rows = []
    for rule in DLP_POLICY.get("rules", []):
        dlp_rows.append(
            "<tr>"
            f"<td>{html.escape(str(rule.get('rule_id', '')))}</td>"
            f"<td>{html.escape(str(rule.get('name', '')))}</td>"
            f"<td>{html.escape(str(rule.get('category', '')))}</td>"
            f"<td>{html.escape(str(rule.get('severity', '')))}</td>"
            f"<td>{html.escape(', '.join(rule.get('stages', [])))}</td>"
            f"<td><span class='badge action-{html.escape(str(rule.get('action', '')))}'>{html.escape(str(rule.get('action', '')))}</span></td>"
            "</tr>"
        )
    policy_json = html.escape(json.dumps(DLP_POLICY, ensure_ascii=False, indent=2))
    admin_note = (
        "Set AUDIT_ADMIN_PASSWORD to enable saving changes."
        if not ADMIN_PASSWORD
        else "Enter the admin password to save DLP policy changes."
    )
    content = f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AI Audit Proxy</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --text: #1f2937;
      --muted: #6b7280;
      --line: #d8dee8;
      --blue: #2563eb;
      --green: #0f766e;
      --amber: #b45309;
      --red: #b91c1c;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: var(--bg);
      color: var(--text);
    }}
    header {{
      background: #111827;
      color: white;
      padding: 20px 28px;
    }}
    header h1 {{ margin: 0; font-size: 24px; letter-spacing: 0; }}
    header p {{ margin: 6px 0 0; color: #cbd5e1; }}
    main {{ max-width: 1280px; margin: 0 auto; padding: 24px; }}
    section {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 18px;
      margin-bottom: 18px;
    }}
    h2 {{ margin: 0 0 14px; font-size: 18px; }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 12px;
    }}
    .kv {{
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 12px;
      min-height: 74px;
    }}
    .kv .label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; }}
    .kv .value {{ margin-top: 6px; font-size: 15px; overflow-wrap: anywhere; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
    th, td {{ text-align: left; border-bottom: 1px solid var(--line); padding: 10px 8px; vertical-align: top; }}
    th {{ color: var(--muted); font-weight: 600; }}
    .badge {{ display: inline-block; border-radius: 999px; padding: 2px 8px; font-size: 12px; background: #e5e7eb; }}
    .action-block {{ background: #fee2e2; color: var(--red); }}
    .action-mask {{ background: #fef3c7; color: var(--amber); }}
    .action-audit_only {{ background: #ccfbf1; color: var(--green); }}
    textarea {{
      width: 100%;
      min-height: 420px;
      font: 13px/1.45 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 12px;
      resize: vertical;
    }}
    .row {{ display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-top: 12px; }}
    input[type=password] {{
      min-width: 260px;
      padding: 9px 10px;
      border: 1px solid var(--line);
      border-radius: 6px;
    }}
    button {{
      border: 0;
      border-radius: 6px;
      background: var(--blue);
      color: white;
      padding: 10px 14px;
      cursor: pointer;
      font-weight: 600;
    }}
    button:disabled {{ opacity: .55; cursor: not-allowed; }}
    .links a {{ margin-right: 14px; color: var(--blue); text-decoration: none; }}
    .status {{ color: var(--muted); }}
    .warn {{ color: var(--amber); }}
  </style>
</head>
<body>
  <header>
    <h1>AI Audit Proxy</h1>
    <p>Read-only runtime view plus guarded DLP policy editing for the lab.</p>
  </header>
  <main>
    <section>
      <h2>Runtime</h2>
      <div class="grid">
        <div class="kv"><div class="label">Service</div><div class="value">{html.escape(SERVICE_NAME)}</div></div>
        <div class="kv"><div class="label">Upstream</div><div class="value">{html.escape(UPSTREAM_BASE_URL)}</div></div>
        <div class="kv"><div class="label">OTLP</div><div class="value">{html.escape(OTLP_ENDPOINT)}</div></div>
        <div class="kv"><div class="label">Body Capture</div><div class="value">{CAPTURE_BODY}</div></div>
      </div>
      <p class="links"><a href="/health">Health</a><a href="/config">Config JSON</a><a href="/metrics">Metrics</a></p>
    </section>
    <section>
      <h2>Guardrails</h2>
      <div class="grid">
        <div class="kv"><div class="label">Enabled</div><div class="value">{GUARDRAILS_ENABLED}</div></div>
        <div class="kv"><div class="label">Block Input</div><div class="value">{GUARDRAIL_BLOCK_INPUT}</div></div>
        <div class="kv"><div class="label">Block Output</div><div class="value">{GUARDRAIL_BLOCK_OUTPUT}</div></div>
        <div class="kv"><div class="label">Banned Keyword Stages</div><div class="value">{html.escape(', '.join(sorted(GUARDRAIL_BANNED_KEYWORD_STAGES)))}</div></div>
      </div>
    </section>
    <section>
      <h2>DLP Runtime</h2>
      <div class="grid">
        <div class="kv"><div class="label">Enabled</div><div class="value">{DLP_ENABLED}</div></div>
        <div class="kv"><div class="label">Rules</div><div class="value">{len(DLP_RULES)}</div></div>
        <div class="kv"><div class="label">Block Input</div><div class="value">{DLP_BLOCK_INPUT}</div></div>
        <div class="kv"><div class="label">Mask Input</div><div class="value">{DLP_MASK_INPUT}</div></div>
        <div class="kv"><div class="label">Block Output</div><div class="value">{DLP_BLOCK_OUTPUT}</div></div>
        <div class="kv"><div class="label">Mask Output</div><div class="value">{DLP_MASK_OUTPUT}</div></div>
      </div>
    </section>
    <section>
      <h2>DLP Rules</h2>
      <table>
        <thead><tr><th>Rule ID</th><th>Name</th><th>Category</th><th>Severity</th><th>Stages</th><th>Action</th></tr></thead>
        <tbody>{''.join(dlp_rows)}</tbody>
      </table>
    </section>
    <section>
      <h2>Edit DLP Policy</h2>
      <p class="status">{html.escape(admin_note)}</p>
      <textarea id="policy">{policy_json}</textarea>
      <div class="row">
        <input id="adminPassword" type="password" placeholder="Admin password">
        <button id="saveBtn" {"disabled" if not ADMIN_PASSWORD else ""}>Save and Reload DLP</button>
        <span id="saveStatus" class="status"></span>
      </div>
      <p class="warn">Only DLP policy JSON is edited here. Runtime environment values still require .env changes and container rebuild.</p>
    </section>
  </main>
  <script>
    const saveBtn = document.getElementById('saveBtn');
    const saveStatus = document.getElementById('saveStatus');
    saveBtn?.addEventListener('click', async () => {{
      saveStatus.textContent = 'Saving...';
      let policy;
      try {{
        policy = JSON.parse(document.getElementById('policy').value);
      }} catch (error) {{
        saveStatus.textContent = 'Invalid JSON: ' + error.message;
        return;
      }}
      const response = await fetch('/admin/dlp-policy', {{
        method: 'POST',
        headers: {{
          'Content-Type': 'application/json',
          'x-admin-password': document.getElementById('adminPassword').value
        }},
        body: JSON.stringify(policy)
      }});
      const result = await response.json().catch(() => ({{ok: false, error: 'invalid response'}}));
      if (!response.ok) {{
        saveStatus.textContent = result.error || 'Save failed';
        return;
      }}
      saveStatus.textContent = 'Saved. Reloading...';
      setTimeout(() => window.location.reload(), 700);
    }});
  </script>
</body>
</html>
"""
    return HTMLResponse(content)


@app.post("/admin/dlp-policy")
async def update_dlp_policy(request: Request) -> JSONResponse:
    if not _admin_allowed(request):
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
    try:
        policy = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "invalid JSON body"}, status_code=400)
    ok, message = _validate_dlp_policy(policy)
    if not ok:
        return JSONResponse({"ok": False, "error": message}, status_code=400)
    try:
        with open(DLP_POLICIES_PATH, "w", encoding="utf-8") as fh:
            json.dump(policy, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        _reload_dlp_policy()
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"failed to save policy: {exc}"}, status_code=500)
    return JSONResponse({"ok": True, "rule_count": len(DLP_RULES), "schema_version": DLP_POLICY.get("schema_version")})


@app.get("/metrics")
async def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
async def proxy(path: str, request: Request) -> Response:
    if SHARED_TOKEN:
        supplied = request.headers.get("x-audit-proxy-token", "")
        if supplied != SHARED_TOKEN:
            return JSONResponse({"error": "unauthorized"}, status_code=401)

    method = request.method
    route = _safe_route(path)
    request_id = request.headers.get("x-request-id", str(uuid.uuid4()))
    body = await request.body()
    request_payload = await _parse_json_body(body, request.headers.get("content-type", ""))
    request_meta = _request_metadata(request_payload)
    model = request_meta["model"]
    started = time.perf_counter()
    upstream_url = f"{UPSTREAM_BASE_URL}/{path}"
    query = request.url.query
    if query:
        upstream_url = f"{upstream_url}?{query}"

    identity = _client_identity(request)
    outbound_headers = _copy_headers(dict(request.headers))
    outbound_headers["x-request-id"] = request_id

    with tracer.start_as_current_span(
        f"{method} {route}",
        kind=SpanKind.SERVER,
        attributes={
            "ai.request.id": request_id,
            "ai.model": model,
            "http.route": route,
            "http.request.method": method,
            "server.address": request.url.hostname or "",
            "url.path": f"/{path}",
            "upstream.base_url": UPSTREAM_BASE_URL,
            "user.id_hash": identity["user_id_hash"],
            "api.key_id": identity["api_key_id"],
        },
    ) as span:
        trace_id = format(span.get_span_context().trace_id, "032x")
        audit_base = {
            "event": "ai_api_call",
            "request_id": request_id,
            "trace_id": trace_id,
            "method": method,
            "route": route,
            "model": model,
            **identity,
        }
        if CAPTURE_BODY and request_payload is not None:
            audit_base["request_body_redacted"] = _redact(request_payload)

        request_text = _request_text(request_payload)
        input_dlp_findings = _scan_dlp(request_text, "input")
        input_dlp_action = _dlp_effective_action(input_dlp_findings, "input")
        if input_dlp_findings:
            _record_dlp_metrics(input_dlp_findings, input_dlp_action, model, route)
            latency = time.perf_counter() - started
            _audit_dlp(
                {
                    **audit_base,
                    "stage": "input",
                    "action": input_dlp_action,
                    **_dlp_event_fields(input_dlp_findings),
                    **_dlp_text_field("input_text_redacted", request_text),
                    "status_code": 451 if input_dlp_action == "blocked" else 0,
                    "latency_ms": round(latency * 1000, 2),
                }
            )
        if input_dlp_action == "blocked":
            latency = time.perf_counter() - started
            first_rule = input_dlp_findings[0]["rule_id"]
            REQUESTS.labels(method, route, model, "4xx").inc()
            LATENCY.labels(method, route, model).observe(latency)
            span.set_attribute("ai.dlp.action", "blocked")
            span.set_attribute("ai.dlp.stage", "input")
            span.set_attribute("ai.dlp.rule", first_rule)
            span.set_attribute("http.response.status_code", 451)
            span.set_status(Status(StatusCode.ERROR))
            _audit_log(
                {
                    **audit_base,
                    "status_code": 451,
                    "latency_ms": round(latency * 1000, 2),
                    "input_tokens": request_meta["input_tokens_estimated"],
                    "output_tokens": 0,
                    "cost_usd": 0.0,
                    "input_token_source": "estimated",
                    "output_token_source": "none",
                    "stream": request_meta["stream"],
                    "security_action": "blocked",
                    "dlp_stage": "input",
                    "dlp_rule": first_rule,
                    **_dlp_event_fields(input_dlp_findings),
                }
            )
            return _dlp_error("input", input_dlp_findings, request_id, trace_id)
        if input_dlp_action == "masked" and request_payload is not None:
            request_payload = _mask_dlp_value(request_payload, "input")
            request_text = _request_text(request_payload)
            body = json.dumps(request_payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            outbound_headers["content-type"] = "application/json"
            if CAPTURE_BODY:
                audit_base["request_body_redacted"] = _redact(request_payload)

        input_findings = _scan_guardrails(request_text, "input")
        if input_findings and GUARDRAIL_BLOCK_INPUT:
            latency = time.perf_counter() - started
            first_rule = input_findings[0]["rule"]
            GUARDRAILS.labels("input", "blocked", first_rule, model, route).inc()
            REQUESTS.labels(method, route, model, "4xx").inc()
            LATENCY.labels(method, route, model).observe(latency)
            span.set_attribute("ai.guardrail.action", "blocked")
            span.set_attribute("ai.guardrail.stage", "input")
            span.set_attribute("ai.guardrail.rule", first_rule)
            span.set_attribute("http.response.status_code", 451)
            span.set_status(Status(StatusCode.ERROR))
            _audit_guardrail(
                {
                    **audit_base,
                    "stage": "input",
                    "action": "blocked",
                    "rules": sorted({finding["rule"] for finding in input_findings}),
                    "matches": [finding["match"] for finding in input_findings[:5]],
                    **_guardrail_text_field("input_text_redacted", request_text),
                    "status_code": 451,
                    "latency_ms": round(latency * 1000, 2),
                }
            )
            _audit_log(
                {
                    **audit_base,
                    "status_code": 451,
                    "latency_ms": round(latency * 1000, 2),
                    "input_tokens": request_meta["input_tokens_estimated"],
                    "output_tokens": 0,
                    "cost_usd": 0.0,
                    "input_token_source": "estimated",
                    "output_token_source": "none",
                    "stream": request_meta["stream"],
                    "security_action": "blocked",
                    "guardrail_stage": "input",
                    "guardrail_rule": first_rule,
                }
            )
            return _guardrail_error("input", input_findings, request_id, trace_id)

        client = httpx.AsyncClient(timeout=None)
        try:
            upstream_request = client.build_request(
                method,
                upstream_url,
                headers=outbound_headers,
                content=body,
            )
            upstream_response = await client.send(upstream_request, stream=True)

            content_type = upstream_response.headers.get("content-type", "")
            is_stream = "text/event-stream" in content_type.lower() or request_meta["stream"]
            if is_stream:
                return await _stream_response(
                    upstream_response,
                    client,
                    started,
                    method,
                    route,
                    model,
                    audit_base,
                    span,
                    request_meta,
                    request_text,
                )

            response_body = await upstream_response.aread()
            await upstream_response.aclose()
            await client.aclose()
            status_code = upstream_response.status_code
            latency = time.perf_counter() - started
            response_payload = await _parse_json_body(response_body, content_type)
            usage = _usage_from_response(response_payload)
            usage_input_tokens = usage.get("input_tokens", 0)
            usage_output_tokens = usage.get("output_tokens", 0)
            input_tokens = usage_input_tokens or request_meta["input_tokens_estimated"]
            output_tokens = usage_output_tokens or _estimate_output_tokens(response_payload)
            input_token_source = "usage" if usage_input_tokens else "estimated"
            output_token_source = "usage" if usage_output_tokens else ("estimated" if output_tokens else "none")
            cost_usd = _cost(model, input_tokens, output_tokens)
            response_text = _response_text(response_payload)
            output_dlp_findings = _scan_dlp(response_text, "output")
            output_dlp_action = _dlp_effective_action(output_dlp_findings, "output")
            if output_dlp_findings:
                _record_dlp_metrics(output_dlp_findings, output_dlp_action, model, route)
                _audit_dlp(
                    {
                        **audit_base,
                        "stage": "output",
                        "action": output_dlp_action,
                        **_dlp_event_fields(output_dlp_findings),
                        **_dlp_text_field("input_text_redacted", request_text),
                        **_dlp_text_field("output_text_redacted", response_text),
                        "status_code": 451 if output_dlp_action == "blocked" else status_code,
                        "latency_ms": round(latency * 1000, 2),
                    }
                )
            if output_dlp_action == "blocked":
                status_code = 451
                first_rule = output_dlp_findings[0]["rule_id"]
                REQUESTS.labels(method, route, model, "4xx").inc()
                LATENCY.labels(method, route, model).observe(latency)
                span.set_attribute("http.response.status_code", status_code)
                span.set_attribute("ai.dlp.action", "blocked")
                span.set_attribute("ai.dlp.stage", "output")
                span.set_attribute("ai.dlp.rule", first_rule)
                span.set_status(Status(StatusCode.ERROR))
                _audit_log(
                    {
                        **audit_base,
                        "status_code": status_code,
                        "latency_ms": round(latency * 1000, 2),
                        "input_tokens": input_tokens,
                        "output_tokens": output_tokens,
                        "cost_usd": round(cost_usd, 8),
                        **_usage_audit_fields(usage, input_token_source, output_token_source),
                        "stream": False,
                        "security_action": "blocked",
                        "dlp_stage": "output",
                        "dlp_rule": first_rule,
                        **_dlp_event_fields(output_dlp_findings),
                    }
                )
                return _dlp_error("output", output_dlp_findings, request_id, trace_id)
            if output_dlp_action == "masked" and response_payload is not None:
                response_payload = _mask_dlp_value(response_payload, "output")
                response_body = json.dumps(response_payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                response_text = _response_text(response_payload)

            output_findings = _scan_guardrails(response_text, "output")
            if output_findings and GUARDRAIL_BLOCK_OUTPUT:
                status_code = 451
                first_rule = output_findings[0]["rule"]
                GUARDRAILS.labels("output", "blocked", first_rule, model, route).inc()
                REQUESTS.labels(method, route, model, "4xx").inc()
                LATENCY.labels(method, route, model).observe(latency)
                span.set_attribute("http.response.status_code", status_code)
                span.set_attribute("ai.guardrail.action", "blocked")
                span.set_attribute("ai.guardrail.stage", "output")
                span.set_attribute("ai.guardrail.rule", first_rule)
                span.set_status(Status(StatusCode.ERROR))
                _audit_guardrail(
                    {
                        **audit_base,
                        "stage": "output",
                        "action": "blocked",
                        "rules": sorted({finding["rule"] for finding in output_findings}),
                        "matches": [finding["match"] for finding in output_findings[:5]],
                        **_guardrail_text_field("input_text_redacted", request_text),
                        **_guardrail_text_field("output_text_redacted", response_text),
                        "status_code": status_code,
                        "latency_ms": round(latency * 1000, 2),
                    }
                )
                _audit_log(
                    {
                        **audit_base,
                        "status_code": status_code,
                        "latency_ms": round(latency * 1000, 2),
                        "input_tokens": input_tokens,
                        "output_tokens": output_tokens,
                        "cost_usd": round(cost_usd, 8),
                        **_usage_audit_fields(usage, input_token_source, output_token_source),
                        "stream": False,
                        "security_action": "blocked",
                        "guardrail_stage": "output",
                        "guardrail_rule": first_rule,
                    }
                )
                return _guardrail_error("output", output_findings, request_id, trace_id)

            _record_metrics(method, route, model, status_code, latency, input_tokens, output_tokens, cost_usd)
            span.set_attribute("http.response.status_code", status_code)
            span.set_attribute("ai.usage.input_tokens", input_tokens)
            span.set_attribute("ai.usage.output_tokens", output_tokens)
            span.set_attribute("ai.cost.usd", cost_usd)
            if status_code >= 500:
                span.set_status(Status(StatusCode.ERROR))

            event = {
                **audit_base,
                "status_code": status_code,
                "latency_ms": round(latency * 1000, 2),
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cost_usd": round(cost_usd, 8),
                **_usage_audit_fields(usage, input_token_source, output_token_source),
                "stream": False,
            }
            if input_dlp_action != "none":
                event["input_dlp_action"] = input_dlp_action
                event.update({f"input_{key}": value for key, value in _dlp_event_fields(input_dlp_findings).items()})
            if output_dlp_action != "none":
                event["output_dlp_action"] = output_dlp_action
                event.update({f"output_{key}": value for key, value in _dlp_event_fields(output_dlp_findings).items()})
            if CAPTURE_BODY and response_payload is not None:
                event["response_body_redacted"] = _redact(response_payload)
            _audit_log(event)

            response_headers = _response_headers(upstream_response.headers, request_id, trace_id)
            return Response(
                content=response_body,
                status_code=status_code,
                headers=response_headers,
                media_type=content_type or None,
            )
        except Exception as exc:
            await client.aclose()
            latency = time.perf_counter() - started
            ERRORS.labels(route, model, exc.__class__.__name__).inc()
            REQUESTS.labels(method, route, model, "5xx").inc()
            LATENCY.labels(method, route, model).observe(latency)
            span.record_exception(exc)
            span.set_status(Status(StatusCode.ERROR))
            _audit_log(
                {
                    **audit_base,
                    "status_code": 502,
                    "latency_ms": round(latency * 1000, 2),
                    "error": exc.__class__.__name__,
                    "error_message": str(exc)[:300],
                }
            )
            return JSONResponse(
                {"error": "upstream_unavailable", "request_id": request_id},
                status_code=502,
                headers={"x-request-id": request_id, "x-trace-id": trace_id},
            )


async def _stream_response(
    upstream_response: httpx.Response,
    client: httpx.AsyncClient,
    started: float,
    method: str,
    route: str,
    model: str,
    audit_base: dict[str, Any],
    span: trace.Span,
    request_meta: dict[str, Any],
    request_text: str,
) -> StreamingResponse:
    chunks: list[str] = []
    status_code = upstream_response.status_code
    request_id = audit_base["request_id"]
    trace_id = audit_base["trace_id"]
    raw_chunks: list[bytes] = []
    exceeded_scan_limit = False

    try:
        total_bytes = 0
        async with asyncio.timeout(STREAM_IDLE_TIMEOUT):
            async for chunk in upstream_response.aiter_bytes():
                total_bytes += len(chunk)
                if total_bytes <= GUARDRAIL_MAX_STREAM_BYTES:
                    raw_chunks.append(chunk)
                    if len(chunks) < 500:
                        try:
                            chunks.append(chunk.decode("utf-8", errors="ignore"))
                        except Exception:
                            pass
                else:
                    exceeded_scan_limit = True
                    break
    finally:
        await upstream_response.aclose()
        await client.aclose()

    latency = time.perf_counter() - started
    stream_chunks = _decode_raw_chunks(raw_chunks) or chunks
    usage = _stream_usage(stream_chunks)
    usage_input_tokens = usage.get("input_tokens", 0)
    usage_output_tokens = usage.get("output_tokens", 0)
    input_tokens = usage_input_tokens or request_meta["input_tokens_estimated"]
    output_tokens = usage_output_tokens or _estimate_stream_tokens(stream_chunks)
    input_token_source = "usage_stream" if usage_input_tokens else "estimated"
    output_token_source = "usage_stream" if usage_output_tokens else ("estimated" if output_tokens else "none")
    cost_usd = _cost(model, input_tokens, output_tokens)
    stream_text = _stream_output_text(stream_chunks)
    output_dlp_findings = _scan_dlp(stream_text, "output")
    output_dlp_action = _dlp_effective_action(output_dlp_findings, "output")
    if output_dlp_findings:
        _record_dlp_metrics(output_dlp_findings, output_dlp_action, model, route)
        _audit_dlp(
            {
                **audit_base,
                "stage": "output",
                "action": output_dlp_action,
                **_dlp_event_fields(output_dlp_findings),
                **_dlp_text_field("input_text_redacted", request_text),
                **_dlp_text_field("output_text_redacted", stream_text),
                "status_code": 451 if output_dlp_action == "blocked" else status_code,
                "latency_ms": round(latency * 1000, 2),
                "stream": True,
            }
        )
    if output_dlp_action == "blocked":
        first_rule = output_dlp_findings[0]["rule_id"]
        REQUESTS.labels(method, route, model, "4xx").inc()
        LATENCY.labels(method, route, model).observe(latency)
        span.set_attribute("http.response.status_code", 451)
        span.set_attribute("ai.usage.input_tokens", input_tokens)
        span.set_attribute("ai.usage.output_tokens", output_tokens)
        span.set_attribute("ai.cost.usd", cost_usd)
        span.set_attribute("ai.dlp.action", "blocked")
        span.set_attribute("ai.dlp.stage", "output")
        span.set_attribute("ai.dlp.rule", first_rule)
        span.set_status(Status(StatusCode.ERROR))
        _audit_log(
            {
                **audit_base,
                "status_code": 451,
                "latency_ms": round(latency * 1000, 2),
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cost_usd": round(cost_usd, 8),
                **_usage_audit_fields(usage, input_token_source, output_token_source),
                "stream": True,
                "security_action": "blocked",
                "dlp_stage": "output",
                "dlp_rule": first_rule,
                **_dlp_event_fields(output_dlp_findings),
            }
        )

        async def dlp_blocked_generator():
            payload = {
                "type": "dlp.blocked",
                "error": {
                    "message": "DLP policy blocked output.",
                    "type": "dlp_violation",
                    "code": "ai_dlp_blocked",
                    "rules": sorted({finding["rule_id"] for finding in output_dlp_findings}),
                },
                "request_id": request_id,
                "trace_id": trace_id,
            }
            yield f"event: error\ndata: {json.dumps(payload, ensure_ascii=False, separators=(',', ':'))}\n\n".encode()

        return StreamingResponse(
            dlp_blocked_generator(),
            status_code=451,
            headers={"x-request-id": request_id, "x-trace-id": trace_id, "x-dlp-action": "blocked"},
            media_type="text/event-stream",
        )
    if output_dlp_action == "masked":
        masked_stream = _mask_dlp_text("".join(stream_chunks), "output")
        raw_chunks = [masked_stream.encode("utf-8")]
        stream_chunks = [masked_stream]
        stream_text = _stream_output_text(stream_chunks)

    output_findings = _scan_guardrails(stream_text, "output")

    if exceeded_scan_limit and GUARDRAIL_BLOCK_OUTPUT:
        output_findings.append(
            {
                "stage": "output",
                "rule": "stream_scan_limit_exceeded",
                "match": str(GUARDRAIL_MAX_STREAM_BYTES),
            }
        )

    if output_findings and GUARDRAIL_BLOCK_OUTPUT:
        first_rule = output_findings[0]["rule"]
        GUARDRAILS.labels("output", "blocked", first_rule, model, route).inc()
        REQUESTS.labels(method, route, model, "4xx").inc()
        LATENCY.labels(method, route, model).observe(latency)
        span.set_attribute("http.response.status_code", 451)
        span.set_attribute("ai.usage.input_tokens", input_tokens)
        span.set_attribute("ai.usage.output_tokens", output_tokens)
        span.set_attribute("ai.cost.usd", cost_usd)
        span.set_attribute("ai.guardrail.action", "blocked")
        span.set_attribute("ai.guardrail.stage", "output")
        span.set_attribute("ai.guardrail.rule", first_rule)
        span.set_status(Status(StatusCode.ERROR))
        _audit_guardrail(
            {
                **audit_base,
                "stage": "output",
                "action": "blocked",
                "rules": sorted({finding["rule"] for finding in output_findings}),
                "matches": [finding["match"] for finding in output_findings[:5]],
                **_guardrail_text_field("input_text_redacted", request_text),
                **_guardrail_text_field("output_text_redacted", stream_text),
                "status_code": 451,
                "latency_ms": round(latency * 1000, 2),
                "stream": True,
            }
        )
        _audit_log(
            {
                **audit_base,
                "status_code": 451,
                "latency_ms": round(latency * 1000, 2),
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cost_usd": round(cost_usd, 8),
                **_usage_audit_fields(usage, input_token_source, output_token_source),
                "stream": True,
                "security_action": "blocked",
                "guardrail_stage": "output",
                "guardrail_rule": first_rule,
            }
        )

        async def blocked_generator():
            payload = {
                "type": "guardrail.blocked",
                "error": {
                    "message": "AI safety guardrail blocked output.",
                    "type": "guardrail_violation",
                    "code": "ai_safety_blocked",
                    "rules": sorted({finding["rule"] for finding in output_findings}),
                },
                "request_id": request_id,
                "trace_id": trace_id,
            }
            yield f"event: error\ndata: {json.dumps(payload, ensure_ascii=False, separators=(',', ':'))}\n\n".encode()

        return StreamingResponse(
            blocked_generator(),
            status_code=451,
            headers={"x-request-id": request_id, "x-trace-id": trace_id, "x-guardrail-action": "blocked"},
            media_type="text/event-stream",
        )

    _record_metrics(method, route, model, status_code, latency, input_tokens, output_tokens, cost_usd)
    span.set_attribute("http.response.status_code", status_code)
    span.set_attribute("ai.usage.input_tokens", input_tokens)
    span.set_attribute("ai.usage.output_tokens", output_tokens)
    span.set_attribute("ai.cost.usd", cost_usd)
    if status_code >= 500:
        span.set_status(Status(StatusCode.ERROR))
    _audit_log(
        {
            **audit_base,
            "status_code": status_code,
            "latency_ms": round(latency * 1000, 2),
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cost_usd": round(cost_usd, 8),
            **_usage_audit_fields(usage, input_token_source, output_token_source),
            "stream": True,
            "security_action": "allowed",
            "output_dlp_action": output_dlp_action,
            **({f"output_{key}": value for key, value in _dlp_event_fields(output_dlp_findings).items()} if output_dlp_action != "none" else {}),
        }
    )

    async def generator():
        for chunk in raw_chunks:
            yield chunk

    return StreamingResponse(
        generator(),
        status_code=status_code,
        headers=_response_headers(upstream_response.headers, request_id, trace_id),
        media_type=upstream_response.headers.get("content-type"),
    )


def _decode_raw_chunks(raw_chunks: list[bytes]) -> list[str]:
    if not raw_chunks:
        return []
    return [b"".join(raw_chunks).decode("utf-8", errors="ignore")]


def _stream_output_text(chunks: list[str]) -> str:
    texts: list[str] = []
    for line in "".join(chunks).splitlines():
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if not payload or payload == "[DONE]":
            continue
        try:
            event = json.loads(payload)
        except json.JSONDecodeError:
            continue
        event_type = event.get("type")
        if event_type in {"response.output_text.delta", "content_block_delta"}:
            texts.append(str(event.get("delta") or ""))
        elif event_type in {"response.output_text.done"}:
            texts.append(str(event.get("text") or ""))
        else:
            texts.append(_response_text(event))
    return "".join(texts)


def _estimate_stream_tokens(chunks: list[str]) -> int:
    text = "".join(chunks)
    usage_tokens = 0
    delta_chars = 0
    for line in text.splitlines():
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if payload == "[DONE]":
            continue
        try:
            event = json.loads(payload)
            usage = _usage_from_response(event)
            usage_tokens = max(usage_tokens, usage.get("output_tokens", 0))
            if event.get("type") in {"response.output_text.delta", "content_block_delta"}:
                delta_chars += len(str(event.get("delta") or ""))
        except json.JSONDecodeError:
            continue
    if usage_tokens:
        return usage_tokens
    return max(1, delta_chars // 4) if delta_chars else 0


def _stream_usage(chunks: list[str]) -> dict[str, int]:
    result = {
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "cached_tokens": 0,
        "reasoning_tokens": 0,
    }
    for line in "".join(chunks).splitlines():
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if not payload or payload == "[DONE]":
            continue
        try:
            usage = _usage_from_response(json.loads(payload))
        except json.JSONDecodeError:
            continue
        for key in result:
            result[key] = max(result[key], usage.get(key, 0))
    return result


def _record_metrics(
    method: str,
    route: str,
    model: str,
    status_code: int,
    latency: float,
    input_tokens: int,
    output_tokens: int,
    cost_usd: float,
) -> None:
    REQUESTS.labels(method, route, model, _status_class(status_code)).inc()
    LATENCY.labels(method, route, model).observe(latency)
    if input_tokens:
        TOKENS.labels(model, "input").inc(input_tokens)
    if output_tokens:
        TOKENS.labels(model, "output").inc(output_tokens)
    if cost_usd:
        COST.labels(model).inc(cost_usd)


def _response_headers(headers: httpx.Headers, request_id: str, trace_id: str) -> dict[str, str]:
    blocked = {"content-length", "connection", "content-encoding", "transfer-encoding"}
    copied = {key: value for key, value in headers.items() if key.lower() not in blocked}
    copied["x-request-id"] = request_id
    copied["x-trace-id"] = trace_id
    return copied
