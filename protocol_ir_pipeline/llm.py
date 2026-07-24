from __future__ import annotations

import json
import os
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from time import perf_counter
from typing import Any


class EmptyLLMResponse(RuntimeError):
    def __init__(self, provider: str, model: str, metadata: dict[str, Any] | None = None) -> None:
        self.provider = provider
        self.model = model
        self.metadata = metadata or {}
        super().__init__(f"LLM returned an empty response from provider={provider} model={model}.")


def load_local_env(repo_root: Path) -> None:
    for filename in (".env.local", ".env"):
        path = repo_root / filename
        if not path.exists():
            continue
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


@dataclass
class LLMConfig:
    provider: str = "deepseek"
    model: str | None = None
    base_url: str | None = None
    api_mode: str = "chat"
    temperature: float = 0.2
    max_tokens: int = 38888
    reasoning_effort: str | None = None
    timeout: float = 1800.0


class LLMClient:
    """Provider wrapper kept deliberately narrow for this research path."""

    def __init__(self, config: LLMConfig) -> None:
        self.config = config
        self.provider = _normalize_provider(config.provider)
        self.model = config.model or _default_model(self.provider)
        self.last_empty_response_metadata: dict[str, Any] | None = None
        self.last_call_metadata: dict[str, Any] | None = None
        self._last_provider_response_metadata: dict[str, Any] = {}

    def complete_json(self, system: str, user: str) -> dict[str, Any]:
        text = self.complete(system, user)
        return extract_json_object(text)

    def complete_json_or_text(self, system: str, user: str) -> tuple[dict[str, Any] | None, str]:
        try:
            text = self.complete(system, user)
        except EmptyLLMResponse as exc:
            self.last_empty_response_metadata = exc.metadata
            return None, ""
        self.last_empty_response_metadata = None
        try:
            return extract_json_object(text), text
        except ValueError:
            return None, text

    def complete(self, system: str, user: str) -> str:
        started_at = datetime.now().isoformat(timespec="seconds")
        start = perf_counter()
        self.last_call_metadata = None
        self._last_provider_response_metadata = {}
        text = ""
        success = False
        error: BaseException | None = None
        try:
            if self.provider in {"deepseek", "openai", "llama"}:
                text = self._complete_openai_compatible(system, user)
            elif self.provider == "anthropic":
                text = self._complete_anthropic(system, user)
            else:
                raise ValueError(f"Unsupported LLM provider: {self.config.provider}")
            success = True
            return text
        except BaseException as exc:
            error = exc
            if isinstance(exc, EmptyLLMResponse):
                self._last_provider_response_metadata = dict(exc.metadata or {})
            raise
        finally:
            provider_metadata = dict(self._last_provider_response_metadata or {})
            self.last_call_metadata = {
                "schema": "protocol_ir_pipeline_llm_call_v1",
                "started_at": started_at,
                "duration_sec": round(perf_counter() - start, 3),
                "provider": self.provider,
                "configured_provider": self.config.provider,
                "model": self.model,
                "api_mode": self.config.api_mode,
                "temperature": self.config.temperature,
                "max_tokens": self.config.max_tokens,
                "reasoning_effort": self.config.reasoning_effort,
                "success": success,
                "response_chars": len(text or ""),
                "response_id": provider_metadata.get("response_id"),
                "finish_reason": provider_metadata.get("finish_reason") or provider_metadata.get("stop_reason"),
                "status": provider_metadata.get("status"),
                "usage": _normalize_usage(provider_metadata.get("usage")),
            }
            if error is not None:
                self.last_call_metadata["error_type"] = type(error).__name__
                self.last_call_metadata["error"] = str(error)

    def _complete_openai_compatible(self, system: str, user: str) -> str:
        kwargs: dict[str, Any] = {}
        api_key = None
        if self.provider == "deepseek":
            api_key = os.getenv("DEEPSEEK_API_KEY")
            kwargs["base_url"] = self.config.base_url or os.getenv(
                "DEEPSEEK_BASE_URL",
                "https://api.deepseek.com",
            )
        elif self.provider == "openai":
            api_key = os.getenv("OPENAI_API_KEY")
            if self.config.base_url or os.getenv("OPENAI_BASE_URL"):
                kwargs["base_url"] = self.config.base_url or os.getenv("OPENAI_BASE_URL")
        elif self.provider == "llama":
            api_key = os.getenv("LLAMA_API_KEY") or os.getenv("OPENAI_API_KEY")
            base_url = self.config.base_url or os.getenv("LLAMA_BASE_URL")
            if not base_url:
                raise RuntimeError("Missing LLAMA_BASE_URL for provider llama.")
            kwargs["base_url"] = base_url
        if not api_key:
            raise RuntimeError(f"Missing API key for provider {self.provider}.")
        try:
            from openai import OpenAI
        except ModuleNotFoundError:
            return self._complete_openai_compatible_stdlib(system, user, api_key=api_key, base_url=kwargs.get("base_url"))
        client = OpenAI(api_key=api_key, timeout=self.config.timeout, **kwargs)

        api_mode = self.config.api_mode.lower()
        if self.provider == "openai" and api_mode == "responses":
            input_messages = [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ]
            request: dict[str, Any] = {
                "model": self.model,
                "input": input_messages,
                "max_output_tokens": self.config.max_tokens,
            }
            if self.config.reasoning_effort:
                request["reasoning"] = {"effort": self.config.reasoning_effort}
            response = client.responses.create(**request, timeout=self.config.timeout)
            self._last_provider_response_metadata = {
                "status": getattr(response, "status", None),
                "usage": _model_dump(getattr(response, "usage", None)),
                "response_id": getattr(response, "id", None),
            }
            if response.output_text:
                return response.output_text
            raise EmptyLLMResponse(
                self.provider,
                self.model,
                self._last_provider_response_metadata,
            )

        system_role = "developer" if self.provider == "openai" and _is_openai_reasoning_model(self.model) else "system"
        messages = [
            {"role": system_role, "content": system},
            {"role": "user", "content": user},
        ]
        request = {
            "model": self.model,
            "messages": messages,
        }
        if self.provider == "openai":
            request["max_completion_tokens"] = self.config.max_tokens
            if self.config.reasoning_effort and _is_openai_reasoning_model(self.model):
                request["reasoning_effort"] = self.config.reasoning_effort
            if not _is_openai_reasoning_model(self.model):
                request["temperature"] = self.config.temperature
        else:
            request["temperature"] = self.config.temperature
            request["max_tokens"] = self.config.max_tokens

        response = client.chat.completions.create(**request, timeout=self.config.timeout)
        choice = response.choices[0] if response.choices else None
        self._last_provider_response_metadata = {
            "finish_reason": getattr(choice, "finish_reason", None),
            "usage": _model_dump(getattr(response, "usage", None)),
            "response_id": getattr(response, "id", None),
        }
        content = choice.message.content if choice and choice.message else ""
        if content:
            return content
        raise EmptyLLMResponse(
            self.provider,
            self.model,
            self._last_provider_response_metadata,
        )

    def _complete_openai_compatible_stdlib(self, system: str, user: str, *, api_key: str, base_url: str | None) -> str:
        if self.provider == "openai" and self.config.api_mode.lower() == "responses":
            raise RuntimeError("The OpenAI responses API requires the openai Python package.")
        if not base_url:
            if self.provider == "openai":
                base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
            elif self.provider == "deepseek":
                base_url = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
            else:
                base_url = os.getenv("LLAMA_BASE_URL")
        if not base_url:
            raise RuntimeError(f"Missing base URL for provider {self.provider}.")
        endpoint = base_url.rstrip("/")
        if not endpoint.endswith("/v1"):
            endpoint = f"{endpoint}/v1"
        endpoint = f"{endpoint}/chat/completions"
        system_role = "developer" if self.provider == "openai" and _is_openai_reasoning_model(self.model) else "system"
        request: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": system_role, "content": system},
                {"role": "user", "content": user},
            ],
        }
        if self.provider == "openai":
            request["max_completion_tokens"] = self.config.max_tokens
            if self.config.reasoning_effort and _is_openai_reasoning_model(self.model):
                request["reasoning_effort"] = self.config.reasoning_effort
            if not _is_openai_reasoning_model(self.model):
                request["temperature"] = self.config.temperature
        else:
            request["temperature"] = self.config.temperature
            request["max_tokens"] = self.config.max_tokens
        body = json.dumps(request).encode("utf-8")
        http_request = urllib.request.Request(
            endpoint,
            data=body,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        ssl_context = ssl._create_unverified_context() if os.getenv("LLM_INSECURE_SKIP_VERIFY") == "1" else None
        try:
            with urllib.request.urlopen(http_request, timeout=self.config.timeout, context=ssl_context) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"{self.provider} API request failed with HTTP {exc.code}: {detail}") from exc
        choice = payload.get("choices", [{}])[0] if isinstance(payload.get("choices"), list) and payload.get("choices") else {}
        self._last_provider_response_metadata = {
            "finish_reason": choice.get("finish_reason"),
            "usage": payload.get("usage"),
            "response_id": payload.get("id"),
        }
        message = choice.get("message") if isinstance(choice.get("message"), dict) else {}
        content = message.get("content") or ""
        if content:
            return str(content)
        raise EmptyLLMResponse(
            self.provider,
            self.model,
            self._last_provider_response_metadata,
        )

    def _complete_anthropic(self, system: str, user: str) -> str:
        import anthropic

        api_key = os.getenv("ANTHROPIC_API_KEY") or os.getenv("CLAUDE_API_KEY")
        if not api_key:
            raise RuntimeError("Missing ANTHROPIC_API_KEY.")
        kwargs: dict[str, Any] = {"api_key": api_key}
        base_url = self.config.base_url or os.getenv("ANTHROPIC_BASE_URL")
        if base_url:
            kwargs["base_url"] = base_url
        client = anthropic.Anthropic(timeout=self.config.timeout, **kwargs)
        previous_socket_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(self.config.timeout)
        try:
            response = client.messages.create(
                model=self.model,
                system=system,
                messages=[{"role": "user", "content": user}],
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
            )
        finally:
            socket.setdefaulttimeout(previous_socket_timeout)
        self._last_provider_response_metadata = {
            "stop_reason": getattr(response, "stop_reason", None),
            "usage": _model_dump(getattr(response, "usage", None)),
            "response_id": getattr(response, "id", None),
        }
        parts = []
        for block in response.content:
            if getattr(block, "type", None) == "text":
                parts.append(block.text)
        text = "\n".join(parts)
        if text:
            return text
        raise EmptyLLMResponse(
            self.provider,
            self.model,
            self._last_provider_response_metadata,
        )


def llm_call_record(
    llm: LLMClient,
    *,
    stage: str,
    system: str,
    prompt: str,
    attempt: int | None = None,
    case: str | None = None,
    parsed_json: bool | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    metadata = dict(llm.last_call_metadata or {})
    metadata.setdefault("schema", "protocol_ir_pipeline_llm_call_v1")
    metadata["stage"] = stage
    metadata["system_chars"] = len(system or "")
    metadata["prompt_chars"] = len(prompt or "")
    if attempt is not None:
        metadata["attempt"] = attempt
    if case:
        metadata["case"] = case
    if parsed_json is not None:
        metadata["parsed_json"] = bool(parsed_json)
    if extra:
        metadata.update(extra)
    return metadata


def extract_json_object(text: str) -> dict[str, Any]:
    stripped = (text or "").strip()
    if stripped.startswith("```"):
        stripped = _strip_fence(stripped)
    try:
        value = json.loads(stripped)
    except json.JSONDecodeError as original_error:
        start = stripped.find("{")
        end = stripped.rfind("}")
        if start < 0 or end < start:
            raise ValueError("LLM response did not contain a JSON object.") from original_error
        try:
            value = json.loads(stripped[start : end + 1])
        except json.JSONDecodeError as exc:
            raise ValueError(f"LLM response contained malformed JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object from the LLM.")
    return value


def _strip_fence(text: str) -> str:
    lines = text.strip().splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].startswith("```"):
        lines = lines[:-1]
    return "\n".join(lines).strip()


def _model_dump(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (dict, list, str, int, float, bool)):
        return value
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if hasattr(value, "dict"):
        return value.dict()
    return str(value)


def _normalize_usage(value: Any) -> dict[str, Any]:
    raw = _model_dump(value)
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        return {"raw": raw}
    completion_details = raw.get("completion_tokens_details")
    if not isinstance(completion_details, dict):
        completion_details = {}
    prompt_details = raw.get("prompt_tokens_details") or raw.get("input_tokens_details")
    if not isinstance(prompt_details, dict):
        prompt_details = {}
    input_tokens = _first_int(raw, "prompt_tokens", "input_tokens")
    output_tokens = _first_int(raw, "completion_tokens", "output_tokens")
    cached_input_tokens = _first_int(prompt_details, "cached_tokens")
    if cached_input_tokens == 0:
        cached_input_tokens = _first_int(raw, "cache_read_input_tokens", "cached_input_tokens")
    reasoning_tokens = _first_int(completion_details, "reasoning_tokens")
    total_tokens = _first_int(raw, "total_tokens")
    if total_tokens == 0:
        total_tokens = input_tokens + output_tokens
    return {
        "raw": raw,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
        "cached_input_tokens": cached_input_tokens,
        "reasoning_tokens": reasoning_tokens,
    }


def _first_int(payload: dict[str, Any], *keys: str) -> int:
    for key in keys:
        value = payload.get(key)
        if value is None:
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return 0


def _normalize_provider(provider: str) -> str:
    provider = (provider or "deepseek").strip().lower()
    if provider == "claude":
        return "anthropic"
    if provider in {"llama", "meta-llama"}:
        return "llama"
    return provider


def _is_openai_reasoning_model(model: str) -> bool:
    normalized = (model or "").strip().lower()
    return normalized.startswith(("gpt-5", "o1", "o3", "o4"))


def _default_model(provider: str) -> str:
    if provider == "deepseek":
        return os.getenv("DEEPSEEK_MODEL", "deepseek-v4-pro")
    if provider == "anthropic":
        return os.getenv("ANTHROPIC_MODEL", "claude-3-7-sonnet-20250219")
    if provider == "openai":
        return os.getenv("OPENAI_MODEL", "gpt-4o")
    if provider == "llama":
        return os.getenv("LLAMA_MODEL", "meta-llama/llama-3.3-70b-instruct")
    return "unknown"
