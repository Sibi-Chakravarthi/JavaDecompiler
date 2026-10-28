"""
client.py — LLM clients for NeuroDecomp Phase 4.

Includes Abstract LlmClient, OllamaClient (default model: qwen2.5-coder:14b),
and FakeLlmClient for deterministic CI/unit testing.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional


class LlmClient(ABC):
    """Abstract base class for LLM auditors."""

    model_name: str = ""
    model_digest: Optional[str] = None

    @abstractmethod
    def is_available(self) -> bool:
        """Checks if the LLM backend is reachable and ready."""
        pass

    @abstractmethod
    def generate(
        self,
        prompt: str,
        format_json: bool = True,
        temperature: float = 0.2,
        timeout: Optional[int] = None,
    ) -> str:
        """Generates text completion from prompt."""
        pass


class FakeLlmClient(LlmClient):
    """Mock LLM client for deterministic testing and offline evaluations."""

    def __init__(
        self,
        model_name: str = "fake-auditor-model",
        canned_responses: Optional[List[str]] = None,
        response_handler: Optional[Callable[[str], str]] = None,
        available: bool = True,
    ) -> None:
        self.model_name = model_name
        self.model_digest = "sha256:fake_digest_0000000000000000"
        self._canned_responses: List[str] = list(canned_responses or [])
        self._response_handler = response_handler
        self._available = available
        self.call_history: List[Dict[str, Any]] = []
        self.total_latency_ms: float = 0.0

    def is_available(self) -> bool:
        return self._available

    def set_available(self, available: bool) -> None:
        self._available = available

    def enqueue_response(self, response: str) -> None:
        self._canned_responses.append(response)

    def generate(
        self,
        prompt: str,
        format_json: bool = True,
        temperature: float = 0.2,
        timeout: Optional[int] = None,
    ) -> str:
        t0 = time.time()
        self.call_history.append({
            "prompt": prompt,
            "format_json": format_json,
            "temperature": temperature,
        })
        if not self._available:
            raise ConnectionError("FakeLlmClient is marked unavailable")

        if self._response_handler:
            out = self._response_handler(prompt)
        elif self._canned_responses:
            out = self._canned_responses.pop(0)
        else:
            # Default empty valid response
            if format_json:
                out = json.dumps({"intentSummary": "Benign logic", "intentClassification": "benign", "findings": []})
            else:
                out = "confirmed"

        latency = (time.time() - t0) * 1000.0
        self.total_latency_ms += latency
        return out


class OllamaClient(LlmClient):
    """Client for local Ollama daemon (defaults to qwen2.5-coder:14b)."""

    def __init__(
        self,
        model_name: str = "qwen2.5-coder:14b",
        host: str = "http://localhost:11434",
        timeout: int = 90,
    ) -> None:
        self.model_name = model_name
        self.host = host.rstrip("/")
        self.timeout = timeout
        self.model_digest: Optional[str] = None
        self.total_latency_ms: float = 0.0
        self.call_count: int = 0
        self._cached_available: Optional[bool] = None

    def is_available(self) -> bool:
        try:
            req = urllib.request.Request(f"{self.host}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status == 200:
                    body = json.loads(resp.read().decode("utf-8"))
                    models = body.get("models", [])
                    for m in models:
                        name = m.get("name", "")
                        if name == self.model_name or name.startswith(f"{self.model_name}:"):
                            self.model_digest = m.get("digest")
                            self._cached_available = True
                            return True
                    # Model not pulled yet, but daemon is reachable
                    self._cached_available = False
                    return False
        except Exception:
            self._cached_available = False
            return False
        return False

    def get_model_digest(self) -> Optional[str]:
        if not self.model_digest:
            self.is_available()
        return self.model_digest

    def generate(
        self,
        prompt: str,
        format_json: bool = True,
        temperature: float = 0.2,
        timeout: Optional[int] = None,
    ) -> str:
        t0 = time.time()
        effective_timeout = timeout or self.timeout
        payload: Dict[str, Any] = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": temperature},
        }
        if format_json:
            payload["format"] = "json"

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.host}/api/generate",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=effective_timeout) as response:
                resp_bytes = response.read()
                resp_json = json.loads(resp_bytes.decode("utf-8"))
                reply_text = resp_json.get("response", "")
                self.call_count += 1
                latency = (time.time() - t0) * 1000.0
                self.total_latency_ms += latency
                return reply_text
        except Exception as e:
            raise RuntimeError(f"Ollama call failed ({self.host}, model: {self.model_name}): {e}") from e
