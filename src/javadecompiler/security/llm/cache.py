"""
cache.py — On-disk response caching for LLM auditor harness.

Prevents expensive and redundant LLM queries across identical classes/methods.
Cache keys are computed as:
  sha256(bytecode_bytes + lifted_code + prompt_version + model_name + sorted_params)
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional


DEFAULT_CACHE_DIR = Path(".javadecompiler_cache")


class LlmDiskCache:
    """Persistent on-disk cache for LLM queries."""

    def __init__(self, cache_dir: Optional[Path] = None, enabled: bool = True) -> None:
        self.cache_dir = cache_dir or DEFAULT_CACHE_DIR
        self.enabled = enabled
        if self.enabled:
            try:
                self.cache_dir.mkdir(parents=True, exist_ok=True)
            except Exception:
                pass

    @staticmethod
    def compute_key(
        bytecode_bytes: bytes,
        lifted_code: str,
        prompt_version: str,
        model_name: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Computes a deterministic SHA-256 cache key."""
        hasher = hashlib.sha256()
        hasher.update(bytecode_bytes)
        hasher.update(lifted_code.encode("utf-8", errors="replace"))
        hasher.update(prompt_version.encode("utf-8"))
        hasher.update(model_name.encode("utf-8"))
        if params:
            sorted_params = json.dumps(params, sort_keys=True)
            hasher.update(sorted_params.encode("utf-8"))
        return hasher.hexdigest()

    def get(self, key: str) -> Optional[str]:
        """Retrieves cached response string, or None if missing or disabled."""
        if not self.enabled:
            return None
        file_path = self.cache_dir / f"{key}.json"
        if not file_path.exists():
            return None
        try:
            return file_path.read_text(encoding="utf-8")
        except Exception:
            return None

    def put(self, key: str, value: str) -> None:
        """Saves response string to cache."""
        if not self.enabled:
            return
        file_path = self.cache_dir / f"{key}.json"
        try:
            file_path.write_text(value, encoding="utf-8")
        except Exception:
            pass

    def has(self, key: str) -> bool:
        """Returns True if the key exists in the cache."""
        if not self.enabled:
            return False
        return (self.cache_dir / f"{key}.json").exists()

    def clear(self) -> int:
        """Removes all cached entries and returns the count removed."""
        count = 0
        if not self.cache_dir.exists():
            return 0
        try:
            for item in self.cache_dir.glob("*.json"):
                try:
                    item.unlink()
                    count += 1
                except Exception:
                    pass
        except Exception:
            pass
        return count
