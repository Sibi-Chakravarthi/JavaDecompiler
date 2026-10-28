"""
Rules package initialization.
"""

from javadecompiler.security.rules.base import (
    RULE_REGISTRY,
    SecurityRule,
    get_all_rules,
    get_rule,
    register_rule,
)

__all__ = [
    "SecurityRule",
    "register_rule",
    "RULE_REGISTRY",
    "get_all_rules",
    "get_rule",
]
