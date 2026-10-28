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

# Milestone 3 static rule families
import javadecompiler.security.rules.execution
import javadecompiler.security.rules.network
import javadecompiler.security.rules.dynamic
import javadecompiler.security.rules.deserialization
import javadecompiler.security.rules.crypto

__all__ = [
    "SecurityRule",
    "register_rule",
    "RULE_REGISTRY",
    "get_all_rules",
    "get_rule",
]
