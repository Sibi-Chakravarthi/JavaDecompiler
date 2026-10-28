"""
Reporting package initialization.
"""

from javadecompiler.security.reporting.json_out import save_json, to_json
from javadecompiler.security.reporting.sarif import save_sarif, to_sarif

__all__ = [
    "to_json",
    "save_json",
    "to_sarif",
    "save_sarif",
]
