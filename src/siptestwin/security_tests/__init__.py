"""Independent SIP security / robustness test modules.

Each module checks one property of a target's behaviour. All tests are bounded
and non-destructive: they validate protocol conformance, authentication
challenge handling, and controlled handling of malformed input. There is no
credential brute-forcing, unbounded flooding, or automated third-party
exploitation here by design.
"""

from .malformed import MalformedCase, malformed_catalog
from .protocol import ProtocolFinding, validate_message, validate_response_sequence
from .regression import RegressionResult, compare_to_baseline

__all__ = [
    "MalformedCase",
    "malformed_catalog",
    "ProtocolFinding",
    "validate_message",
    "validate_response_sequence",
    "RegressionResult",
    "compare_to_baseline",
]
