"""Config: the D7 schema, its validation, and the atomic store.

The daemon is the only writer (D12). Everything else is a client.
"""

from smbpal.config.schema import (
    SCHEMA_VERSION,
    Problem,
    empty_config,
    validate,
    validate_or_raise,
)
from smbpal.config.store import ConfigStore

__all__ = [
    "SCHEMA_VERSION",
    "ConfigStore",
    "Problem",
    "empty_config",
    "validate",
    "validate_or_raise",
]
