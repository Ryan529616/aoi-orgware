"""Shared agent identity grammar for AOI dispatch and integrity records.

Codex collaboration agents use canonical rooted identities such as
``/root/reviewer``.  These values originate at the hook boundary and are not
ordinary AOI task, claim, or command identifiers, so they deliberately have a
separate bounded grammar.
"""

from __future__ import annotations

import re
from typing import Any


# ``@`` preserves documented operator/claim-owner identities such as an email
# address when those principals are bound into an integrity producer set.
AGENT_ID_RE = re.compile(r"[A-Za-z0-9._:@/-]{1,512}")


class AgentIdentityError(ValueError):
    """A hook, operator, claim-owner, or reviewer identity is out of bounds."""


def validate_agent_id(value: Any, label: str = "agent id") -> str:
    """Return one exact bounded identity or raise a dependency-free error."""

    if not isinstance(value, str) or not AGENT_ID_RE.fullmatch(value):
        raise AgentIdentityError(
            f"{label} must use 1-512 ASCII letters, digits, dot, colon, at, slash, dash, or underscore"
        )
    return value


__all__ = ["AGENT_ID_RE", "AgentIdentityError", "validate_agent_id"]
