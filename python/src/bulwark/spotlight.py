"""Spotlighting: make untrusted content unmistakably data.

Three composable transforms: ``delimit`` wraps content in a random-nonce
boundary a fake closing tag can't forge; ``datamark`` replaces spaces with a
marker; ``base64`` encodes the content as an opaque blob. Based on spotlighting
(Hines et al., Microsoft, 2024).
"""

from __future__ import annotations

import base64
import secrets
from typing import List, Optional, Sequence

from .types import SpotlightResult

DEFAULT_MARKER = "▁"  # ▁ LOWER ONE EIGHTH BLOCK — rare in prose, reads as a space marker
DEFAULT_TAG = "untrusted_content"


def make_nonce(n_bytes: int = 9) -> str:
    return secrets.token_hex(n_bytes)


def delimit(text: str, *, nonce: Optional[str] = None, tag: str = DEFAULT_TAG) -> "tuple[str, str]":
    """Wrap ``text`` in a nonce-tagged boundary. Returns (wrapped, nonce)."""
    nonce = nonce or make_nonce()
    open_tag = f'<{tag} data-nonce="{nonce}">'
    close_tag = f'</{tag} data-nonce="{nonce}">'
    return f"{open_tag}\n{text}\n{close_tag}", nonce


def datamark(text: str, *, marker: str = DEFAULT_MARKER) -> str:
    """Replace spaces with ``marker`` so the whole span reads as data."""
    return text.replace(" ", marker)


def encode_base64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def spotlight(
    text: str,
    *,
    methods: Sequence[str] = ("delimit",),
    nonce: Optional[str] = None,
    marker: str = DEFAULT_MARKER,
    tag: str = DEFAULT_TAG,
) -> SpotlightResult:
    """Apply the requested spotlight transforms in a safe order.

    ``methods`` may contain any of ``"delimit"``, ``"datamark"``, ``"base64"``.
    ``base64`` and ``datamark`` are mutually exclusive (base64 wins); ``delimit``
    is always applied even if omitted, because the boundary nonce is what the
    output validator checks for leakage.
    """
    applied: List[str] = []
    content = text
    used_marker: Optional[str] = None
    base64_encoded = False

    if "base64" in methods:
        content = encode_base64(content)
        base64_encoded = True
        applied.append("base64")
    elif "datamark" in methods:
        content = datamark(content, marker=marker)
        used_marker = marker
        applied.append("datamark")

    content, used_nonce = delimit(content, nonce=nonce, tag=tag)
    applied.append("delimit")

    return SpotlightResult(
        content=content,
        nonce=used_nonce,
        methods=applied,
        marker=used_marker,
        base64_encoded=base64_encoded,
    )
