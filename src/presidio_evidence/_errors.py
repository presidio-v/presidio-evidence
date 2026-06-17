"""Error type for the evidence substrate."""

from __future__ import annotations


class EvidenceError(ValueError):
    """An evidence document, ref, trust store, or signing request is malformed.

    A :class:`ValueError` subclass so existing ``except ValueError`` paths in
    consumers keep working as they migrate onto the library.
    """
