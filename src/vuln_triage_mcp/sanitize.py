"""Sanitization for untrusted external text (advisory summaries, details)."""

import unicodedata

TRUNCATION_MARKER = " …[truncated]"

# Cc: control, Cf: format (zero-width, bidi overrides), Cs: surrogates, Co: private use.
_STRIP_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co"})


def clean_untrusted(text: str | None, max_len: int = 1500) -> str:
    """Strip control/format characters, collapse whitespace, and cap length.

    The result is at most max_len characters, including the truncation marker.
    """
    if max_len <= 0:
        raise ValueError("max_len must be positive")
    if not text:
        return ""

    chars = []
    for ch in text:
        if ch.isspace():
            chars.append(" ")
        elif unicodedata.category(ch) not in _STRIP_CATEGORIES:
            chars.append(ch)
    cleaned = " ".join("".join(chars).split())

    if len(cleaned) <= max_len:
        return cleaned
    if max_len <= len(TRUNCATION_MARKER):
        return cleaned[:max_len]
    return cleaned[: max_len - len(TRUNCATION_MARKER)].rstrip() + TRUNCATION_MARKER
