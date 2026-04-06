"""IoC defanging and extraction module.

Defangs Indicators of Compromise (IoCs) in text to prevent accidental activation
of malicious URLs, IPs, and other network indicators.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from aiir2.models import IoC


# ---------------------------------------------------------------------------
# Regex patterns for IoC extraction
# ---------------------------------------------------------------------------

# IPv4 address: four octets, each 0-255
_IPV4_PATTERN = re.compile(
    r"(?<![.\d])"          # not preceded by dot or digit (avoid matching versions)
    r"(\d{1,3})"
    r"\."
    r"(\d{1,3})"
    r"\."
    r"(\d{1,3})"
    r"\."
    r"(\d{1,3})"
    r"(?![.\d])"           # not followed by dot or digit
)

# URLs with http/https/ftp/file protocols
# file:// is included because macOS logs frequently reference local paths this way
# (e.g., quarantine events, Gatekeeper blocks, crash reports)
_URL_PATTERN = re.compile(
    r"(?:https?|ftp|file)://"
    r"[^\s<>\"'`,;)(\[\]]+",
    re.IGNORECASE,
)

# SHA256 (64 hex chars), SHA1 (40 hex chars), MD5 (32 hex chars)
# Must be standalone (word boundaries)
_HASH_PATTERN = re.compile(
    r"\b([0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})\b"
)

# Email addresses
_EMAIL_PATTERN = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
)

# Domain names (used for standalone domain extraction, not inside URLs)
_DOMAIN_PATTERN = re.compile(
    r"(?<![/@])"           # not preceded by slash or @ (already captured as URL/email)
    r"\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*"
    r"\."
    r"(?:com|net|org|io|gov|edu|mil|int|info|biz|co|uk|de|fr|jp|ru|cn|au|ca"
    r"|onion|local|internal|corp|lan))\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Defanging helpers
# ---------------------------------------------------------------------------


def defang_ip(ip: str) -> str:
    """Defang an IP address by replacing dots with [.]

    Args:
        ip: IPv4 address string.

    Returns:
        Defanged IP string like ``192[.]168[.]1[.]1``.
    """
    return ip.replace(".", "[.]")


def defang_url(url: str) -> str:
    """Defang a URL by replacing the scheme and domain dots.

    Args:
        url: URL string starting with http://, https://, ftp://, or file://.
             file:// URLs (common in macOS logs for quarantine/Gatekeeper events)
             are defanged by replacing the scheme only; path dots are left intact
             as they represent filesystem paths, not hostnames.

    Returns:
        Defanged URL string.
    """
    # Replace scheme
    defanged = re.sub(r"^http://", "hxxp://", url, flags=re.IGNORECASE)
    defanged = re.sub(r"^https://", "hxxps://", defanged, flags=re.IGNORECASE)
    defanged = re.sub(r"^ftp://", "fxxp://", defanged, flags=re.IGNORECASE)
    # file:// → fxxle:// — defang scheme only; paths are local and not network-reachable
    defanged = re.sub(r"^file://", "fxxle://", defanged, flags=re.IGNORECASE)
    if re.match(r"^fxxle://", defanged, re.IGNORECASE):
        return defanged  # No hostname to defang in file:// URLs

    # Extract scheme and rest
    scheme_match = re.match(r"(hxxps?://|hxxp://|fxxp://)(.*)", defanged)
    if scheme_match:
        scheme = scheme_match.group(1)
        rest = scheme_match.group(2)

        # Split at first slash to isolate hostname
        slash_idx = rest.find("/")
        if slash_idx != -1:
            hostname = rest[:slash_idx]
            path = rest[slash_idx:]
        else:
            hostname = rest
            path = ""

        # Defang dots in hostname (including port if present)
        colon_idx = hostname.find(":")
        if colon_idx != -1:
            host_only = hostname[:colon_idx]
            port = hostname[colon_idx:]
        else:
            host_only = hostname
            port = ""

        defanged_host = host_only.replace(".", "[.]")
        defanged = f"{scheme}{defanged_host}{port}{path}"

    return defanged


def defang_domain(domain: str) -> str:
    """Defang a standalone domain by replacing dots with [.]

    Args:
        domain: Domain name string.

    Returns:
        Defanged domain string like ``example[.]com``.
    """
    return domain.replace(".", "[.]")


def defang_email(email: str) -> str:
    """Defang an email address by replacing @ with [@] and dots in domain.

    Args:
        email: Email address string.

    Returns:
        Defanged email string like ``user[@]example[.]com``.
    """
    parts = email.split("@", 1)
    if len(parts) == 2:
        return f"{parts[0]}[@]{parts[1].replace('.', '[.]')}"
    return email


def _is_valid_ipv4(m: re.Match) -> bool:
    """Check if a regex match represents a valid IPv4 address."""
    try:
        octets = [int(m.group(i)) for i in range(1, 5)]
        return all(0 <= o <= 255 for o in octets)
    except (ValueError, IndexError):
        return False


# ---------------------------------------------------------------------------
# Main defang function
# ---------------------------------------------------------------------------


def defang_text(text: str) -> tuple[str, list[IoC]]:
    """Defang IoCs in text.

    Processes the text in order: URLs first (to avoid double-processing),
    then IPs, then emails, then standalone domains, then hashes.

    Args:
        text: Raw text that may contain IoCs.

    Returns:
        A tuple of (defanged_text, list_of_iocs).
    """
    iocs: list[IoC] = []
    result = text

    # Track already-processed spans to avoid double-defanging
    # We rebuild the string with replacements applied left-to-right.
    # Use a list of (start, end, replacement) tuples.

    replacements: list[tuple[int, int, str, IoC]] = []

    # 1. URLs (http/https/ftp) — highest priority, match before domain/IP
    for m in _URL_PATTERN.finditer(text):
        original = m.group(0)
        defanged = defang_url(original)
        ioc_type = "url"
        ioc = IoC(original=original, defanged=defanged, type=ioc_type)
        replacements.append((m.start(), m.end(), defanged, ioc))

    # 2. Emails — before domain to avoid partial overlap
    for m in _EMAIL_PATTERN.finditer(text):
        # Skip if overlaps with an existing replacement
        if _overlaps(m.start(), m.end(), replacements):
            continue
        original = m.group(0)
        defanged = defang_email(original)
        ioc = IoC(original=original, defanged=defanged, type="email")
        replacements.append((m.start(), m.end(), defanged, ioc))

    # 3. IPv4 addresses
    for m in _IPV4_PATTERN.finditer(text):
        if not _is_valid_ipv4(m):
            continue
        if _overlaps(m.start(), m.end(), replacements):
            continue
        original = m.group(0)
        defanged = defang_ip(original)
        ioc = IoC(original=original, defanged=defanged, type="ip")
        replacements.append((m.start(), m.end(), defanged, ioc))

    # 4. Standalone domains (after URLs and emails)
    for m in _DOMAIN_PATTERN.finditer(text):
        if _overlaps(m.start(), m.end(), replacements):
            continue
        original = m.group(0)
        defanged = defang_domain(original)
        ioc = IoC(original=original, defanged=defanged, type="domain")
        replacements.append((m.start(), m.end(), defanged, ioc))

    # 5. Hashes (MD5/SHA1/SHA256)
    for m in _HASH_PATTERN.finditer(text):
        if _overlaps(m.start(), m.end(), replacements):
            continue
        original = m.group(0)
        # Hashes are not defanged (not executable), but we record them
        ioc = IoC(original=original, defanged=original, type="hash")
        # Don't add to replacements since we keep the text the same
        iocs.append(ioc)

    # Apply replacements from right to left to preserve offsets
    replacements_no_hash = [(s, e, r, ioc) for s, e, r, ioc in replacements]
    replacements_no_hash.sort(key=lambda x: x[0], reverse=True)

    result = text
    for start, end, replacement, ioc in replacements_no_hash:
        result = result[:start] + replacement + result[end:]
        iocs.append(ioc)

    # Sort IoCs by position in original text (hashes were appended separately)
    # Re-sort by original value for determinism
    iocs_positioned = []
    iocs_hashes = []
    for ioc in iocs:
        if ioc.type == "hash":
            iocs_hashes.append(ioc)
        else:
            iocs_positioned.append(ioc)

    # Sort positioned IoCs by their original position
    def ioc_position(ioc: IoC) -> int:
        idx = text.find(ioc.original)
        return idx if idx != -1 else len(text)

    iocs_positioned.sort(key=ioc_position)
    final_iocs = iocs_positioned + iocs_hashes

    return result, final_iocs


def defang_dict(obj: object) -> object:
    """Recursively defang all string values in a dict or list.

    Applies :func:`defang_text` to every string leaf so that IoCs re-introduced
    by the LLM in generated narrative fields are neutralised before the data is
    stored or rendered.  Non-string values (numbers, booleans, ``None``) are
    passed through unchanged.

    Args:
        obj: A dict, list, or scalar value returned from a Pydantic ``model_dump()``.

    Returns:
        The same structure with all string values defanged.
    """
    if isinstance(obj, dict):
        return {k: defang_dict(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [defang_dict(item) for item in obj]
    if isinstance(obj, str):
        return defang_text(obj)[0]
    return obj


def _overlaps(
    start: int, end: int, replacements: list[tuple[int, int, str, IoC]]
) -> bool:
    """Check if a span overlaps with any existing replacement span."""
    for s, e, _, _ in replacements:
        if start < e and end > s:
            return True
    return False
