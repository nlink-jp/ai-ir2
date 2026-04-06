"""Tests for aiir2.parser.defang module."""

import pytest

from aiir2.parser.defang import defang_email, defang_ip, defang_text, defang_url


# ---------------------------------------------------------------------------
# defang_ip
# ---------------------------------------------------------------------------


def test_defang_ip_simple():
    """Test basic IP address defanging."""
    assert defang_ip("192.168.1.1") == "192[.]168[.]1[.]1"


def test_defang_ip_localhost():
    """Test localhost IP defanging."""
    assert defang_ip("127.0.0.1") == "127[.]0[.]0[.]1"


def test_defang_ip_public():
    """Test public IP address defanging."""
    assert defang_ip("8.8.8.8") == "8[.]8[.]8[.]8"


# ---------------------------------------------------------------------------
# defang_url
# ---------------------------------------------------------------------------


def test_defang_url_http():
    """Test HTTP URL defanging."""
    assert defang_url("http://evil.com/path") == "hxxp://evil[.]com/path"


def test_defang_url_https():
    """Test HTTPS URL defanging."""
    assert defang_url("https://evil.com") == "hxxps://evil[.]com"


def test_defang_url_ftp():
    """Test FTP URL defanging."""
    assert defang_url("ftp://files.evil.com/payload") == "fxxp://files[.]evil[.]com/payload"


def test_defang_url_with_path_and_query():
    """Test URL with path and query string defanging."""
    result = defang_url("http://example.com/path?q=1&r=2")
    assert result.startswith("hxxp://")
    assert "example[.]com" in result
    assert "/path?q=1&r=2" in result


def test_defang_url_with_port():
    """Test URL with explicit port defanging."""
    result = defang_url("http://example.com:8080/path")
    assert "hxxp://" in result
    assert "example[.]com" in result
    assert ":8080" in result


# ---------------------------------------------------------------------------
# defang_text
# ---------------------------------------------------------------------------


def test_defang_text_ip():
    """Test that IP addresses in text are defanged."""
    text = "Server at 192.168.1.100 is down"
    defanged, iocs = defang_text(text)
    assert "192[.]168[.]1[.]100" in defanged
    assert "192.168.1.100" not in defanged
    assert any(ioc.type == "ip" for ioc in iocs)


def test_defang_text_url():
    """Test that URLs in text are defanged."""
    text = "Check http://internal.corp/logs for details"
    defanged, iocs = defang_text(text)
    assert "hxxp://" in defanged
    assert "http://" not in defanged
    assert any(ioc.type == "url" for ioc in iocs)


def test_defang_text_multiple_iocs():
    """Test that multiple IoCs in one text are all defanged."""
    text = "Server at 192.168.1.100 and http://internal.corp/logs"
    defanged, iocs = defang_text(text)
    assert "192[.]168[.]1[.]100" in defanged
    assert "hxxp://" in defanged
    assert len(iocs) >= 2


def test_defang_text_returns_ioc_list():
    """Test that defang_text returns IoC objects with correct fields."""
    text = "Contact admin@evil.com about 10.0.0.1"
    defanged, iocs = defang_text(text)
    ioc_types = {ioc.type for ioc in iocs}
    assert "email" in ioc_types
    assert "ip" in ioc_types
    for ioc in iocs:
        assert ioc.original
        assert ioc.defanged
        assert ioc.type


def test_detect_sha256():
    """Test SHA256 hash extraction."""
    hash_val = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
    _, iocs = defang_text(f"hash: {hash_val}")
    hash_iocs = [i for i in iocs if i.type == "hash"]
    assert len(hash_iocs) == 1
    assert hash_iocs[0].original == hash_val


def test_detect_md5():
    """Test MD5 hash extraction."""
    hash_val = "d41d8cd98f00b204e9800998ecf8427e"
    _, iocs = defang_text(f"md5: {hash_val}")
    hash_iocs = [i for i in iocs if i.type == "hash"]
    assert len(hash_iocs) == 1
    assert hash_iocs[0].original == hash_val


def test_detect_sha1():
    """Test SHA1 hash extraction."""
    hash_val = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    _, iocs = defang_text(f"sha1: {hash_val}")
    hash_iocs = [i for i in iocs if i.type == "hash"]
    assert len(hash_iocs) == 1


def test_defang_email():
    """Test email address defanging."""
    text = "contact: attacker@evil.com"
    defanged, iocs = defang_text(text)
    assert "[@]" in defanged
    assert "@" not in defanged.replace("[@]", "")
    assert any(ioc.type == "email" for ioc in iocs)


def test_defang_email_helper():
    """Test defang_email helper function directly."""
    result = defang_email("user@example.com")
    assert "[@]" in result
    assert result == "user[@]example[.]com"


def test_defang_text_clean():
    """Test that text without IoCs passes through unchanged."""
    text = "The server returned HTTP 500 error at 14:32"
    defanged, iocs = defang_text(text)
    # No IoCs should be extracted from normal text
    assert defanged == text
    assert len(iocs) == 0


def test_defang_text_version_not_ip():
    """Test that version strings like 1.2.3 are not defanged as IPs.

    The regex requires 4 octets so 3-part version numbers should not match.
    """
    text = "Running nginx version 1.24.0"
    defanged, iocs = defang_text(text)
    ip_iocs = [i for i in iocs if i.type == "ip"]
    # 1.24.0 has only 3 parts, should not match
    assert "1[.]24[.]0" not in defanged


def test_defang_preserves_surrounding_text():
    """Test that text surrounding IoCs is preserved."""
    text = "Alert: IP 10.0.0.1 attempted login"
    defanged, iocs = defang_text(text)
    assert defanged.startswith("Alert: IP ")
    assert defanged.endswith(" attempted login")


# ---------------------------------------------------------------------------
# macOS-specific defanging (file:// URLs)
# ---------------------------------------------------------------------------


def test_defang_file_url_scheme_only():
    """file:// URLs should have scheme defanged; path dots left intact."""
    defanged = defang_url("file:///Applications/Evil.app/Contents/MacOS/evil")
    assert defanged.startswith("fxxle://")
    # Path dots (file extension) should NOT be replaced with [.]
    assert "Evil.app" in defanged or "Evil[.]app" not in defanged


def test_defang_text_contains_file_url():
    """defang_text should detect and defang file:// URLs from macOS logs."""
    text = (
        "Gatekeeper blocked: file:///Users/alice/Downloads/malware.pkg "
        "reason=not-notarized"
    )
    defanged, iocs = defang_text(text)
    assert "fxxle://" in defanged
    url_iocs = [i for i in iocs if i.type == "url"]
    assert any("file://" in ioc.original for ioc in url_iocs)


def test_defang_text_macos_log_line():
    """Realistic macOS ULS log line with IP and file:// path."""
    text = (
        "[kernel] Sandbox: deny(1) network-outbound 10.20.30.40 "
        "file:///System/Library/Extensions/Foo.kext"
    )
    defanged, iocs = defang_text(text)
    assert "10[.]20[.]30[.]40" in defanged
    assert "fxxle://" in defanged


# ---------------------------------------------------------------------------
# defang_dict
# ---------------------------------------------------------------------------

from aiir2.parser.defang import defang_dict


def test_defang_dict_defangs_string_values():
    result = defang_dict({"key": "found at http://evil.com/path"})
    assert result["key"] == "found at hxxp://evil[.]com/path"


def test_defang_dict_leaves_non_strings_unchanged():
    result = defang_dict({"count": 42, "flag": True, "empty": None})
    assert result == {"count": 42, "flag": True, "empty": None}


def test_defang_dict_recurses_into_nested_dict():
    result = defang_dict({"outer": {"inner": "connect to 192.168.1.1"}})
    assert result["outer"]["inner"] == "connect to 192[.]168[.]1[.]1"


def test_defang_dict_recurses_into_list():
    result = defang_dict({"items": ["clean text", "http://bad.example.com"]})
    assert result["items"][0] == "clean text"
    assert "hxxp://" in result["items"][1]


def test_defang_dict_handles_plain_list():
    result = defang_dict(["http://evil.com", "safe"])
    assert "hxxp://" in result[0]
    assert result[1] == "safe"


def test_defang_dict_passes_through_scalar():
    assert defang_dict(99) == 99
    assert defang_dict(None) is None
