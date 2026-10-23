from sentinel.redaction import redact, safe_headers, safe_url

def test_redacts_credentials_and_cookie_values():
    assert "secret" not in redact("Authorization: Bearer secret")
    h=safe_headers({"Set-Cookie":"sid=secret; HttpOnly; SameSite=Lax"})
    assert "secret" not in str(h) and "httponly" in h["set-cookie"].lower()


def test_safe_url_removes_query_and_fragment():
    assert safe_url("https://example.test/path?token=secret#fragment") == "https://example.test/path"
