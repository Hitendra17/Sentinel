from types import SimpleNamespace
from sentinel.checks import evaluate

def test_checks_record_absent_header_and_cookie_without_value():
    r=SimpleNamespace(error=None,status=200,url="http://127.0.0.1/",headers={"set-cookie":"[COOKIE VALUE REDACTED]; HttpOnly; SameSite=Lax"})
    checks,evidence=evaluate(r)
    assert any(c.check_id=="header.content-security-policy" and c.status=="potential" for c in checks)
    assert "secret" not in str(evidence)

def test_expected_https_context():
    r=SimpleNamespace(error=None,status=200,url="http://example.com/",headers={})
    assert any(c.check_id=="transport.https" for c in evaluate(r,True)[0])
