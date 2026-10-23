import json
import pytest
from sentinel.scope import Scope, normalize_url

def scope(tmp_path, **kw):
    p=tmp_path/"scope.json"; p.write_text(json.dumps({"origins":["http://127.0.0.1:8000"],"allow_private":True,**kw})); return Scope.load(str(p))

def test_normalize_and_origin_match(tmp_path):
    assert normalize_url("HTTP://127.0.0.1:8000") == "http://127.0.0.1:8000/"
    assert scope(tmp_path).permits("http://127.0.0.1:8000/health")
    assert not scope(tmp_path).permits("http://127.0.0.1:8001/")

def test_malformed_scope_and_bounds(tmp_path):
    p=tmp_path/"s"; p.write_text('{"origins": []}')
    with pytest.raises(ValueError): Scope.load(str(p))
    p.write_text('{"origins": ["http://127.0.0.1"], "max_requests": 1000}')
    with pytest.raises(ValueError): Scope.load(str(p))
