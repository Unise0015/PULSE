import pytest
from pulse.ecosystems.smart_detection import RegistryValidationResult, DetectionStatus
import asyncio
from unittest.mock import patch, MagicMock
from pathlib import Path

from pulse.ecosystems import EcosystemRegistry
from pulse.ecosystems.python_provider import PythonProvider
from pulse.ecosystems.node_provider import NodeProvider
from pulse.ecosystems.rust_provider import RustProvider
from pulse.ecosystems.go_provider import GoProvider
from pulse.ecosystems.ruby_provider import RubyProvider
from pulse.ecosystems.composer_provider import ComposerProvider
from pulse.ecosystems.nuget_provider import NuGetProvider
from pulse.ecosystems.maven_provider import MavenProvider
from pulse.ecosystems.smart_detection import SmartEcosystemDetector

@pytest.fixture
def registry():
    reg = EcosystemRegistry()
    reg.reset()
    reg.register(PythonProvider())
    reg.register(NodeProvider())
    reg.register(RustProvider())
    reg.register(GoProvider())
    reg.register(RubyProvider())
    reg.register(ComposerProvider())
    reg.register(NuGetProvider())
    reg.register(MavenProvider())
    yield reg
    reg.reset()

@pytest.fixture(autouse=True)
def clean_db():
    from pulse.history.db import get_db_path, init_db
    import sqlite3
    init_db()
    db_path = get_db_path()
    with sqlite3.connect(db_path) as conn:
        conn.execute("DELETE FROM ecosystem_resolution_cache")
        conn.execute("DELETE FROM ecosystem_detection_cache")
        conn.commit()

def mock_httpx_get(url):
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    
    # Mock PyPI flask
    if "pypi.org/pypi/flask" in url:
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"releases": {"2.0.0": [{}]}}
    elif "pypi.org/pypi/django" in url:
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"releases": {}}
    elif "pypi.org/pypi/requests" in url:
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"releases": {}}
        
    # Mock npm react, express
    elif "registry.npmjs.org/react" in url:
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"versions": {"18.0.0": {}}}
    elif "registry.npmjs.org/express" in url:
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"versions": {}}
        
    # Mock crates.io serde
    elif "crates.io/api/v1/crates/serde" in url:
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"versions": [{"num": "1.0.0"}]}
        
    # Mock rubygems rails
    elif "rubygems.org/api/v1/gems/rails.json" in url:
        mock_resp.status_code = 200
        
    # Mock packagist laravel/framework
    elif "packagist.org/packages/laravel/framework.json" in url:
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"package": {"versions": {"v8.0.0": {}}}}
        
    # Mock go github.com/gin-gonic/gin
    elif "proxy.golang.org/github.com/gin-gonic/gin" in url:
        mock_resp.status_code = 200
        mock_resp.text = "v1.7.0\nv1.8.0\n"
        
    # Mock ambiguous redis
    elif "pypi.org/pypi/redis" in url:
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"releases": {}}
    elif "registry.npmjs.org/redis" in url:
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"versions": {}}
    elif "rubygems.org/api/v1/gems/redis.json" in url:
        mock_resp.status_code = 200
        
    return mock_resp

async def async_mock_get(*args, **kwargs):
    return mock_httpx_get(args[0])

@patch('httpx.AsyncClient.get', side_effect=async_mock_get)
def test_smart_detection_flask(mock_get, registry):
    detector = SmartEcosystemDetector(registry)
    candidates, v_found = detector.detect("flask", Path("/tmp"), version="2.0.0")
    
    assert len(candidates) == 1
    assert candidates[0].ecosystem == "Python"
    assert v_found == DetectionStatus.SUCCESS

@patch('httpx.AsyncClient.get', side_effect=async_mock_get)
def test_smart_detection_flask_bad_version(mock_get, registry):
    detector = SmartEcosystemDetector(registry)
    candidates, v_found = detector.detect("flask", Path("/tmp"), version="99.99.99")
    
    assert len(candidates) == 1
    assert candidates[0].ecosystem == "Python"
    assert v_found == DetectionStatus.VERSION_NOT_FOUND

@patch('httpx.AsyncClient.get', side_effect=async_mock_get)
def test_smart_detection_react(mock_get, registry):
    detector = SmartEcosystemDetector(registry)
    candidates, v_found = detector.detect("react", Path("/tmp"), version="18.0.0")
    
    assert len(candidates) == 1
    assert candidates[0].ecosystem == "Node.js"
    assert v_found == DetectionStatus.SUCCESS

@patch('httpx.AsyncClient.get', side_effect=async_mock_get)
def test_smart_detection_ambiguous(mock_get, registry):
    detector = SmartEcosystemDetector(registry)
    candidates, v_found = detector.detect("redis", Path("/tmp"))
    
    assert len(candidates) == 3
    ecosystems = [c.ecosystem for c in candidates]
    assert "Python" in ecosystems
    assert "Node.js" in ecosystems
    assert "Ruby" in ecosystems

def test_smart_detection_offline(registry):
    detector = SmartEcosystemDetector(registry)
    # Without mocking httpx, because offline mode shouldn't call it
    candidates, v_found = detector.detect("flask", Path("/tmp"), offline=True)
    
    assert len(candidates) == 0

@patch('httpx.AsyncClient.get', side_effect=async_mock_get)
def test_smart_detection_go_heuristic(mock_get, registry):
    detector = SmartEcosystemDetector(registry)
    candidates, v_found = detector.detect("github.com/gin-gonic/gin", Path("/tmp"))
    
    assert len(candidates) == 1
    assert candidates[0].ecosystem == "Go"
    assert candidates[0].confidence >= 100

@patch('httpx.AsyncClient.get', side_effect=async_mock_get)
def test_smart_detection_cache_behavior(mock_get, registry):
    detector = SmartEcosystemDetector(registry)
    
    # 1. Run detection first time (hits network and caches results)
    candidates, v_found = detector.detect("react", Path("/tmp"), version="18.0.0")
    assert len(candidates) == 1
    assert candidates[0].ecosystem == "Node.js"
    
    # 2. Run detection second time with same package but no version. Should hit cache!
    candidates2, v_found2 = detector.detect("react", Path("/tmp"))
    assert len(candidates2) == 1
    assert candidates2[0].ecosystem == "Node.js"
    
    # 3. Run detection third time with version. Should run targeted check only on Node.js registry!
    candidates3, v_found3 = detector.detect("react", Path("/tmp"), version="18.0.0")
    assert len(candidates3) == 1
    assert candidates3[0].ecosystem == "Node.js"


def test_smart_detection_scoring_math(registry):
    # Directly test scoring math with mock setup
    detector = SmartEcosystemDetector(registry)
    
    def mock_lookups(*args, **kwargs):
        if args and asyncio.iscoroutine(args[0]):
            args[0].close()
        return [
            RegistryValidationResult(True, True, None, False, 200),   # PyPI
            RegistryValidationResult(True, False, None, False, 200),  # npm
            RegistryValidationResult(False, False, None, False, 404), # crates
            RegistryValidationResult(False, False, None, False, 404), # rubygems
            RegistryValidationResult(False, False, None, False, 404), # packagist
            RegistryValidationResult(False, False, None, False, 404), # nuget
            RegistryValidationResult(False, False, None, False, 404), # maven
            RegistryValidationResult(False, False, None, False, 404), # go
        ]
        
    with patch('asyncio.run', side_effect=mock_lookups):
        candidates, v_found = detector.detect("somepackage", Path("/tmp"), version="1.0.0")
        assert len(candidates) == 1
        assert candidates[0].ecosystem == "Python"
        assert candidates[0].score == 110
        assert v_found == DetectionStatus.SUCCESS


def test_ecosystem_presence_boost(tmp_path, registry):
    detector = SmartEcosystemDetector(registry)
    
    # Create a package.json in tmp_path to trigger Node.js lockfile presence boost
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    
    def mock_lookups(*args, **kwargs):
        if args and asyncio.iscoroutine(args[0]):
            args[0].close()
        return [
            RegistryValidationResult(True, False, None, False, 200),  # PyPI exists (score 10)
            RegistryValidationResult(True, False, None, False, 200),  # npm exists (score 10 + 15 boost = 25)
            RegistryValidationResult(False, False, None, False, 404), # crates
            RegistryValidationResult(False, False, None, False, 404), # rubygems
            RegistryValidationResult(False, False, None, False, 404), # packagist
            RegistryValidationResult(False, False, None, False, 404), # nuget
            RegistryValidationResult(False, False, None, False, 404), # maven
            RegistryValidationResult(False, False, None, False, 404), # go
        ]
        
    with patch('asyncio.run', side_effect=mock_lookups):
        # We query somepackage without a version so that version_exists is False
        candidates, v_found = detector.detect("somepackage", tmp_path)
        # Node.js score should be 25, Python score should be 10.
        # Since Node.js score - Python score = 15 < 50, it is technically ambiguous if len > 1,
        # but wait, let's see how candidates list is sorted and if Node.js has higher score
        assert len(candidates) > 1
        assert candidates[0].ecosystem == "Node.js"
        assert candidates[0].score == 25
        assert candidates[1].ecosystem == "Python"
        assert candidates[1].score == 10

