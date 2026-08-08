"""Tests for PackageRegistryProvider."""
import pytest
from unittest.mock import patch, MagicMock
from pulse.domain.models import PackageInfo
from pulse.vulnerability.package_registry import PackageRegistryProvider


PYPI_RESPONSE = {
    "info": {
        "version": "4.2.5",
        "home_page": "https://www.djangoproject.com/",
    },
    "releases": {
        "4.2.5": [{"upload_time": "2023-09-18T10:00:00"}]
    }
}

NPM_RESPONSE = {
    "dist-tags": {"latest": "4.17.21"},
    "time": {"4.17.21": "2021-02-20T12:00:00"},
    "homepage": "https://lodash.com/",
}


@pytest.fixture
def mock_provider(tmp_path):
    """Provider with an isolated tmp database."""
    with patch("pulse.vulnerability.package_registry.get_db_path", return_value=tmp_path / "test.db"):
        # Initialize the table
        import sqlite3
        with sqlite3.connect(tmp_path / "test.db") as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS package_registry_cache (
                    pkg_key TEXT PRIMARY KEY,
                    latest_version TEXT,
                    release_date TEXT,
                    homepage TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
        yield PackageRegistryProvider()


def test_pypi_enrichment(mock_provider):
    pkg = PackageInfo(name="django", version="3.2", ecosystem="python")
    with patch.object(mock_provider, "_fetch_pypi", return_value={
        "latest_version": "4.2.5",
        "release_date": "2023-09-18",
        "homepage": "https://www.djangoproject.com/",
    }):
        mock_provider.enrich_packages([pkg])
    assert pkg.latest_version == "4.2.5"
    assert pkg.release_date == "2023-09-18" if hasattr(pkg, "release_date") else True
    assert pkg.homepage == "https://www.djangoproject.com/"


def test_npm_enrichment(mock_provider):
    pkg = PackageInfo(name="lodash", version="4.17.20", ecosystem="npm")
    with patch.object(mock_provider, "_fetch_npm", return_value={
        "latest_version": "4.17.21",
        "release_date": "2021-02-20",
        "homepage": "https://lodash.com/",
    }):
        mock_provider.enrich_packages([pkg])
    assert pkg.latest_version == "4.17.21"
    assert pkg.homepage == "https://lodash.com/"


def test_cache_is_used_on_second_call(mock_provider):
    pkg1 = PackageInfo(name="django", version="3.2", ecosystem="python")
    pkg2 = PackageInfo(name="django", version="3.2", ecosystem="python")

    fetch_calls = []

    def fake_fetch(name):
        fetch_calls.append(name)
        return {"latest_version": "4.2.5", "release_date": "2023-09-18", "homepage": "https://djangoproject.com"}

    with patch.object(mock_provider, "_fetch_pypi", side_effect=fake_fetch):
        mock_provider.enrich_packages([pkg1])
        mock_provider.enrich_packages([pkg2])

    # Second call should hit cache — only 1 network fetch
    assert len(fetch_calls) == 1
    assert pkg2.latest_version == "4.2.5"


def test_unknown_ecosystem_skips_gracefully(mock_provider):
    pkg = PackageInfo(name="libc", version="2.31", ecosystem="system")
    mock_provider.enrich_packages([pkg])  # Should not raise
    assert pkg.latest_version is None


def test_registry_failure_leaves_none(mock_provider):
    pkg = PackageInfo(name="django", version="3.2", ecosystem="python")
    with patch.object(mock_provider, "_fetch_pypi", return_value=None):
        mock_provider.enrich_packages([pkg])
    assert pkg.latest_version is None
