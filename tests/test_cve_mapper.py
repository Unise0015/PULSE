import pytest
from pulse.website.cve_mapper import get_cpe_candidate, get_osv_package_for_tech

def test_get_cpe_candidate():
    # Exact version
    cpe = get_cpe_candidate("nginx", "1.20.1")
    assert cpe == "cpe:2.3:a:nginx:nginx:1.20.1:*:*:*:*:*:*:*"

    # Missing version (should fallback to '*')
    cpe = get_cpe_candidate("nginx", None)
    assert cpe == "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"

    # Tech with no CPE in catalog (e.g. WordPress, which uses OSV lookup_strategy)
    cpe = get_cpe_candidate("wordpress", "6.2")
    assert cpe is None

    # Invalid technology
    cpe = get_cpe_candidate("nonexistent-tech", "1.0")
    assert cpe is None

def test_get_osv_package_for_tech():
    # Valid OSV tech
    osv = get_osv_package_for_tech("wordpress")
    assert osv == ("wordpress", "WordPress")

    # Tech without OSV ecosystem/package defined (e.g. Nginx, which is NVD only)
    osv = get_osv_package_for_tech("nginx")
    assert osv is None

    # Invalid technology
    osv = get_osv_package_for_tech("nonexistent-tech")
    assert osv is None
