"""
Comprehensive Test Suite for Smart Package Disambiguation, Multi-Vendor CPE,
Release-Qualified Distro OSV, and Ecosystem-Aware Version Range Evaluation.
Includes strict negative controls (redis, docker, kubernetes) and pure collisions (nginx, apache).
"""

import pytest
import asyncio
from rich.console import Console

from pulse.domain.models import PackageInfo
from pulse.ecosystems.package_resolution import PackageResolutionService
from pulse.ecosystems.smart_disambiguation import PackageDisambiguator, DisambiguationType
from pulse.vulnerability.cpe_resolver import CPEResolver
from pulse.vulnerability.distro_osv import DistroOSVClient, DISTRO_RELEASE_ECOSYSTEMS
from pulse.domain.version_range import VersionRangeMatcher
from pulse.services.package_service import PackageService


# ── 1. Pure Collision Resolution Tests ──

def test_nginx_pure_collision_resolution():
    """Verifies that nginx 1.24.0 resolves to Standalone Software rather than npm stub."""
    resolver = PackageResolutionService()
    result = asyncio.run(resolver.resolve("nginx", "1.24.0"))

    assert result.is_standalone is True
    assert result.ecosystem == "Standalone Software"
    assert result.version_exists is True
    assert result.version_verified is True
    assert any("cpe:2.3:a:f5:nginx:1.24.0" in c for c in result.cpe_candidates)
    assert any("cpe:2.3:a:nginx:nginx:1.24.0" in c for c in result.cpe_candidates)
    assert result.warning_message is not None
    assert "wrapper" in result.warning_message.lower() or "standalone" in result.warning_message.lower()


def test_apache_pure_collision_resolution():
    """Verifies that apache 2.4.58 resolves to Standalone Software with Apache HTTP Server CPE."""
    resolver = PackageResolutionService()
    result = asyncio.run(resolver.resolve("apache", "2.4.58"))

    assert result.is_standalone is True
    assert result.ecosystem == "Standalone Software"
    assert any("cpe:2.3:a:apache:http_server:2.4.58" in c for c in result.cpe_candidates)


def test_openssl_pure_collision_resolution():
    """Verifies that openssl 3.0.13 resolves to Standalone Software with OpenSSL CPE."""
    resolver = PackageResolutionService()
    result = asyncio.run(resolver.resolve("openssl", "3.0.13"))

    assert result.is_standalone is True
    assert result.ecosystem == "Standalone Software"
    assert any("cpe:2.3:a:openssl:openssl:3.0.13" in c for c in result.cpe_candidates)


# ── 2. Negative Controls (Real Language Package Manager Verification) ──

def test_redis_negative_control_npm_client():
    """Verifies that redis 6.2.1 resolves cleanly to Node.js (npm) because version exists."""
    resolver = PackageResolutionService()
    result = asyncio.run(resolver.resolve("redis", "6.2.1"))

    assert result.is_standalone is False
    assert result.ecosystem == "Node.js"
    assert result.version_exists is True
    assert result.version_verified is True


def test_docker_negative_control_pypi_sdk():
    """Verifies that docker 7.2.0 resolves cleanly to Python (PyPI) because version exists."""
    resolver = PackageResolutionService()
    result = asyncio.run(resolver.resolve("docker", "7.2.0"))

    assert result.is_standalone is False
    assert result.ecosystem == "Python"
    assert result.version_exists is True
    assert result.version_verified is True


def test_kubernetes_negative_control_pypi_client():
    """Verifies that kubernetes 36.0.3 resolves cleanly to Python (PyPI) because version exists."""
    resolver = PackageResolutionService()
    result = asyncio.run(resolver.resolve("kubernetes", "36.0.3"))

    assert result.is_standalone is False
    assert result.ecosystem == "Python"
    assert result.version_exists is True
    assert result.version_verified is True


def test_django_control_pypi():
    """Verifies that django 4.2.0 resolves cleanly to Python (PyPI)."""
    resolver = PackageResolutionService()
    result = asyncio.run(resolver.resolve("django", "4.2.0"))

    assert result.is_standalone is False
    assert result.ecosystem == "Python"
    assert result.version_exists is True


def test_react_control_npm():
    """Verifies that react 18.2.0 resolves cleanly to Node.js (npm)."""
    resolver = PackageResolutionService()
    result = asyncio.run(resolver.resolve("react", "18.2.0"))

    assert result.is_standalone is False
    assert result.ecosystem == "Node.js"
    assert result.version_exists is True


# ── 3. Multi-Vendor Lineage CPE Resolution Tests ──

def test_multi_vendor_cpe_lineage_nginx():
    """Verifies that nginx expands across all historical vendors (f5, nginx, igor_sysoev)."""
    candidates = CPEResolver.get_cpe_candidates("nginx", "1.24.0")

    assert "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*" in candidates
    assert "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*" in candidates
    assert "cpe:2.3:a:igor_sysoev:nginx:1.24.0:*:*:*:*:*:*:*" in candidates


def test_multi_vendor_cpe_lineage_sudo():
    """Verifies that sudo expands across sudo_project and todd_miller."""
    candidates = CPEResolver.get_cpe_candidates("sudo", "1.9.14")
    assert any("sudo_project" in c for c in candidates)
    assert any("todd_miller" in c for c in candidates)


def test_multi_vendor_cpe_lineage_spring_boot():
    """Verifies that spring_boot expands across vmware and pivotal_software."""
    candidates = CPEResolver.get_cpe_candidates("spring_boot", "3.1.2")
    assert any("vmware" in c for c in candidates)
    assert any("pivotal_software" in c for c in candidates)


# ── 4. Release-Qualified Distro OSV Ecosystem Tests ──

def test_distro_osv_release_qualified_tags():
    """Verifies that distro OSV ecosystems use release-qualified tags."""
    assert "Debian:12" in DISTRO_RELEASE_ECOSYSTEMS
    assert "Debian:11" in DISTRO_RELEASE_ECOSYSTEMS
    assert "Alpine:v3.19" in DISTRO_RELEASE_ECOSYSTEMS
    assert "Ubuntu:22.04" in DISTRO_RELEASE_ECOSYSTEMS
    assert "Rocky Linux:9" in DISTRO_RELEASE_ECOSYSTEMS
    assert "AlmaLinux:9" in DISTRO_RELEASE_ECOSYSTEMS
    assert "Wolfi" in DISTRO_RELEASE_ECOSYSTEMS


# ── 5. Ecosystem-Aware Version Range Evaluation Tests ──

def test_version_range_matcher_osv_boundaries():
    """Verifies SemVer range matching for introduced/fixed/last_affected."""
    assert VersionRangeMatcher.is_version_affected("1.24.0", introduced="1.20.0", fixed="1.24.2") is True
    assert VersionRangeMatcher.is_version_affected("1.24.3", introduced="1.20.0", fixed="1.24.2") is False
    assert VersionRangeMatcher.is_version_affected("v1.24.0", introduced="v1.20.0", fixed="v1.24.2") is True


def test_version_range_matcher_nvd_boundaries():
    """Verifies NVD boundary operators (versionStartIncluding / versionEndExcluding)."""
    assert VersionRangeMatcher.matches_nvd_boundaries("1.24.0", v_start_incl="1.20.0", v_end_excl="1.25.0") is True
    assert VersionRangeMatcher.matches_nvd_boundaries("1.26.0", v_start_incl="1.20.0", v_end_excl="1.25.0") is False
    assert VersionRangeMatcher.matches_nvd_boundaries("1.19.9", v_start_incl="1.20.0", v_end_excl="1.25.0") is False


# ── 6. Targeted Scan Integration for Standalone Software ──

def test_standalone_nginx_scan_returns_findings():
    """Verifies that scanning nginx 1.24.0 as Standalone software finds real vulnerabilities."""
    console = Console(record=True)
    pkg = PackageInfo(name="nginx", version="1.24.0", ecosystem="Standalone")
    
    service = PackageService()
    scan_result = service.run(console, [pkg], target_type="package", target_id="standalone:nginx")
    
    assert scan_result.packages_scanned == 1
    assert len(scan_result.findings) > 0
    cve_ids = [f.cve_id for f in scan_result.findings if f.cve_id]
    assert len(cve_ids) > 0
