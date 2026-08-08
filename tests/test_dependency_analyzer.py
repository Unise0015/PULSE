import pytest
import os
import json
from pathlib import Path
from dataclasses import asdict
from pulse.supply_chain.dependency_analyzer import DependencyAnalyzer
from pulse.domain.models import PackageInfo, VulnerabilityFinding, DependencyNode

def create_mock_finding(name, version="1.0.0"):
    pkg = PackageInfo(name=name, version=version, ecosystem="python")
    return VulnerabilityFinding(
        package=pkg,
        cve_id="CVE-1234",
        cvss_score=9.8,
        cvss_severity="CRITICAL",
        epss_score=0.1,
        epss_percent="10%",
        kev_match=False,
        risk_heat_score=90,
        description="Test",
        fix_version="1.0.1",
        source="OSV",
        published_date=None,
        last_modified_date=None,
        nvd_url=""
    )

def test_flat_tree_build():
    packages = [
        PackageInfo(name="requests", version="2.31.0", ecosystem="python", dependency_type="DIRECT"),
        PackageInfo(name="urllib3", version="1.26.0", ecosystem="python", dependency_type="TRANSITIVE")
    ]
    findings = [create_mock_finding("requests")]
    
    trees = DependencyAnalyzer.build_flat_tree(packages, findings)
    
    assert len(trees) == 2
    
    requests_node = next(n for n in trees if n.package_name == "requests")
    assert requests_node.direct is True
    assert requests_node.vulnerable is True
    assert requests_node.cve_count == 1
    assert requests_node.depth == 0
    assert len(requests_node.children) == 0
    
    urllib3_node = next(n for n in trees if n.package_name == "urllib3")
    assert urllib3_node.direct is False
    assert urllib3_node.vulnerable is False
    assert urllib3_node.cve_count == 0
    assert urllib3_node.depth == 0
    assert len(urllib3_node.children) == 0

def test_compute_metrics():
    # Construct a manual tree
    # root (direct, vuln)
    # └── child1 (transitive, clean)
    #     └── child2 (transitive, vuln)
    
    child2 = DependencyNode(
        package_name="child2", version="1", ecosystem="npm", direct=False,
        vulnerable=True, cve_count=1, depth=2, children=[]
    )
    
    child1 = DependencyNode(
        package_name="child1", version="1", ecosystem="npm", direct=False,
        vulnerable=False, cve_count=0, depth=1, children=[child2]
    )
    
    root = DependencyNode(
        package_name="root", version="1", ecosystem="npm", direct=True,
        vulnerable=True, cve_count=1, depth=0, children=[child1]
    )
    
    metrics = DependencyAnalyzer.compute_metrics([root])
    
    assert metrics.direct_count == 1
    assert metrics.transitive_count == 2
    assert metrics.vulnerable_direct == 1
    assert metrics.vulnerable_transitive == 1
    assert metrics.max_depth == 2
    assert metrics.critical_chains == 1

def test_node_json_serialization():
    node = DependencyNode(
        package_name="test", version="1.0", ecosystem="npm", direct=True,
        vulnerable=True, cve_count=1, depth=0, children=[
            DependencyNode(
                package_name="child", version="2.0", ecosystem="npm", direct=False,
                vulnerable=False, cve_count=0, depth=1, children=[]
            )
        ]
    )
    
    data = asdict(node)
    assert data["package_name"] == "test"
    assert data["children"][0]["package_name"] == "child"
    
    # Ensure it's json serializable
    json_str = json.dumps(data)
    assert "test" in json_str

def test_python_tree_builds_nodes():
    # Since importlib.metadata reads the actual environment, we just ensure it 
    # doesn't crash and returns valid DependencyNode objects.
    findings = []
    trees = DependencyAnalyzer.build_python_tree(findings)
    assert isinstance(trees, list)
    if trees:
        assert isinstance(trees[0], DependencyNode)

def test_node_tree_from_package_lock(tmp_path):
    pkg_json = {
        "dependencies": {
            "express": "^4.17.1"
        }
    }
    
    # v2 lockfile mock
    lock_json = {
        "packages": {
            "": {},
            "node_modules/express": {
                "version": "4.17.1",
                "dependencies": {
                    "accepts": "~1.3.7"
                }
            },
            "node_modules/accepts": {
                "version": "1.3.7"
            }
        }
    }
    
    (tmp_path / "package.json").write_text(json.dumps(pkg_json), encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(json.dumps(lock_json), encoding="utf-8")
    
    findings = [create_mock_finding("accepts")]
    trees = DependencyAnalyzer.build_node_tree(str(tmp_path), findings)
    
    assert len(trees) == 1
    root = trees[0]
    assert root.package_name == "express"
    assert root.direct is True
    assert root.vulnerable is False
    
    assert len(root.children) == 1
    child = root.children[0]
    assert child.package_name == "accepts"
    assert child.direct is False
    assert child.vulnerable is True
    assert child.cve_count == 1
