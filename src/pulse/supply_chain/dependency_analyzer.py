"""
Dependency tree analysis engine — offline-friendly, no external services.
Uses generic edge-based trees built from EcosystemProviders.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Set

from pulse.domain.models import (
    DependencyNode,
    DependencyEdge,
    PackageInfo,
    SupplyChainMetrics,
    VulnerabilityFinding,
)

# Maximum depth of recursive tree expansion
MAX_DEPTH = 5


class DependencyAnalyzer:
    """Builds dependency graphs and computes supply chain exposure metrics."""

    @classmethod
    def build_generic_tree(
        cls,
        packages: List[PackageInfo],
        edges: List[DependencyEdge],
        findings: List[VulnerabilityFinding]
    ) -> List[DependencyNode]:
        """
        Build a dependency tree for any ecosystem using packages and dependency edges.
        """
        # 1. Build package maps: (ecosystem, normalized_name) -> PackageInfo
        pkg_map: Dict[tuple[str, str], PackageInfo] = {}
        for pkg in packages:
            eco = (pkg.ecosystem or "").lower()
            norm_name = cls._get_norm_key(pkg.name, eco)
            pkg_map[(eco, norm_name)] = pkg

        # 2. Build parent-to-children adj list
        adj: Dict[tuple[str, str], List[str]] = {}
        for edge in edges:
            parent_name = edge.parent_name
            child_name = edge.child_name
            
            # Find parent's ecosystem
            parent_ecosystem = None
            for (eco, norm_name), pkg in pkg_map.items():
                if pkg.name.lower() == parent_name.lower():
                    parent_ecosystem = eco
                    break
            if not parent_ecosystem:
                if packages:
                    parent_ecosystem = (packages[0].ecosystem or "").lower()
                else:
                    parent_ecosystem = ""

            parent_norm = cls._get_norm_key(parent_name, parent_ecosystem)
            child_norm = cls._get_norm_key(child_name, parent_ecosystem)
            
            key = (parent_ecosystem, parent_norm)
            if key not in adj:
                adj[key] = []
            if child_norm not in adj[key]:
                adj[key].append(child_norm)

        vuln_map = cls._build_vuln_map_eco(findings)
        
        # 3. Direct packages are roots
        roots = [pkg for pkg in packages if getattr(pkg, "dependency_type", "DIRECT") == "DIRECT"]
        
        if not roots:
            all_children = set()
            for edge in edges:
                parent_ecosystem = None
                for (eco, norm_name), pkg in pkg_map.items():
                    if pkg.name.lower() == edge.parent_name.lower():
                        parent_ecosystem = eco
                        break
                if not parent_ecosystem:
                    parent_ecosystem = (packages[0].ecosystem or "").lower() if packages else ""
                child_norm = cls._get_norm_key(edge.child_name, parent_ecosystem)
                all_children.add((parent_ecosystem, child_norm))
                
            roots = []
            for pkg in packages:
                eco = (pkg.ecosystem or "").lower()
                norm_name = cls._get_norm_key(pkg.name, eco)
                if (eco, norm_name) not in all_children:
                    roots.append(pkg)
        
        roots.sort(key=lambda p: p.name.lower())

        trees: List[DependencyNode] = []
        for pkg in roots:
            eco = (pkg.ecosystem or "").lower()
            norm_name = cls._get_norm_key(pkg.name, eco)
            node = cls._make_node_eco(pkg.name, pkg.version, pkg.ecosystem, True, 0, vuln_map)
            cls._build_generic_children(
                node, norm_name, eco, adj, pkg_map, vuln_map, { (eco, norm_name) }, 1
            )
            trees.append(node)

        return trees

    @classmethod
    def _build_generic_children(
        cls,
        parent: DependencyNode,
        pkg_norm: str,
        eco: str,
        adj: dict,
        pkg_map: dict,
        vuln_map: dict,
        visited: Set[tuple[str, str]],
        depth: int
    ) -> None:
        if depth > MAX_DEPTH:
            return
        
        key = (eco, pkg_norm)
        children_norms = adj.get(key, [])
        seen_children = set()
        for child_norm in children_norms:
            child_key = (eco, child_norm)
            if child_key in visited or child_key not in pkg_map or child_norm in seen_children:
                continue
            seen_children.add(child_norm)
            
            pkg = pkg_map[child_key]
            child_node = cls._make_node_eco(pkg.name, pkg.version, pkg.ecosystem, False, depth, vuln_map)
            cls._build_generic_children(
                child_node, child_norm, eco, adj, pkg_map, vuln_map,
                visited | {child_key}, depth + 1
            )
            parent.children.append(child_node)

    # ── Legacy/Compatibility tree builders ─────────────────────────────────────

    @classmethod
    def build_python_tree(
        cls, findings: List[VulnerabilityFinding]
    ) -> List[DependencyNode]:
        from pulse.ecosystems.python_provider import PythonProvider
        provider = PythonProvider()
        packages = provider.discover_packages(Path("."))
        edges = provider.discover_dependency_edges(Path("."))
        return cls.build_generic_tree(packages, edges, findings)

    @classmethod
    def build_node_tree(
        cls, path: str, findings: List[VulnerabilityFinding]
    ) -> List[DependencyNode]:
        from pulse.ecosystems.node_provider import NodeProvider
        provider = NodeProvider()
        packages = provider.discover_packages(Path(path))
        edges = provider.discover_dependency_edges(Path(path))
        return cls.build_generic_tree(packages, edges, findings)

    # ── Flat tree fallback ─────────────────────────────────────────────────────

    @classmethod
    def build_flat_tree(
        cls,
        packages: List[PackageInfo],
        findings: List[VulnerabilityFinding],
    ) -> List[DependencyNode]:
        """
        Flat (depth-0) tree for targeted scans.
        """
        vuln_map = cls._build_vuln_map_eco(findings)
        seen: Set[str] = set()
        nodes: List[DependencyNode] = []

        for pkg in packages:
            key = (pkg.ecosystem.lower(), pkg.name.lower())
            if key in seen:
                continue
            seen.add(key)
            is_direct = getattr(pkg, "dependency_type", "DIRECT") == "DIRECT"
            eco = pkg.ecosystem.lower()
            norm_name = cls._get_norm_key(pkg.name, eco)
            cve_count = vuln_map.get(f"{eco}:{norm_name}") or vuln_map.get(norm_name, 0)
            nodes.append(
                DependencyNode(
                    package_name=pkg.name,
                    version=pkg.version,
                    ecosystem=pkg.ecosystem,
                    direct=is_direct,
                    vulnerable=cve_count > 0,
                    cve_count=cve_count,
                    depth=0,
                )
            )

        return nodes

    # ── Metrics ────────────────────────────────────────────────────────────────

    @classmethod
    def compute_metrics(cls, trees: List[DependencyNode]) -> SupplyChainMetrics:
        """Compute supply chain exposure metrics from a dependency tree list."""
        direct_count = 0
        transitive_count = 0
        vulnerable_direct = 0
        vulnerable_transitive = 0
        max_depth = 0
        critical_chains = 0

        def walk(node: DependencyNode, is_direct: bool) -> None:
            nonlocal transitive_count, vulnerable_direct, vulnerable_transitive
            nonlocal max_depth, critical_chains
            max_depth = max(max_depth, node.depth)
            if is_direct:
                if node.vulnerable:
                    vulnerable_direct += 1
                    critical_chains += 1
            else:
                if node.vulnerable:
                    vulnerable_transitive += 1
            for child in node.children:
                transitive_count += 1
                walk(child, False)

        for node in trees:
            direct_count += 1
            walk(node, True)

        return SupplyChainMetrics(
            direct_count=direct_count,
            transitive_count=transitive_count,
            vulnerable_direct=vulnerable_direct,
            vulnerable_transitive=vulnerable_transitive,
            max_depth=max_depth,
            critical_chains=critical_chains,
        )

    # ── Helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _norm(name: str) -> str:
        """Legacy helper for backward compatibility."""
        return name.lower().replace("-", "_").replace(".", "_")

    @classmethod
    def _get_norm_key(cls, name: str, ecosystem: str) -> str:
        eco = (ecosystem or "").lower()
        if eco in ("python", "pypi"):
            return name.lower().replace("-", "_").replace(".", "_")
        return name.lower()

    @staticmethod
    def _parse_dep_name(req: str) -> str:
        """Extract the bare package name from a Requires-Dist specifier string."""
        raw = re.split(r"[\s><=!;(\[]", req.strip())[0]
        return DependencyAnalyzer._norm(raw) if raw else ""

    @classmethod
    def _make_node_eco(
        cls,
        name: str,
        version: str,
        ecosystem: str,
        direct: bool,
        depth: int,
        vuln_map: Dict[str, int]
    ) -> DependencyNode:
        eco = (ecosystem or "").lower()
        norm_name = cls._get_norm_key(name, eco)
        # Check specific ecosystem key, fallback to name-only
        cve_count = vuln_map.get(f"{eco}:{norm_name}") or vuln_map.get(norm_name, 0)
        return DependencyNode(
            package_name=name,
            version=version,
            ecosystem=ecosystem,
            direct=direct,
            vulnerable=cve_count > 0,
            cve_count=cve_count,
            depth=depth,
        )

    @classmethod
    def _build_vuln_map_eco(cls, findings: List[VulnerabilityFinding]) -> Dict[str, int]:
        vuln_map = {}
        for f in findings:
            eco = (f.package.ecosystem or "").lower()
            norm_name = cls._get_norm_key(f.package.name, eco)
            
            # Store specific eco:name key
            eco_key = f"{eco}:{norm_name}"
            vuln_map[eco_key] = vuln_map.get(eco_key, 0) + 1
            
            # Store fallback name-only key
            vuln_map[norm_name] = vuln_map.get(norm_name, 0) + 1
        return vuln_map
