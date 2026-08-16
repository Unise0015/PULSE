import re
from datetime import datetime
from typing import List, Optional
from pulse.domain.models import VulnerabilityFinding, VersionMetadata
from pulse.domain.version import get_comparator
from pulse.vulnerability.policy import ScanPolicy
from pulse.version_intelligence.models import (
    UpgradeRecommendation, RecommendationStrategy, RecommendationConfidence,
    MigrationRisk, VerificationSource, RecommendationMethod, RecommendationEvidence
)
from pulse.version_intelligence.command_generator import generate_package_manager_commands
from pulse.remediation.verification_service import UpgradeVerificationService

def _parse_major(version_str: Optional[str]) -> Optional[int]:
    if not version_str:
        return None
    m = re.match(r"(\d+)", version_str.strip())
    return int(m.group(1)) if m else None

def analyze_upgrade_recommendation(
    pkg_name: str,
    ecosystem: str,
    current_version: str,
    findings: List[VulnerabilityFinding],
    version_metadata: Optional[VersionMetadata] = None,
    verify_candidate: bool = False
) -> UpgradeRecommendation:
    """Decision engine generating a transparent, evidence-based UpgradeRecommendation."""
    now = datetime.now()
    curr_ver = current_version or "Unknown"

    # Collect fix versions from findings
    fix_versions = [f.fix_version for f in findings if f.fix_version]
    sorted_fixes: List[str] = []
    if fix_versions:
        try:
            from functools import cmp_to_key
            comp = get_comparator(ecosystem)
            def _cmp(v1, v2):
                if comp.compare(v1, "==", v2):
                    return 0
                return 1 if comp.compare(v1, ">", v2) else -1
            sorted_fixes = sorted(list(set(fix_versions)), key=cmp_to_key(_cmp))
        except Exception:
            sorted_fixes = sorted(list(set(fix_versions)))

    minimum_known_safe = sorted_fixes[-1] if sorted_fixes else (fix_versions[0] if fix_versions else None)

    latest_stable = None
    if version_metadata:
        latest_stable = getattr(version_metadata, "latest_stable_version", None) or getattr(version_metadata, "latest_lts_version", None) or getattr(version_metadata, "latest_version", None)

    # EOL Status Classification
    curr_major = _parse_major(curr_ver)
    latest_major = _parse_major(latest_stable)

    if curr_major is not None and latest_major is not None:
        if curr_major < latest_major - 1:
            status = "End of Life"
        elif curr_major == latest_major - 1:
            status = "Maintenance"
        else:
            status = "Supported"
    else:
        status = "Supported"

    has_vulnerabilities = len(findings) > 0 and any(f.cvss_score > 0 or f.kev_match or bool(f.cve_id) for f in findings)

    # Candidate evaluation & verification loop
    rejected_candidates: List[str] = []
    if minimum_known_safe:
        recommended_version: Optional[str] = minimum_known_safe
    elif latest_stable and latest_stable != curr_ver:
        recommended_version = latest_stable
    elif not has_vulnerabilities:
        recommended_version = curr_ver
    else:
        recommended_version = None

    verified_safe = False
    verification_scan_performed = False
    verification_findings = 0
    verification_blocking_findings = 0
    cache_hit = False

    # Advisory pre-filtering: candidate list starts from theoretically safe version according to advisories
    candidate_versions: List[str] = []
    if sorted_fixes:
        candidate_versions.extend(sorted_fixes)
    if latest_stable and latest_stable not in candidate_versions and (not has_vulnerabilities or latest_stable != curr_ver):
        candidate_versions.append(latest_stable)

    evidence = RecommendationEvidence(
        method=RecommendationMethod.ADVISORY_CONFIRMED if minimum_known_safe else RecommendationMethod.REGISTRY_CONFIRMED,
        policy_version=ScanPolicy.POLICY_VERSION,
        providers_used=["OSV", "NVD", "KEV", "EPSS"],
        verified_at=now,
        confidence=RecommendationConfidence.HIGH if version_metadata else RecommendationConfidence.MEDIUM
    )

    if verify_candidate and candidate_versions:
        verifier = UpgradeVerificationService()
        verification_scan_performed = True

        for candidate in candidate_versions:
            ver_res = verifier.verify_candidate(pkg_name, candidate, ecosystem)
            if ver_res.blocking_findings == 0:
                recommended_version = candidate
                verified_safe = True
                verification_findings = ver_res.total_findings
                verification_blocking_findings = 0
                cache_hit = ver_res.cache_hit

                new_ev = RecommendationEvidence(
                    method=RecommendationMethod.VERIFIED_SCAN,
                    policy_version=ScanPolicy.POLICY_VERSION,
                    providers_used=["OSV", "NVD", "KEV", "EPSS"],
                    verified_at=now,
                    cache_hit=cache_hit,
                    confidence=RecommendationConfidence.HIGH
                )
                evidence.upgrade_to(new_ev)
                break
            else:
                rejected_candidates.append(candidate)

    # Reasoning & Strategy generation
    strategy = RecommendationStrategy.MINIMUM_SAFE
    alternative_version = None
    alternative_reason = ""

    if rejected_candidates and recommended_version:
        first_rej = rejected_candidates[0]
        recommendation_reason = (
            f"Recommended version {recommended_version} is the lowest verified secure release in the supported maintenance branch. "
            f"Version {first_rej} was rejected because verification detected known blocking vulnerabilities."
        )
    elif minimum_known_safe and latest_stable and minimum_known_safe != latest_stable:
        recommendation_reason = "First LTS patch release that fixes every detected vulnerability with lowest migration risk"
        strategy = RecommendationStrategy.MINIMUM_SAFE
        alternative_version = latest_stable
        alternative_reason = "Latest stable release for longest future support"
    elif latest_stable and latest_stable != curr_ver:
        recommendation_reason = "Latest stable release recommended for production"
        strategy = RecommendationStrategy.LATEST_STABLE
        alternative_version = None
        alternative_reason = "Already on optimal release track"
    elif minimum_known_safe:
        recommendation_reason = "Minimum version required to resolve all reported vulnerabilities"
        strategy = RecommendationStrategy.SECURITY_ONLY
        alternative_version = None
        alternative_reason = "No separate alternative branch identified"
    else:
        if has_vulnerabilities:
            recommended_version = None
            recommendation_reason = "No verified non-vulnerable upgrade release identified. Manual upgrade review required."
            strategy = RecommendationStrategy.CUSTOM
            alternative_version = None
            alternative_reason = "Monitor vendor security advisories"
        else:
            recommended_version = curr_ver
            recommendation_reason = "Already on optimal version with no known vulnerabilities"
            strategy = RecommendationStrategy.CUSTOM
            alternative_version = None
            alternative_reason = "No upgrade required"

    # Migration Risk Evaluation
    target_major = _parse_major(recommended_version) if recommended_version else None
    if curr_major is not None and target_major is not None:
        diff = target_major - curr_major
        if diff <= 0:
            migration_risk = MigrationRisk.LOW
        elif diff == 1:
            migration_risk = MigrationRisk.MEDIUM
        else:
            migration_risk = MigrationRisk.HIGH
    else:
        migration_risk = MigrationRisk.LOW

    # Suitability
    if evidence.method == RecommendationMethod.VERIFIED_SCAN and verified_safe:
        suitability_rating = "Production Ready (Verified Safe)"
    elif version_metadata and version_metadata.latest_stable_version and recommended_version == version_metadata.latest_stable_version:
        suitability_rating = "Production Ready" if migration_risk == MigrationRisk.LOW else "Recommended Update"
    elif minimum_known_safe and recommended_version == minimum_known_safe:
        suitability_rating = "Recommended Update"
    elif not has_vulnerabilities:
        suitability_rating = "Production Ready"
    else:
        suitability_rating = "Manual Review Required"

    # Verification Sources
    verifications = [
        VerificationSource(source="Registry Metadata", verified=bool(version_metadata), timestamp=now),
        VerificationSource(source="OSV Database", verified=bool(findings), timestamp=now),
        VerificationSource(source="NVD Database", verified=any(f.cve_id and f.cve_id.startswith("CVE-") for f in findings), timestamp=now),
        VerificationSource(source="CISA KEV Database", verified=any(f.kev_match for f in findings), timestamp=now),
        VerificationSource(source="No known vulnerabilities at scan time", verified=verified_safe or not has_vulnerabilities, timestamp=now)
    ]

    sources = [
        "OSV affected ranges",
        "Registry metadata",
        "Version Intelligence",
        "Supported Branch Analysis"
    ]

    if recommended_version and (not has_vulnerabilities or recommended_version != curr_ver):
        commands = generate_package_manager_commands(pkg_name, recommended_version, ecosystem)
    else:
        commands = {"upgrade": "Manual upgrade review required"}

    return UpgradeRecommendation(
        package_name=pkg_name,
        ecosystem=ecosystem,
        current_version=curr_ver,
        status=status,
        minimum_known_safe=minimum_known_safe,
        latest_stable=latest_stable,
        recommended_version=recommended_version,
        recommendation_reason=recommendation_reason,
        strategy=strategy,
        alternative_version=alternative_version,
        alternative_reason=alternative_reason,
        confidence=evidence.confidence,
        suitability_rating=suitability_rating,
        migration_risk=migration_risk,
        verified_safe=verified_safe,
        verification_scan_performed=verification_scan_performed,
        verification_findings=verification_findings,
        verification_blocking_findings=verification_blocking_findings,
        evidence=evidence,
        rejected_candidates=rejected_candidates,
        verifications=verifications,
        sources=sources,
        commands=commands,
        verified_date=now
    )


def populate_scan_recommendations(scan_result) -> None:
    """Generates canonical verified upgrade recommendations for all vulnerable packages in scan_result once."""
    if not getattr(scan_result, "findings", None):
        return
    pkg_map = {}
    for f in scan_result.findings:
        if not f.package:
            continue
        key = scan_result.make_package_key(f.package.ecosystem, f.package.name)
        if key not in pkg_map:
            pkg_map[key] = (f.package, [])
        pkg_map[key][1].append(f)

    for key, (sample_pkg, findings_list) in pkg_map.items():
        if key not in scan_result.upgrade_recommendations:
            rec = analyze_upgrade_recommendation(
                pkg_name=sample_pkg.name,
                ecosystem=sample_pkg.ecosystem,
                current_version=sample_pkg.version,
                findings=findings_list,
                version_metadata=getattr(sample_pkg, "version_metadata", None),
                verify_candidate=True
            )
            scan_result.upgrade_recommendations[key] = rec
