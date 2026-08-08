import sqlite3
from pathlib import Path
from typing import Optional, List
from pulse.domain.models import ScanResult, VulnerabilityFinding, PostureDelta
from pulse.history.db import get_db_path

class HistoryService:
    def __init__(self):
        from pulse.history.db import init_db
        init_db()
        self.db_path = get_db_path()

    def save_scan(self, scan: ScanResult, report_dir: Optional[str] = None) -> int:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            import json
            recs_json = None
            if hasattr(scan, "_recommendations") and scan._recommendations:
                try:
                    recs_dict = {}
                    for pkg_name, rec in scan._recommendations.items():
                        recs_dict[pkg_name] = {
                            "recommended_version": rec.recommended_version,
                            "latest_stable": rec.latest_stable,
                            "verification_status": getattr(rec, "verification_status", "VERIFIED" if rec.verified_safe else "UNVERIFIED"),
                            "verification_confidence": str(rec.confidence.value if hasattr(rec.confidence, "value") else rec.confidence),
                            "migration_risk": str(rec.migration_risk.value if hasattr(rec.migration_risk, "value") else rec.migration_risk),
                            "upgrade_command": rec.upgrade_command,
                            "recommendation_reason": rec.recommendation_reason
                        }
                    recs_json = json.dumps(recs_dict)
                except Exception:
                    pass

            # Save the run
            cursor.execute('''
                INSERT INTO scan_runs (
                    timestamp, hostname, tool_version, attack_surface_score,
                    scan_duration_seconds, packages_scanned, vulnerabilities_found, kev_matches,
                    target_type, target_id, target_fingerprint, report_dir, recommendations_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                scan.hostname,
                scan.tool_version,
                scan.attack_surface_score,
                scan.scan_duration_seconds,
                scan.packages_scanned,
                len(scan.findings),
                scan.kev_matches,
                scan.target_type,
                scan.target_id,
                scan.target_fingerprint,
                report_dir,
                recs_json
            ))
            scan_run_id = cursor.lastrowid
            
            # Save the findings
            from pulse.domain.models import FindingSourceType, deduplicate_and_merge_findings
            unique_findings = deduplicate_and_merge_findings(scan.findings)
            scan.findings = unique_findings
            for finding in unique_findings:
                if finding.source_type == FindingSourceType.WEBSITE:
                    continue # Do not store website findings in cve_events
                    
                intel = finding.exploit_intelligence
                public_poc_val = 1 if (intel and intel.public_poc) else 0
                poc_source_val = intel.poc_source if intel else None
                exploit_maturity_val = intel.exploit_maturity if intel else "Unknown"
                threat_level_val = "Low"

                cursor.execute('''
                    INSERT INTO cve_events (
                        scan_run_id, cve_id, package, status, risk_score,
                        cvss_score, cvss_severity, epss_score, epss_percent,
                        latest_version, description, kev_match,
                        cwe, cvss_vector, nvd_url,
                        public_poc, poc_source, exploit_maturity, threat_level
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    scan_run_id,
                    finding.cve_id,
                    f"{finding.package.ecosystem}:{finding.package.name}@{finding.package.version}",
                    "new", # Will be refined later if needed
                    finding.risk_heat_score,
                    finding.cvss_score,
                    finding.cvss_severity,
                    finding.epss_score,
                    finding.epss_percent,
                    finding.package.latest_version or "",
                    finding.description or "",
                    1 if finding.kev_match else 0,
                    finding.cwe or "",
                    finding.cvss_vector or "",
                    finding.nvd_url or "",
                    public_poc_val,
                    poc_source_val,
                    exploit_maturity_val,
                    threat_level_val
                ))
            
            # Save the website technologies if available
            if hasattr(scan, "website_assessment") and scan.website_assessment and scan.website_assessment.technologies:
                import hashlib
                import json
                
                for tech in scan.website_assessment.technologies:
                    # Generate keys using normalized catalog name
                    norm_key = tech.name.lower()
                    tech_key = hashlib.sha256(f"{norm_key}:{tech.category.value.lower() if hasattr(tech.category, 'value') else str(tech.category).lower()}".encode("utf-8")).hexdigest()
                    version_str = tech.version if tech.version else ""
                    fingerprint_hash = hashlib.sha256(f"{norm_key}:{version_str.lower()}:{tech.category.value.lower() if hasattr(tech.category, 'value') else str(tech.category).lower()}".encode("utf-8")).hexdigest()
                    
                    # Lifecycle tracking: check previous scans for the first_seen scan run ID
                    cursor.execute('''
                        SELECT first_seen_scan_id
                        FROM scan_technologies
                        WHERE fingerprint_hash = ?
                        ORDER BY scan_run_id DESC LIMIT 1
                    ''', (fingerprint_hash,))
                    row = cursor.fetchone()
                    
                    if row:
                        first_seen_scan_id = row[0]
                    else:
                        first_seen_scan_id = scan_run_id
                    last_seen_scan_id = scan_run_id
                    
                    # Truncate evidence (max 10 items, max 500 chars value/description)
                    truncated_ev_list = []
                    for ev in tech.evidence[:10]:
                        truncated_ev_list.append({
                            "method": ev.method.value if hasattr(ev.method, "value") else ev.method,
                            "source": ev.source,
                            "value": ev.value[:500] if ev.value else "",
                            "confidence": ev.confidence,
                            "description": ev.description[:500] if ev.description else "",
                            "reliability": ev.reliability.value if hasattr(ev.reliability, "value") else ev.reliability
                        })
                    evidence_json = json.dumps(truncated_ev_list)
                    
                    # Truncate version evidence
                    version_evidence_json = None
                    if tech.version_evidence:
                        v_ev = tech.version_evidence
                        version_evidence_json = json.dumps({
                            "method": v_ev.method.value if hasattr(v_ev.method, "value") else v_ev.method,
                            "source": v_ev.source,
                            "value": v_ev.value[:500] if v_ev.value else "",
                            "confidence": v_ev.confidence,
                            "description": v_ev.description[:500] if v_ev.description else "",
                            "reliability": v_ev.reliability.value if hasattr(v_ev.reliability, "value") else v_ev.reliability
                        })
                        
                    # Children and CPE Candidates serialization
                    children_json = json.dumps(tech.children)
                    cpe_candidates_json = json.dumps([{"cpe": c.cpe, "confidence": c.confidence} for c in tech.cpe_candidates])
                    
                    cursor.execute('''
                        INSERT INTO scan_technologies (
                            scan_run_id, name, version, category, confidence, confidence_band,
                            evidence_count, raw_match_count, version_status, evidence_json,
                            version_evidence_json, version_confidence, signature_id, signature_version,
                            parent, children_json, cpe_candidates_json, ecosystem,
                            correlation_supported, detection_mode, technology_key, fingerprint_hash,
                            first_seen_scan_id, last_seen_scan_id, schema_version
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        scan_run_id,
                        norm_key,
                        tech.version,
                        tech.category.value if hasattr(tech.category, 'value') else str(tech.category),
                        tech.confidence,
                        tech.confidence_band.value if hasattr(tech.confidence_band, 'value') else str(tech.confidence_band),
                        len(truncated_ev_list),
                        tech.raw_match_count,
                        tech.version_status.value if hasattr(tech.version_status, 'value') else str(tech.version_status),
                        evidence_json,
                        version_evidence_json,
                        tech.version_confidence,
                        tech.signature_id,
                        tech.signature_version,
                        tech.parent,
                        children_json,
                        cpe_candidates_json,
                        tech.ecosystem,
                        1 if tech.correlation_supported else 0,
                        tech.detection_mode.value if hasattr(tech.detection_mode, 'value') else str(tech.detection_mode),
                        tech_key,
                        fingerprint_hash,
                        first_seen_scan_id,
                        last_seen_scan_id,
                        "1.0"
                    ))
            
            conn.commit()

        self.cleanup_if_needed()
        return scan_run_id

    def get_posture_delta(self, current_scan: ScanResult) -> Optional[PostureDelta]:
        """Calculates the delta between the last scan in DB and the current_scan."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Get the most recent scan (which would be the previous one since we haven't saved current yet)
            sql = '''
                SELECT id, attack_surface_score, kev_matches, packages_scanned
                FROM scan_runs
                WHERE target_type = ? AND target_id = ?
            '''
            params = [current_scan.target_type, current_scan.target_id]
            
            if hasattr(current_scan, 'id') and current_scan.id is not None:
                sql += ' AND id != ?'
                params.append(current_scan.id)
                
            sql += ' ORDER BY timestamp DESC LIMIT 1'
            
            cursor.execute(sql, tuple(params))
            row = cursor.fetchone()
            
            if not row:
                return None # First scan
                
            prev_scan_id = row[0]
            prev_score = row[1] if row[1] is not None else 0
            prev_kev_matches = row[2] if row[2] is not None else 0
            prev_packages_scanned = row[3] if row[3] is not None else 0

            
            # Fetch previous findings
            cursor.execute('''
                SELECT cve_id, risk_score
                FROM cve_events
                WHERE scan_run_id = ?
            ''', (prev_scan_id,))
            
            prev_cves = {}
            for cve_row in cursor.fetchall():
                prev_cves[cve_row[0]] = cve_row[1]
                
        # Compare
        current_cve_map = {f.cve_id: f for f in current_scan.findings if f.cve_id}
        
        new_findings = []
        remediated_cves = []
        
        highest_new_risk = None
        highest_resolved_risk_score = 0
        highest_resolved_cve = None
        
        # Find new ones
        for cve_id, finding in current_cve_map.items():
            if cve_id not in prev_cves:
                new_findings.append(finding)
                if not highest_new_risk or finding.risk_heat_score > highest_new_risk.risk_heat_score:
                    highest_new_risk = finding
                    
        # Find remediated ones
        for prev_cve_id, prev_risk in prev_cves.items():
            if prev_cve_id not in current_cve_map:
                remediated_cves.append(prev_cve_id)
                if prev_risk > highest_resolved_risk_score:
                    highest_resolved_risk_score = prev_risk
                    highest_resolved_cve = prev_cve_id
                    
        # Score deltas
        risk_score_change = current_scan.attack_surface_score - prev_score
        curr_kev = getattr(current_scan, "_stored_kev_matches", current_scan.kev_matches)
        kev_change_count = curr_kev - prev_kev_matches
        
        # We need previous critical count. For MVP, we can estimate or just query it if we stored severity. 
        # Since we didn't store severity in DB, we'll just diff against 0 for now or calculate from new/remediated
        # Actually, let's just count criticals in new vs remediated (assuming remediated criticals > 90)
        new_criticals = sum(1 for f in new_findings if f.cvss_severity == "CRITICAL")
        # Estimate resolved criticals
        resolved_criticals = sum(1 for risk in [prev_cves[c] for c in remediated_cves] if risk >= 90)
        critical_count_change = new_criticals - resolved_criticals
        
        return PostureDelta(
            previous_score=prev_score,
            current_score=current_scan.attack_surface_score,
            new_cves=new_findings,
            remediated_cves=remediated_cves,
            risk_score_change=risk_score_change,
            kev_change_count=kev_change_count,
            critical_count_change=critical_count_change,
            highest_new_risk=highest_new_risk,
            highest_resolved_risk_score=highest_resolved_risk_score if highest_resolved_cve else None,
            highest_resolved_cve=highest_resolved_cve
        )

    def get_scan_runs(self) -> List[dict]:
        """Fetch all historical scan runs."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, timestamp, attack_surface_score, packages_scanned, vulnerabilities_found, target_type, target_id, report_dir
                FROM scan_runs
                ORDER BY timestamp DESC
            ''')
            runs = []
            for row in cursor.fetchall():
                runs.append({
                    "id": row[0],
                    "timestamp": row[1],
                    "score": row[2],
                    "packages": row[3],
                    "vulns": row[4],
                    "target_type": row[5] if len(row) > 5 and row[5] is not None else "global",
                    "target_id": row[6] if len(row) > 6 and row[6] is not None else "global",
                    "report_dir": row[7] if len(row) > 7 and row[7] is not None else None
                })
            return runs

    def get_scan_by_id(self, scan_id: int) -> Optional[ScanResult]:
        """Reconstruct a lightweight ScanResult from history for delta comparison."""
        from datetime import datetime
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT timestamp, hostname, tool_version, attack_surface_score, 
                       scan_duration_seconds, packages_scanned, kev_matches, vulnerabilities_found,
                       target_type, target_id, target_fingerprint, recommendations_json
                FROM scan_runs
                WHERE id = ?
            ''', (scan_id,))
            row = cursor.fetchone()
            if not row:
                return None
                
            ts = datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S")
            scan = ScanResult(
                timestamp=ts,
                hostname=row[1],
                tool_version=row[2],
                attack_surface_score=row[3],
                scan_duration_seconds=row[4],
                packages_scanned=row[5],
                findings=[],
                target_type=row[8] if len(row) > 8 and row[8] is not None else "global",
                target_id=row[9] if len(row) > 9 and row[9] is not None else "global",
                target_fingerprint=row[10] if len(row) > 10 and row[10] is not None else ""
            )
            scan.id = scan_id

            if len(row) > 11 and row[11]:
                try:
                    import json
                    scan._recommendations = json.loads(row[11])
                except Exception:
                    pass
            # The kev_matches field is a property that calculates from findings,
            # but PostureDelta needs exact matches. We will reconstruct minimal findings.
            scan._stored_kev_matches = row[6] # Temporary hack for delta
            
            cursor.execute('''
                SELECT cve_id, package, risk_score, cvss_score, cvss_severity, epss_score, epss_percent, latest_version, description, kev_match, cwe, cvss_vector, nvd_url,
                       public_poc, poc_source, exploit_maturity, threat_level
                FROM cve_events
                WHERE scan_run_id = ?
            ''', (scan_id,))
            
            from pulse.domain.models import PackageInfo, ExploitIntelligence
            for cve_row in cursor.fetchall():
                # Parse package string formatted as "ecosystem:name@version"
                # Fallback to old format "name version" for backward compatibility
                pkg_str = cve_row[1]
                if ":" in pkg_str and "@" in pkg_str:
                    eco_part, rest = pkg_str.split(":", 1)
                    pkg_name, pkg_version = rest.split("@", 1)
                    eco = eco_part
                else:
                    pkg_parts = pkg_str.rsplit(" ", 1)
                    pkg_name = pkg_parts[0]
                    pkg_version = pkg_parts[1] if len(pkg_parts) > 1 else ""
                    eco = "unknown"
                
                public_poc = bool(cve_row[13]) if len(cve_row) > 13 and cve_row[13] is not None else False
                poc_source = cve_row[14] if len(cve_row) > 14 else None
                exploit_maturity = cve_row[15] if len(cve_row) > 15 and cve_row[15] else "No Public PoC Identified"
                
                intel = ExploitIntelligence(
                    public_poc=public_poc,
                    poc_source=poc_source,
                    exploit_maturity=exploit_maturity,
                    exploit_references=[]
                )
                
                f = VulnerabilityFinding(
                    package=PackageInfo(name=pkg_name, version=pkg_version, ecosystem=eco, latest_version=cve_row[7] if len(cve_row) > 7 else None),
                    cve_id=cve_row[0],
                    cvss_score=cve_row[3] if len(cve_row) > 3 and cve_row[3] is not None else 0.0,
                    cvss_severity=cve_row[4] if len(cve_row) > 4 and cve_row[4] else ("CRITICAL" if cve_row[2] >= 90 else "HIGH"),
                    epss_score=cve_row[5] if len(cve_row) > 5 and cve_row[5] is not None else 0.0,
                    epss_percent=cve_row[6] if len(cve_row) > 6 and cve_row[6] else "0%",
                    kev_match=bool(cve_row[9]) if len(cve_row) > 9 else False,
                    risk_heat_score=cve_row[2],
                    description=cve_row[8] if len(cve_row) > 8 and cve_row[8] else "",
                    fix_version=None,
                    source="history",
                    published_date=None,
                    last_modified_date=None,
                    nvd_url=cve_row[12] if len(cve_row) > 12 and cve_row[12] else "",
                    cwe=cve_row[10] if len(cve_row) > 10 and cve_row[10] else None,
                    cvss_vector=cve_row[11] if len(cve_row) > 11 and cve_row[11] else None,
                    exploit_intelligence=intel
                )
                scan.findings.append(f)

            from pulse.domain.models import deduplicate_and_merge_findings
            scan.findings = deduplicate_and_merge_findings(scan.findings)

            # If target_type == "website", rebuild technologies list from SQLite
            if scan.target_type == "website":
                # Fetch technologies stored for this run
                cursor.execute('''
                    SELECT name, version, category, confidence, evidence_json
                    FROM scan_technologies
                    WHERE scan_run_id = ?
                ''', (scan_id,))
                
                from pulse.domain.models import TechnologyFingerprint, TechnologyCategory, WebsiteAssessment
                import json
                
                technologies = []
                for tech_row in cursor.fetchall():
                    tech_name = tech_row[0]
                    tech_version = tech_row[1]
                    cat_str = tech_row[2]
                    confidence = tech_row[3]
                    evidence_json = tech_row[4]
                    
                    category = None
                    for cat in TechnologyCategory:
                        if cat.value.lower() == cat_str.lower() or cat.name.lower() == cat_str.lower():
                            category = cat
                            break
                    if not category:
                        category = TechnologyCategory.FRAMEWORK
                        
                    evidence = []
                    if evidence_json:
                        try:
                            from pulse.domain.models import DetectionEvidence, DetectionMethod, EvidenceReliability
                            ev_data = json.loads(evidence_json)
                            for ev in ev_data:
                                method = DetectionMethod(ev["method"]) if "method" in ev else DetectionMethod.HEADER
                                rel = EvidenceReliability(ev["reliability"]) if "reliability" in ev else EvidenceReliability.MEDIUM
                                evidence.append(DetectionEvidence(
                                    method=method,
                                    source=ev.get("source", ""),
                                    value=ev.get("value", ""),
                                    confidence=ev.get("confidence", 100),
                                    description=ev.get("description", ""),
                                    reliability=rel
                                ))
                        except Exception:
                            pass
                            
                    technologies.append(TechnologyFingerprint(
                        name=tech_name,
                        version=tech_version,
                        category=category,
                        confidence=confidence,
                        evidence=evidence,
                        correlation_supported=True
                    ))
                    
                scan.website_assessment = WebsiteAssessment(
                    url=scan.target_id,
                    technologies=technologies,
                    security_headers=[]
                )
            
            # Validate scan reconstruction
            expected_vulns = row[7] if len(row) > 7 else len(scan.findings)
            if len(scan.findings) != expected_vulns:
                import logging
                logging.getLogger(__name__).warning(
                    f"History reconstruction warning: Expected {expected_vulns} vulnerabilities for scan {scan_id}, "
                    f"but reconstructed {len(scan.findings)}."
                )
            
            return scan



    def get_previous_technologies(self, target_type: str, target_id: str) -> List[dict]:
        """Fetch the list of technologies detected in the most recent scan run."""
        from pulse.domain.models import TechnologyCategory, DetectionStatus, ConfidenceBand
        from datetime import datetime
        import json
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id FROM scan_runs
                WHERE target_type = ? AND target_id = ?
                ORDER BY timestamp DESC LIMIT 1
            ''', (target_type, target_id))
            row = cursor.fetchone()
            if not row:
                return []
                
            scan_run_id = row[0]
            
            cursor.execute('''
                SELECT t.name, t.version, t.category, t.confidence, t.confidence_band,
                       t.evidence_count, t.signature_id, t.signature_version, t.parent,
                       t.children_json, t.cpe_candidates_json, t.ecosystem,
                       t.correlation_supported, t.detection_mode, t.technology_key, t.fingerprint_hash,
                       r_first.timestamp as first_seen_time, r_last.timestamp as last_seen_time, t.version_status
                FROM scan_technologies t
                LEFT JOIN scan_runs r_first ON t.first_seen_scan_id = r_first.id
                LEFT JOIN scan_runs r_last ON t.last_seen_scan_id = r_last.id
                WHERE t.scan_run_id = ?
            ''', (scan_run_id,))
            
            techs = []
            for r in cursor.fetchall():
                name, version, category_str, confidence, confidence_band_str, \
                evidence_count, signature_id, signature_version, parent, \
                children_json, cpe_candidates_json, ecosystem, \
                correlation_supported, detection_mode_str, technology_key, fingerprint_hash, \
                first_seen_time, last_seen_time, version_status_str = r
                
                category = None
                for cat in TechnologyCategory:
                    if cat.value.lower() == category_str.lower() or cat.name.lower() == category_str.lower():
                        category = cat
                        break
                if not category:
                    category = TechnologyCategory.FRAMEWORK
                    
                confidence_band = None
                for cb in ConfidenceBand:
                    if cb.value.lower() == confidence_band_str.lower() or cb.name.lower() == confidence_band_str.lower():
                        confidence_band = cb
                        break
                if not confidence_band:
                    confidence_band = ConfidenceBand.LOW
                    
                version_status = None
                for vs in DetectionStatus:
                    if vs.value.lower() == version_status_str.lower() or vs.name.lower() == version_status_str.lower():
                        version_status = vs
                        break
                if not version_status:
                    version_status = DetectionStatus.UNKNOWN
                    
                first_seen = None
                if first_seen_time:
                    try:
                         first_seen = datetime.strptime(first_seen_time, "%Y-%m-%d %H:%M:%S")
                    except Exception:
                        pass
                last_seen = None
                if last_seen_time:
                    try:
                        last_seen = datetime.strptime(last_seen_time, "%Y-%m-%d %H:%M:%S")
                    except Exception:
                        pass
                        
                cpe_list = []
                if cpe_candidates_json:
                    try:
                        cpe_data = json.loads(cpe_candidates_json)
                        for c in cpe_data:
                            if isinstance(c, dict) and "cpe" in c:
                                cpe_list.append(c["cpe"])
                            else:
                                cpe_list.append(str(c))
                    except Exception:
                        pass
                        
                techs.append({
                    "technology_key": technology_key,
                    "name": name,
                    "category": category,
                    "version": version,
                    "version_status": version_status,
                    "confidence": confidence,
                    "confidence_band": confidence_band,
                    "fingerprint_hash": fingerprint_hash,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "evidence_count": evidence_count,
                    "source_signature": signature_id or name.lower(),
                    "cpe_candidates": cpe_list,
                    "source_fingerprints": [signature_id] if signature_id else [name.lower()],
                    "risk_score": 0
                })
                
            return techs

    def get_storage_stats(self) -> dict:
        """Returns database file size, total scan count, and total report folders count."""
        import os
        from pathlib import Path
        from pulse.config import get_config_dir

        db_path = Path(self.db_path)
        db_size_bytes = db_path.stat().st_size if db_path.exists() else 0
        db_size_mb = round(db_size_bytes / (1024 * 1024), 2)

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM scan_runs")
            scan_count = cursor.fetchone()[0]

        reports_dir = get_config_dir() / "reports"
        reports_count = 0
        if reports_dir.exists():
            reports_count = len([p for p in reports_dir.iterdir() if p.is_dir() and p.name.startswith("scan_")])

        return {
            "db_size_mb": db_size_mb,
            "stored_scans_count": scan_count,
            "stored_reports_count": reports_count
        }

    def _delete_scan_assets_and_rows(self, scan_ids: list[int]) -> int:
        """Helper to purge SQLite rows and associated report folders for a list of scan IDs."""
        if not scan_ids:
            return 0

        import shutil
        from pathlib import Path
        from pulse.config import get_setting

        delete_reports = get_setting("HISTORY_DELETE_REPORTS", "true").lower() in ("true", "1", "yes")
        deleted_count = 0

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            for sid in scan_ids:
                if delete_reports:
                    cursor.execute("SELECT report_dir FROM scan_runs WHERE id = ?", (sid,))
                    row = cursor.fetchone()
                    if row and row[0]:
                        rpath = Path(row[0])
                        if rpath.exists() and rpath.is_dir():
                            try:
                                shutil.rmtree(rpath)
                            except Exception:
                                pass

                cursor.execute("DELETE FROM cve_events WHERE scan_run_id = ?", (sid,))
                cursor.execute("DELETE FROM scan_technologies WHERE scan_run_id = ?", (sid,))
                cursor.execute("DELETE FROM scan_runs WHERE id = ?", (sid,))
                deleted_count += 1
            conn.commit()

        return deleted_count

    def cleanup_if_needed(self) -> int:
        """Automatic history cleanup policy based on HISTORY_MAX_SCANS and HISTORY_RETENTION_DAYS."""
        from datetime import datetime, timedelta
        from pulse.config import get_setting

        auto_cleanup = get_setting("HISTORY_AUTO_CLEANUP", "true").lower() in ("true", "1", "yes")
        if not auto_cleanup:
            return 0

        max_scans = int(get_setting("HISTORY_MAX_SCANS", get_setting("REPORT_KEEP_HISTORY", "100")))
        retention_days = int(get_setting("HISTORY_RETENTION_DAYS", "90"))

        scan_ids_to_delete = set()

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Enforce max count
            cursor.execute("SELECT id FROM scan_runs ORDER BY id DESC")
            all_rows = cursor.fetchall()
            if len(all_rows) > max_scans:
                for row in all_rows[max_scans:]:
                    scan_ids_to_delete.add(row[0])

            # Enforce age limit
            cutoff = datetime.now() - timedelta(days=retention_days)
            cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("SELECT id FROM scan_runs WHERE timestamp < ?", (cutoff_str,))
            for row in cursor.fetchall():
                scan_ids_to_delete.add(row[0])

        return self._delete_scan_assets_and_rows(list(scan_ids_to_delete))

    def clear_history_all(self) -> int:
        """Purge all scan history and associated report assets."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM scan_runs")
            sids = [r[0] for r in cursor.fetchall()]

        return self._delete_scan_assets_and_rows(sids)

    def clear_history_by_days(self, days: int) -> int:
        """Purge scans older than N days."""
        from datetime import datetime, timedelta
        cutoff = datetime.now() - timedelta(days=days)
        return self.clear_history_before_date(cutoff)

    def clear_history_before_date(self, cutoff: datetime) -> int:
        """Purge scans before a cutoff datetime."""
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM scan_runs WHERE timestamp < ?", (cutoff_str,))
            sids = [r[0] for r in cursor.fetchall()]

        return self._delete_scan_assets_and_rows(sids)

    def clear_history_keep_count(self, max_keep: int) -> int:
        """Purge scans keeping only the last N scans."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM scan_runs ORDER BY id DESC")
            all_rows = cursor.fetchall()
            if len(all_rows) <= max_keep:
                return 0
            sids = [r[0] for r in all_rows[max_keep:]]

        return self._delete_scan_assets_and_rows(sids)

    def register_report_artifact(self, scan_id: str, fmt: str, path_str: str) -> None:
        """Persist an exact report export artifact path in SQLite."""
        p = Path(path_str)
        file_size = p.stat().st_size if p.exists() else 0
        status = "AVAILABLE" if p.exists() else "MISSING"

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO report_artifacts (scan_id, format, path, created_at, file_size, status)
                VALUES (?, ?, ?, datetime('now'), ?, ?)
            ''', (str(scan_id), fmt.lower(), str(p.resolve()), file_size, status))
            conn.commit()

    def get_report_artifact(self, scan_id: str, fmt: str = "html") -> Optional[dict]:
        """Fetch the latest registered report artifact for a specific scan ID and format."""
        sid_str = str(scan_id)
        sid_padded = sid_str.zfill(6)
        sid_unpadded = sid_str.lstrip("0") or "0"

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, scan_id, format, path, created_at, file_size, status
                FROM report_artifacts
                WHERE (scan_id = ? OR scan_id = ? OR scan_id = ?) AND format = ?
                ORDER BY id DESC LIMIT 1
            ''', (sid_str, sid_padded, sid_unpadded, fmt.lower()))
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "id": row[0],
                "scan_id": row[1],
                "format": row[2],
                "path": row[3],
                "created_at": row[4],
                "file_size": row[5],
                "status": row[6]
            }

    def get_latest_report_artifact(self, fmt: str = "html") -> Optional[dict]:
        """Fetch the most recently created report artifact across all scans."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, scan_id, format, path, created_at, file_size, status
                FROM report_artifacts
                WHERE format = ?
                ORDER BY id DESC LIMIT 1
            ''', (fmt.lower(),))
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "id": row[0],
                "scan_id": row[1],
                "format": row[2],
                "path": row[3],
                "created_at": row[4],
                "file_size": row[5],
                "status": row[6]
            }



