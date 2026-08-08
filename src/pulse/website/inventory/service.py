import hashlib
from datetime import datetime
from typing import List
from pulse.domain.models import WebsiteAssessment, TechnologyCategory, DetectionStatus, ConfidenceBand
from pulse.website.inventory.models import InventoryTechnology
from pulse.website.inventory.normalizer import normalize_name
from pulse.website.confidence import get_confidence_band
from pulse.history.history import HistoryService

class TechnologyInventoryService:
    def build_inventory(self, assessment: WebsiteAssessment) -> List[InventoryTechnology]:
        if not assessment or not assessment.technologies:
            return []

        # 1. Group raw fingerprints by normalized name and category
        from pulse.website.technology_resolver import resolve_technology
        from pulse.website.technology_catalog import TECHNOLOGY_CATALOG
        groups = {}
        for fp in assessment.technologies:
            norm_name = resolve_technology(fp.name) or fp.name.lower()
            key = (norm_name, fp.category)
            if key not in groups:
                groups[key] = []
            groups[key].append(fp)
            
        inventory = []
        
        # Instantiate HistoryService to fetch lifecycle datetimes from SQLite
        history_service = None
        try:
            history_service = HistoryService()
        except Exception:
            pass

        for (norm_name, category), group in groups.items():
            # Choose primary fingerprint (the one with a version or highest confidence)
            group_sorted = sorted(group, key=lambda x: (x.version is not None, x.confidence), reverse=True)
            primary = group_sorted[0]
            
            version = primary.version
            version_status = primary.version_status
            
            # Calculate stable hashes
            tech_key_raw = f"{norm_name.lower()}:{category.value.lower() if hasattr(category, 'value') else str(category).lower()}"
            technology_key = hashlib.sha256(tech_key_raw.encode("utf-8")).hexdigest()
            
            version_str = version if version else ""
            fingerprint_hash_raw = f"{norm_name.lower()}:{version_str.lower()}:{category.value.lower() if hasattr(category, 'value') else str(category).lower()}"
            fingerprint_hash = hashlib.sha256(fingerprint_hash_raw.encode("utf-8")).hexdigest()
            
            # Merge confidence, evidence counts, CPE candidates, and source signatures
            max_confidence = max(fp.confidence for fp in group)
            confidence_band = get_confidence_band(max_confidence)
            
            total_evidence_count = sum(fp.evidence_count for fp in group)
            
            cpes = set()
            for fp in group:
                for candidate in fp.cpe_candidates:
                    if hasattr(candidate, "cpe"):
                        cpes.add(candidate.cpe)
                    else:
                        cpes.add(str(candidate))
            cpe_list = sorted(list(cpes))
            
            sources = sorted(list(set(fp.signature_id for fp in group if fp.signature_id)))
            if not sources:
                sources = sorted(list(set(fp.name.lower() for fp in group)))
                
            # Lifecycle timestamps from SQLite
            first_seen = None
            last_seen = None
            if history_service:
                try:
                    import sqlite3
                    with sqlite3.connect(history_service.db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute('''
                            SELECT MIN(r.timestamp), MAX(r.timestamp)
                            FROM scan_technologies t
                            JOIN scan_runs r ON t.scan_run_id = r.id
                            WHERE t.technology_key = ?
                        ''', (technology_key,))
                        row = cursor.fetchone()
                        if row and row[0]:
                            first_seen = datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S")
                            last_seen = datetime.strptime(row[1], "%Y-%m-%d %H:%M:%S")
                except Exception:
                    pass
                    
            current_time = datetime.now()
            if not first_seen:
                first_seen = current_time
            if not last_seen:
                last_seen = current_time
                
            catalog_entry = TECHNOLOGY_CATALOG.get(norm_name)
            display_name = catalog_entry.get("display_name") if catalog_entry else normalize_name(norm_name)
            
            item = InventoryTechnology(
                technology_key=technology_key,
                name=display_name,
                category=category,
                version=version,
                version_status=version_status,
                confidence=max_confidence,
                confidence_band=confidence_band,
                fingerprint_hash=fingerprint_hash,
                first_seen=first_seen,
                last_seen=last_seen,
                evidence_count=total_evidence_count,
                source_signature=primary.signature_id or primary.name.lower(),
                cpe_candidates=cpe_list,
                source_fingerprints=sources,
                risk_score=0
            )
            inventory.append(item)
            
        # Category priorities mapping
        CATEGORY_PRIORITY = {
            TechnologyCategory.FRAMEWORK: 1,
            TechnologyCategory.CMS: 2,
            TechnologyCategory.RUNTIME: 3,
            TechnologyCategory.DATABASE: 4,
            TechnologyCategory.CDN: 5,
            TechnologyCategory.SECURITY: 6,
            TechnologyCategory.ANALYTICS: 7,
            TechnologyCategory.MONITORING: 8,
        }
        
        inventory.sort(key=lambda t: (CATEGORY_PRIORITY.get(t.category, 99), t.name.lower()))
        return inventory
