import os
import pkgutil
import importlib
import inspect
from typing import List
from pulse.website.signatures.base import TechnologySignature
from pulse.domain.models import TechnologyCategory

class SignatureRegistry:
    _loaded = False
    _signatures: List[TechnologySignature] = []
    _scans_executed = {}
    _scans_matched = {}

    @classmethod
    def record_execution(cls, signature_id: str, matched: bool) -> float:
        cls._scans_executed[signature_id] = cls._scans_executed.get(signature_id, 0) + 1
        if matched:
            cls._scans_matched[signature_id] = cls._scans_matched.get(signature_id, 0) + 1
        return float(cls._scans_matched.get(signature_id, 0)) / cls._scans_executed[signature_id]

    @classmethod
    def load(cls) -> List[TechnologySignature]:
        if cls._loaded:
            return cls._signatures

        signatures = []
        seen_ids = set()
        
        # Discover all modules in the current package directory
        pkg_dir = os.path.dirname(__file__)
        for _, module_name, _ in pkgutil.iter_modules([pkg_dir]):
            if module_name == "base":
                continue
            
            # Import module dynamically
            module = importlib.import_module(f"pulse.website.signatures.{module_name}")
            
            # Find all classes that inherit from TechnologySignature
            for name, member in inspect.getmembers(module, inspect.isclass):
                if issubclass(member, TechnologySignature) and member is not TechnologySignature:
                    try:
                        sig_instance = member()
                    except Exception as e:
                        raise ValueError(f"Failed to instantiate signature class {name}: {e}")
                    
                    # Fail-fast validations
                    sig_id = sig_instance.signature_id
                    if not sig_id:
                        raise ValueError(f"Signature class {name} must provide a non-empty signature_id")
                    if not sig_id.islower() or not sig_id.replace("_", "").isalnum():
                        raise ValueError(f"Signature class {name} has invalid signature_id '{sig_id}'. Must be lowercase alphanumeric (underscores allowed)")
                    
                    if sig_id in seen_ids:
                        raise ValueError(f"Duplicate signature_id '{sig_id}' detected at signature class {name}")
                        
                    if not isinstance(sig_instance.priority, int) or not (0 <= sig_instance.priority <= 100):
                        raise ValueError(f"Signature {sig_id} must have a priority integer between 0 and 100")
                        
                    if not isinstance(sig_instance.category, TechnologyCategory):
                        raise ValueError(f"Signature {sig_id} has invalid category '{sig_instance.category}'")
                        
                    seen_ids.add(sig_id)
                    signatures.append(sig_instance)
        
        # Sort signatures by priority descending so higher priority executes first
        signatures.sort(key=lambda s: s.priority, reverse=True)
        cls._signatures = signatures
        cls._loaded = True
        return cls._signatures

    @classmethod
    def reset(cls):
        """For testing purposes, clear the loaded state."""
        cls._loaded = False
        cls._signatures = []
