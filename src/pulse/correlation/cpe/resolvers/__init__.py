from typing import List
from pulse.correlation.cpe.resolvers.base import BaseCPEResolver

class CPEResolverRegistry:
    _loaded = False
    _resolvers: List[BaseCPEResolver] = []

    @classmethod
    def load(cls) -> List[BaseCPEResolver]:
        if cls._loaded:
            return cls._resolvers

        # Import resolvers inside load to avoid circular imports during package load
        from pulse.correlation.cpe.resolvers.nextjs import NextJsResolver
        from pulse.correlation.cpe.resolvers.wordpress import WordPressResolver
        from pulse.correlation.cpe.resolvers.nginx import NginxResolver
        from pulse.correlation.cpe.resolvers.apache import ApacheResolver
        from pulse.correlation.cpe.resolvers.generic import GenericCPEResolver

        resolver_classes = [
            NextJsResolver,
            WordPressResolver,
            NginxResolver,
            ApacheResolver,
            GenericCPEResolver
        ]

        loaded_instances = []
        seen_ids = set()
        seen_names = set()

        for rc in resolver_classes:
            instance = rc()
            
            # Validation checks
            rid = getattr(instance, "resolver_id", None)
            rname = getattr(instance, "resolver_name", None)
            priority = getattr(instance, "priority", None)
            categories = getattr(instance, "supported_categories", None)

            if rid is None or rid == "":
                raise ValueError(f"Resolver class {rc.__name__} has missing or empty resolver_id")
            if rname is None or rname == "":
                raise ValueError(f"Resolver class {rc.__name__} has missing or empty resolver_name")
            if priority is None or not isinstance(priority, int):
                raise ValueError(f"Resolver class {rc.__name__} has invalid or missing priority (must be int)")
            if categories is None or not isinstance(categories, list) or len(categories) == 0:
                raise ValueError(f"Resolver class {rc.__name__} has missing or empty supported_categories")

            # Check uniqueness
            if rid in seen_ids:
                raise ValueError(f"Duplicate resolver_id found: {rid}")
            if rname in seen_names:
                raise ValueError(f"Duplicate resolver_name found: {rname}")

            seen_ids.add(rid)
            seen_names.add(rname)
            loaded_instances.append(instance)

        # Sort by priority descending
        loaded_instances.sort(key=lambda x: x.priority, reverse=True)
        cls._resolvers = loaded_instances
        cls._loaded = True
        return cls._resolvers

    @classmethod
    def reset(cls) -> None:
        """Helper to reset the registry for testing validation failures."""
        cls._loaded = False
        cls._resolvers = []
