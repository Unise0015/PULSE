from pulse.ecosystems.registry import PluginRegistry

# Global registry instance
registry = PluginRegistry()

def __getattr__(name):
    if name == "EcosystemRegistry":
        from pulse.ecosystems.registry import PluginRegistry
        return PluginRegistry
    raise AttributeError(f"module {__name__} has no attribute {name}")
