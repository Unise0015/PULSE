import pytest
import logging
from pathlib import Path
from pulse.ecosystems.base import (
    EcosystemPlugin, ScanContext, ScannerConfig, PluginManifest,
    Capability, PluginCategory, PluginHealth, RawDependency, ResolvedDependency, EventBus, Event
)
from pulse.ecosystems.registry import PluginRegistry

class MockDependencyPlugin(EcosystemPlugin):
    def __init__(self, p_id, priority=0, dependencies=None):
        self._id = p_id
        self._priority = priority
        self._deps = dependencies or []

    @property
    def manifest(self) -> PluginManifest:
        return PluginManifest(
            id=self._id,
            name=self._id.capitalize(),
            ecosystem="Mock",
            priority=self._priority,
            category=PluginCategory.DEPENDENCY,
            dependencies=self._deps
        )

    def detect(self, context: ScanContext) -> bool:
        return True

    def parse(self, context: ScanContext) -> list[RawDependency]:
        return []

    def resolve(self, raw, context: ScanContext) -> list[ResolvedDependency]:
        return []

    def normalize(self, resolved, context: ScanContext):
        return []

def test_plugin_manifest_properties():
    manifest = PluginManifest(
        id="test_plugin",
        name="Test Plugin",
        ecosystem="TestEcosystem",
        version="1.2.3",
        priority=100,
        category=PluginCategory.WEBSITE,
        health=PluginHealth.EXPERIMENTAL,
        capabilities={Capability.LOCKFILE, Capability.GRAPH},
        dependencies=["other_plugin"]
    )
    assert manifest.id == "test_plugin"
    assert manifest.name == "Test Plugin"
    assert manifest.priority == 100
    assert manifest.category == PluginCategory.WEBSITE
    assert manifest.health == PluginHealth.EXPERIMENTAL
    assert Capability.LOCKFILE in manifest.capabilities
    assert "other_plugin" in manifest.dependencies

def test_topological_sorting_in_registry():
    p1 = MockDependencyPlugin("a", priority=10, dependencies=["b"])
    p2 = MockDependencyPlugin("b", priority=20, dependencies=["c"])
    p3 = MockDependencyPlugin("c", priority=30)
    p4 = MockDependencyPlugin("d", priority=5)

    registry = PluginRegistry()
    registry.reset()
    try:
        registry.register(p1)
        registry.register(p2)
        registry.register(p3)
        registry.register(p4)

        loaded = registry.load()
        loaded_ids = [p.manifest.id for p in loaded]
        
        # Dependency resolution ordering: "c" first, then "b", then "a".
        assert loaded_ids.index("c") < loaded_ids.index("b")
        assert loaded_ids.index("b") < loaded_ids.index("a")
    finally:
        registry.reset()

def test_circular_dependency_checks():
    p1 = MockDependencyPlugin("a", dependencies=["b"])
    p2 = MockDependencyPlugin("b", dependencies=["a"])
    
    registry = PluginRegistry()
    registry.reset()
    try:
        registry.register(p1)
        registry.register(p2)
        
        with pytest.raises(ValueError, match="Circular dependency detected"):
            registry.load()
    finally:
        registry.reset()

def test_event_bus_prioritization():
    bus = EventBus()
    calls = []

    def handler_low(event):
        calls.append("low")

    def handler_high(event):
        calls.append("high")

    def handler_medium(event):
        calls.append("medium")

    bus.subscribe(Event, handler_low, priority=10)
    bus.subscribe(Event, handler_high, priority=90)
    bus.subscribe(Event, handler_medium, priority=50)

    bus.publish(Event())
    
    # Priority is sorted descending, so high executes first, then medium, then low.
    assert calls == ["high", "medium", "low"]

def test_plugin_graceful_degradation():
    class CrashingPlugin(MockDependencyPlugin):
        def parse(self, context: ScanContext):
            raise RuntimeError("Parse failure")

    p = CrashingPlugin("crash")
    cfg = ScannerConfig()
    context = ScanContext(root=Path("."), config=cfg, cache=None, history=None, logger=logging.getLogger())
    
    res = p.discover(context)
    from pulse.domain.models import PluginExecutionStatus
    assert res.diagnostics.status == PluginExecutionStatus.FAILED
    assert len(res.diagnostics.errors) == 1
    assert "Parsing failed: Parse failure" in res.diagnostics.errors[0]
