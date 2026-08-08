import pytest
from unittest.mock import patch, MagicMock
from pulse.scanner import ScannerOrchestrator
from pulse.domain.models import PackageInfo

def test_scanner_orchestrator_empty_results():
    """Test that ScannerOrchestrator gracefully handles zero packages and zero findings."""
    scanner = ScannerOrchestrator()
    console = MagicMock()
    
    with patch('pulse.discoverers.python.PythonDiscoverer.discover', return_value=[]), \
         patch('pulse.discoverers.node.NodeDiscoverer.discover', return_value=[]):
             
        result = scanner.run_auto_discover_scan(console)
        
        assert result.packages_scanned == 0
        assert result.attack_surface_score == 0
        assert len(result.findings) == 0
