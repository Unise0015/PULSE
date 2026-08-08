import pytest
from io import StringIO
from rich.console import Console
from datetime import datetime
from unittest.mock import patch
from pulse.domain.models import ScanResult, PackageInfo, VulnerabilityFinding
from pulse.services.package_service import PackageService


def _make_dummy_packages():
    return [PackageInfo(name="django", version="3.2.0", ecosystem="python")]


def test_normal_scan_hides_pipeline_noise(capsys):
    """Verify normal mode uses a single transient spinner and hides pipeline details."""
    service = PackageService()
    console = Console()
    
    with patch("pulse.services.enrichment_pipeline.EnrichmentPipeline.run") as mock_run:
        from pulse.services.enrichment_pipeline import EnrichmentResult, EnrichmentMetrics
        mock_run.return_value = EnrichmentResult(findings=[], attack_paths=[], packages=[], metrics=EnrichmentMetrics())
        
        service.run(console, _make_dummy_packages())
        captured = capsys.readouterr().out
        
        # We might not capture the rich Progress if it's transient, but we can verify it doesn't print "OSV Matching found..."
        assert "OSV Matching found" not in captured
        assert "Enriching with NVD" not in captured
        
        # Verify the pipeline was called with progress=None
        mock_run.assert_called_once()
        kwargs = mock_run.call_args.kwargs
        assert kwargs.get("progress") is None


def test_debug_mode_shows_pipeline_noise(capsys):
    """Verify debug mode passes the progress bar to the pipeline."""
    from pulse.state import AppState
    
    original = AppState.DEBUG_MODE
    try:
        AppState.DEBUG_MODE = True
        service = PackageService()
        console = Console()
        
        with patch("pulse.services.enrichment_pipeline.EnrichmentPipeline.run") as mock_run:
            from pulse.services.enrichment_pipeline import EnrichmentResult, EnrichmentMetrics
            mock_run.return_value = EnrichmentResult(findings=[], attack_paths=[], packages=[], metrics=EnrichmentMetrics())
            
            service.run(console, _make_dummy_packages())
            
            # Verify the pipeline was called with a progress object
            mock_run.assert_called_once()
            kwargs = mock_run.call_args.kwargs
            assert kwargs.get("progress") is not None
    finally:
        AppState.DEBUG_MODE = original
