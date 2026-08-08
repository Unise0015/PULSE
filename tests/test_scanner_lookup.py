from unittest.mock import patch, MagicMock
from pulse.scanner import ScannerOrchestrator
from rich.console import Console

def test_lookup_cve_no_crash():
    # Test that lookup_cve doesn't crash when calling providers
    console = Console(force_terminal=True)
    orch = ScannerOrchestrator()

    # Mock providers to avoid network calls
    with patch("pulse.scanner.NVDProvider") as mock_nvd, \
         patch("pulse.scanner.EPSSProvider") as mock_epss, \
         patch("pulse.scanner.KEVProvider") as mock_kev:

        # Setup mock instances
        nvd_instance = mock_nvd.return_value
        epss_instance = mock_epss.return_value
        kev_instance = mock_kev.return_value

        # Test with a dummy CVE ID
        # This should not crash now that the VulnerabilityFinding object is correctly constructed
        orch.lookup_cve(console, "CVE-2023-12345")

        # Verify providers were called
        nvd_instance.enrich_findings.assert_called_once()
        epss_instance.enrich_findings.assert_called_once()
        kev_instance.enrich_findings.assert_called_once()

def test_lookup_cve_not_found():
    # Test the case where the CVE is not found in NVD
    console = Console(force_terminal=True)
    orch = ScannerOrchestrator()

    with patch("pulse.scanner.NVDProvider") as mock_nvd, \
         patch("pulse.scanner.EPSSProvider") as mock_epss, \
         patch("pulse.scanner.KEVProvider") as mock_kev:

        # Mock NVD to not provide a description (which is how it determines "not found")
        nvd_instance = mock_nvd.return_value
        def mock_enrich(findings):
            # Do nothing, so finding.description remains empty
            pass
        nvd_instance.enrich_findings.side_effect = mock_enrich

        orch.lookup_cve(console, "CVE-NOT-FOUND")

        nvd_instance.enrich_findings.assert_called_once()
