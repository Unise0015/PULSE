from unittest.mock import patch, MagicMock
from pulse.cli import lookup_cve_menu

@patch("pulse.cli.questionary.text")
@patch("pulse.cli.ScannerOrchestrator")
@patch("pulse.cli.console.print")
def test_lookup_cve_valid(mock_print, mock_orchestrator_class, mock_text):
    # Mock user entering a valid CVE ID
    mock_text.return_value.ask.return_value = "CVE-2022-34265"
    
    mock_orch = MagicMock()
    mock_orchestrator_class.return_value = mock_orch
    
    lookup_cve_menu()
    
    # Verify lookup_cve was called with correct ID
    mock_orch.lookup_cve.assert_called_once()
    assert mock_orch.lookup_cve.call_args[0][1] == "CVE-2022-34265"

@patch("pulse.cli.questionary.text")
@patch("pulse.cli.ScannerOrchestrator")
@patch("pulse.cli.console.print")
def test_lookup_cve_invalid_format(mock_print, mock_orchestrator_class, mock_text):
    # Mock user entering an invalid format
    mock_text.return_value.ask.return_value = "1234-5678"
    
    mock_orch = MagicMock()
    mock_orchestrator_class.return_value = mock_orch
    
    lookup_cve_menu()
    
    # Verify lookup was not called
    mock_orch.lookup_cve.assert_not_called()
    mock_print.assert_any_call("[red]Invalid format. Must start with CVE-[/red]")
