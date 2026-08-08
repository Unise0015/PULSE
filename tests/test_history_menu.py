from unittest.mock import patch, MagicMock
from pulse.cli import view_history_menu

@patch("pulse.cli.post_scan_render")
@patch("pulse.history.HistoryService")
@patch("pulse.cli.console.print")
@patch("questionary.select")
def test_view_history_menu(mock_select, mock_print, mock_history_class, mock_render):
    mock_history = MagicMock()
    mock_history_class.return_value = mock_history
    
    mock_history.get_scan_runs.return_value = [
        {"id": 1, "timestamp": "2026-06-07 10:00:00", "score": 50, "packages": 10, "vulns": 2},
        {"id": 2, "timestamp": "2026-06-07 12:00:00", "score": 30, "packages": 10, "vulns": 1}
    ]
    
    mock_scan = MagicMock()
    mock_scan.findings = []
    mock_history.get_scan_by_id.return_value = mock_scan
    
    # Mock questionary selection
    mock_select.return_value.ask.return_value = "1. 2026-06-07 10:00:00 - Score: 50 (Pkgs: 10, Vulns: 2)"
    
    view_history_menu()
    
    from unittest.mock import ANY
    mock_history.get_scan_by_id.assert_called_once_with(1)
    mock_render.assert_called_once_with(ANY, mock_scan)

@patch("pulse.history.HistoryService")
@patch("pulse.cli.console.print")
def test_view_history_menu_no_scans(mock_print, mock_history_class):
    mock_history = MagicMock()
    mock_history_class.return_value = mock_history
    mock_history.get_scan_runs.return_value = []
    
    view_history_menu()
    mock_print.assert_called_with("\n[yellow]No scan history available.[/yellow]")
