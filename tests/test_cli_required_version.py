import pytest
from unittest.mock import patch, MagicMock
from pulse.cli import scan_single_package_menu
from pulse.ecosystems.smart_detection import DetectionStatus

@patch("pulse.cli.questionary.text")
@patch("pulse.cli.console.print")
def test_empty_version_reprompts(mock_print, mock_text):
    # Mock sequence: package name, empty version, empty version, valid version
    mock_name = MagicMock()
    mock_name.ask.return_value = "Django"
    
    mock_empty1 = MagicMock()
    mock_empty1.ask.return_value = ""
    
    mock_empty2 = MagicMock()
    mock_empty2.ask.return_value = "   "
    
    mock_valid = MagicMock()
    mock_valid.ask.return_value = "3.2"
    
    mock_text.side_effect = [mock_name, mock_empty1, mock_empty2, mock_valid]
    
    with patch("pulse.ecosystems.smart_detection.SmartEcosystemDetector") as mock_detector:
        detector_instance = MagicMock()
        mock_result = MagicMock()
        mock_result.status = DetectionStatus.SUCCESS
        mock_result.provider = MagicMock()
        detector_instance.resolve_package.return_value = mock_result
        mock_detector.return_value = detector_instance
        
        with patch("pulse.cli.ScannerOrchestrator") as mock_orchestrator, \
             patch("pulse.cli.post_scan_render"), \
             patch("pulse.cli.post_scan_menu"):
            scan_single_package_menu()
            
            assert mock_text.call_count == 4
            warning_calls = [call for call in mock_print.call_args_list if "Package version is required." in str(call)]
            assert len(warning_calls) == 2
            
            # Ensure resolve_package was called only once with the valid version
            detector_instance.resolve_package.assert_called_once()
            args, _ = detector_instance.resolve_package.call_args
            assert args[2] == "3.2"

@patch("pulse.cli.questionary.text")
@patch("pulse.cli.console.print")
def test_latest_version_flow(mock_print, mock_text):
    mock_name = MagicMock()
    mock_name.ask.return_value = "Django"
    
    mock_latest = MagicMock()
    mock_latest.ask.return_value = "latest"
    
    mock_text.side_effect = [mock_name, mock_latest]
    
    with patch("pulse.ecosystems.smart_detection.SmartEcosystemDetector") as mock_detector:
        detector_instance = MagicMock()
        mock_result = MagicMock()
        mock_result.status = DetectionStatus.SUCCESS
        mock_result.provider = MagicMock()
        detector_instance.resolve_package.return_value = mock_result
        mock_detector.return_value = detector_instance
        
        with patch("pulse.cli.ScannerOrchestrator") as mock_orchestrator, \
             patch("pulse.cli.post_scan_render"), \
             patch("pulse.cli.post_scan_menu"):
            scan_single_package_menu()
            
            # Ensure resolve_package was called with None so it doesn't fail on "latest" string
            detector_instance.resolve_package.assert_called_once()
            args, _ = detector_instance.resolve_package.call_args
            assert args[2] is None
