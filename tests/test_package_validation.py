import pytest
from unittest.mock import patch, MagicMock
from pulse.cli import scan_single_package_menu
from pulse.ecosystems.smart_detection import DetectionResult, DetectionStatus, DetectionSource
from pulse.ecosystems.base import EcosystemPlugin, PluginManifest

@pytest.fixture
def mock_provider():
    provider = MagicMock(spec=EcosystemPlugin)
    provider.manifest = PluginManifest(id="python-pypi", name="Python", ecosystem="PyPI")
    provider.registry_name = "PyPI"
    provider.display_name = "Python"
    return provider

@pytest.fixture
def mock_provider_npm():
    provider = MagicMock(spec=EcosystemPlugin)
    provider.manifest = PluginManifest(id="nodejs-npm", name="Node.js", ecosystem="npm")
    provider.registry_name = "npm"
    provider.display_name = "Node.js"
    return provider

@patch("pulse.cli.questionary")
@patch("pulse.cli.console.print")
def test_invalid_package_reprompts(mock_print, mock_questionary, mock_provider):
    # Mock inputs:
    # 1. Package Name = "abcxyz"
    # 2. Version = "1.0"
    # 3. Choice = "B" (Back / Abort)
    
    mock_name = MagicMock()
    mock_name.ask.return_value = "abcxyz"
    
    mock_version = MagicMock()
    mock_version.ask.return_value = "1.0"
    
    mock_choice = MagicMock()
    mock_choice.ask.return_value = "B"
    
    # Set up questionary text and select
    def text_side_effect(prompt):
        if "Package" in prompt:
            return mock_name
        return mock_version
        
    mock_questionary.text.side_effect = text_side_effect
    mock_questionary.select.return_value = mock_choice
    
    with patch("pulse.ecosystems.smart_detection.SmartEcosystemDetector") as mock_detector_class:
        detector_instance = MagicMock()
        mock_result = DetectionResult(
            status=DetectionStatus.PACKAGE_NOT_FOUND,
            package_name="abcxyz",
            version="1.0"
        )
        detector_instance.resolve_package.return_value = mock_result
        mock_detector_class.return_value = detector_instance
        
        scan_single_package_menu()
        
        # Check that it printed the package not found message
        not_found_calls = [call for call in mock_print.call_args_list if "was not found in any supported registry" in str(call)]
        assert len(not_found_calls) >= 1

@patch("pulse.cli.questionary")
@patch("pulse.cli.console.print")
def test_invalid_version_reprompts_version_only(mock_print, mock_questionary, mock_provider):
    # Flow:
    # 1. Package = "flask"
    # 2. Version = "9.9.9"
    # 3. Next version loop -> version = "3.1.3"
    
    mock_name = MagicMock()
    mock_name.ask.return_value = "flask"
    
    mock_v1 = MagicMock()
    mock_v1.ask.return_value = "9.9.9"
    
    mock_v2 = MagicMock()
    mock_v2.ask.return_value = "3.1.3"
    
    text_calls = []
    def text_side_effect(prompt):
        if "Package Name" in prompt:
            text_calls.append("name")
            return mock_name
        if "Version" in prompt:
            text_calls.append("version")
            if text_calls.count("version") == 1:
                return mock_v1
            return mock_v2
        return MagicMock()
        
    mock_questionary.text.side_effect = text_side_effect
    
    with patch("pulse.ecosystems.smart_detection.SmartEcosystemDetector") as mock_detector_class:
        detector_instance = MagicMock()
        
        # First call returns VERSION_NOT_FOUND
        res1 = DetectionResult(
            status=DetectionStatus.VERSION_NOT_FOUND,
            package_name="flask",
            version="9.9.9",
            provider=mock_provider,
            registry_name="PyPI",
            latest_available_version="3.1.3"
        )
        
        # Second call returns SUCCESS
        res2 = DetectionResult(
            status=DetectionStatus.SUCCESS,
            package_name="flask",
            version="3.1.3",
            provider=mock_provider,
            registry_name="PyPI"
        )
        
        detector_instance.resolve_package.side_effect = [res1, res2]
        mock_detector_class.return_value = detector_instance
        
        with patch("pulse.cli.ScannerOrchestrator"), patch("pulse.cli.post_scan_render"), patch("pulse.cli.post_scan_menu"):
            scan_single_package_menu()
            
            # Check prints
            version_not_found = [call for call in mock_print.call_args_list if "Version \"9.9.9\" was not found." in str(call)]
            assert len(version_not_found) >= 1
            
            latest_ver = [call for call in mock_print.call_args_list if "Latest available version: 3.1.3" in str(call)]
            assert len(latest_ver) >= 1
            
            # Name should only be asked once!
            assert text_calls.count("name") == 1
            assert text_calls.count("version") == 2

@patch("pulse.cli.questionary")
@patch("pulse.cli.console.print")
def test_valid_package_auto_scans(mock_print, mock_questionary, mock_provider):
    mock_name = MagicMock()
    mock_name.ask.return_value = "django"
    mock_version = MagicMock()
    mock_version.ask.return_value = "3.2"
    
    def text_side_effect(prompt):
        return mock_name if "Package" in prompt else mock_version
    mock_questionary.text.side_effect = text_side_effect
    
    with patch("pulse.ecosystems.smart_detection.SmartEcosystemDetector") as mock_detector_class:
        detector_instance = MagicMock()
        res = DetectionResult(
            status=DetectionStatus.SUCCESS,
            package_name="django",
            version="3.2",
            provider=mock_provider,
            registry_name="PyPI"
        )
        detector_instance.resolve_package.return_value = res
        mock_detector_class.return_value = detector_instance
        
        with patch("pulse.cli.ScannerOrchestrator"), patch("pulse.cli.post_scan_render"), patch("pulse.cli.post_scan_menu"):
            scan_single_package_menu()
            
            success_calls = [call for call in mock_print.call_args_list if "found on PyPI" in str(call)]
            assert len(success_calls) >= 1
            
            # Select menu should NOT be called
            mock_questionary.select.assert_not_called()

@patch("pulse.cli.questionary")
@patch("pulse.cli.console.print")
def test_ambiguous_package_shows_menu(mock_print, mock_questionary, mock_provider, mock_provider_npm):
    mock_name = MagicMock()
    mock_name.ask.return_value = "redis"
    mock_version = MagicMock()
    mock_version.ask.return_value = "latest"
    
    def text_side_effect(prompt):
        return mock_name if "Package" in prompt else mock_version
    mock_questionary.text.side_effect = text_side_effect
    
    mock_choice = MagicMock()
    mock_choice.ask.return_value = "Python (PyPI)"
    mock_questionary.select.return_value = mock_choice
    
    with patch("pulse.ecosystems.smart_detection.SmartEcosystemDetector") as mock_detector_class:
        detector_instance = MagicMock()
        res = DetectionResult(
            status=DetectionStatus.AMBIGUOUS,
            package_name="redis",
            version="latest",
            candidates=[mock_provider, mock_provider_npm]
        )
        detector_instance.resolve_package.return_value = res
        mock_detector_class.return_value = detector_instance
        
        with patch("pulse.cli.ScannerOrchestrator"), patch("pulse.cli.post_scan_render"), patch("pulse.cli.post_scan_menu"):
            scan_single_package_menu()
            
            mock_questionary.select.assert_called_once()
            args, kwargs = mock_questionary.select.call_args
            assert "Python (PyPI)" in kwargs["choices"]
            assert "Node.js (npm)" in kwargs["choices"]

@patch("pulse.cli.questionary")
@patch("pulse.cli.console.print")
def test_registry_timeout_returns_network_error(mock_print, mock_questionary, mock_provider):
    mock_name = MagicMock()
    mock_name.ask.return_value = "requests"
    mock_version = MagicMock()
    mock_version.ask.return_value = "2.31.0"
    
    def text_side_effect(prompt):
        return mock_name if "Package" in prompt else mock_version
    mock_questionary.text.side_effect = text_side_effect
    
    with patch("pulse.ecosystems.smart_detection.SmartEcosystemDetector") as mock_detector_class:
        detector_instance = MagicMock()
        res = DetectionResult(
            status=DetectionStatus.NETWORK_ERROR,
            package_name="requests",
            version="2.31.0",
            candidates=[mock_provider]
        )
        detector_instance.resolve_package.return_value = res
        mock_detector_class.return_value = detector_instance
        
        with patch("pulse.cli.ScannerOrchestrator"), patch("pulse.cli.post_scan_render"), patch("pulse.cli.post_scan_menu"):
            scan_single_package_menu()
            
            network_calls = [call for call in mock_print.call_args_list if "registry services are unavailable" in str(call)]
            assert len(network_calls) >= 1
            
            # Since candidates has 1, it should proceed using heuristic detection and auto-scan
            heuristic_calls = [call for call in mock_print.call_args_list if "Proceeding using heuristic detection" in str(call)]
            assert len(heuristic_calls) >= 1