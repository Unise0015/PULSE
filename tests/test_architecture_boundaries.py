import ast
from pathlib import Path
import pytest

SRC_DIR = Path(__file__).parent.parent / "src" / "pulse"

def get_pulse_imports(file_path: Path):
    """Parses AST of the file and extracts all imports starting with pulse."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=str(file_path))
    except Exception as e:
        pytest.fail(f"Failed to parse AST for {file_path}: {e}")
        
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for name in node.names:
                imports.append(name.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                module = node.module
                if node.level > 0:
                    # Resolve relative import
                    parts = file_path.parts
                    try:
                        idx = parts.index("pulse")
                        pkg_parts = list(parts[idx:-1])
                        if node.level > 1:
                            pkg_parts = pkg_parts[:-(node.level - 1)]
                        module = ".".join(pkg_parts) + "." + node.module
                    except ValueError:
                        pass
                imports.append(module)
    return [imp for imp in imports if imp.startswith("pulse") or imp == "pulse"]

def get_all_python_files(dir_path: Path):
    return [p for p in dir_path.rglob("*.py") if p.name != "__init__.py"]

def test_domain_has_no_internal_imports():
    """Verify that domain module imports nothing from other internal modules."""
    domain_dir = SRC_DIR / "domain"
    files = get_all_python_files(domain_dir)
    assert len(files) > 0, "No files found in domain/"
    
    for f in files:
        imports = get_pulse_imports(f)
        for imp in imports:
            # Domain must only import from within domain
            assert imp.startswith("pulse.domain"), \
                f"Domain file {f.name} violates architecture boundary by importing: {imp}"

def test_vulnerability_layer_boundaries():
    """Verify that vulnerability module does not import from higher modules."""
    vuln_dir = SRC_DIR / "vulnerability"
    files = get_all_python_files(vuln_dir)
    assert len(files) > 0, "No files found in vulnerability/"
    
    forbidden_prefixes = [
        "pulse.supply_chain",
        "pulse.website",
        "pulse.services",
        "pulse.scanner",
        "pulse.cli"
    ]
    
    for f in files:
        imports = get_pulse_imports(f)
        for imp in imports:
            for pref in forbidden_prefixes:
                assert not imp.startswith(pref), \
                    f"Vulnerability file {f.name} violates architecture boundary by importing: {imp}"

def test_supply_chain_layer_boundaries():
    """Verify that supply_chain module does not import from higher modules or sibling vulnerability/website/history."""
    sc_dir = SRC_DIR / "supply_chain"
    files = get_all_python_files(sc_dir)
    assert len(files) > 0, "No files found in supply_chain/"
    
    forbidden_prefixes = [
        "pulse.vulnerability",
        "pulse.website",
        "pulse.services",
        "pulse.scanner",
        "pulse.cli"
    ]
    
    for f in files:
        imports = get_pulse_imports(f)
        for imp in imports:
            for pref in forbidden_prefixes:
                assert not imp.startswith(pref), \
                    f"Supply Chain file {f.name} violates architecture boundary by importing: {imp}"

def test_website_layer_boundaries():
    """Verify that website module does not import from higher modules or sibling vulnerability/supply_chain/history."""
    web_dir = SRC_DIR / "website"
    files = get_all_python_files(web_dir)
    assert len(files) > 0, "No files found in website/"
    
    forbidden_prefixes = [
        "pulse.vulnerability",
        "pulse.supply_chain",
        "pulse.services",
        "pulse.scanner",
        "pulse.cli"
    ]
    
    for f in files:
        imports = get_pulse_imports(f)
        for imp in imports:
            for pref in forbidden_prefixes:
                assert not imp.startswith(pref), \
                    f"Website file {f.name} violates architecture boundary by importing: {imp}"

def test_history_layer_boundaries():
    """Verify that history module does not import from higher modules or sibling vulnerability/supply_chain/website."""
    history_dir = SRC_DIR / "history"
    files = get_all_python_files(history_dir)
    assert len(files) > 0, "No files found in history/"
    
    forbidden_prefixes = [
        "pulse.vulnerability",
        "pulse.supply_chain",
        "pulse.website",
        "pulse.services",
        "pulse.scanner",
        "pulse.cli"
    ]
    
    for f in files:
        imports = get_pulse_imports(f)
        for imp in imports:
            for pref in forbidden_prefixes:
                assert not imp.startswith(pref), \
                    f"History file {f.name} violates architecture boundary by importing: {imp}"

def test_cli_does_not_import_providers_directly():
    """Verify that cli does not import providers or vulnerability module directly."""
    cli_file = SRC_DIR / "cli.py"
    imports = get_pulse_imports(cli_file)
    
    forbidden_prefixes = [
        "pulse.vulnerability",
        "pulse.providers"
    ]
    
    for imp in imports:
        for pref in forbidden_prefixes:
            assert not imp.startswith(pref), \
                f"CLI file violates architecture boundary by importing providers directly: {imp}"

def test_no_legacy_imports():
    """Verify that no legacy shims or modules are imported anywhere in the codebase."""
    forbidden = [
        "pulse.models",
        "pulse.db",
        "pulse.providers",
        "pulse.sbom",
        "pulse.attack_paths",
        "pulse.dependency_analyzer",
        "pulse.website_fingerprint",
        "pulse.exploit_intelligence",
        "pulse.threat_mapping",
        "pulse.data_validation"
    ]
    
    # Check src directory
    src_files = [p for p in SRC_DIR.rglob("*.py") if p.name != "__init__.py"]
    # Check tests directory
    tests_dir = Path(__file__).parent
    test_files = [p for p in tests_dir.rglob("*.py") if p.name != "__init__.py" and p.name != "test_architecture_boundaries.py"]
    
    for f in src_files + test_files:
        imports = get_pulse_imports(f)
        for imp in imports:
            for forb in forbidden:
                assert not imp.startswith(forb), \
                    f"File {f.name} violates legacy boundary by importing: {imp}"
