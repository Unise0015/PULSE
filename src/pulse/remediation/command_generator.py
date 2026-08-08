def generate_upgrade_command(package: str, ecosystem: str, target_version: str, package_manager: str = "") -> str:
    """Generates an ecosystem-specific CLI upgrade command for a target version.
    
    Supported package managers & ecosystems:
    - Python (pip): pip install pkg==ver
    - Node.js (npm/pnpm/yarn): npm install pkg@ver / pnpm add pkg@ver / yarn add pkg@ver
    - PHP (composer): composer require pkg:ver
    - Rust (cargo): cargo add pkg@ver
    - Go: go get pkg@v1.2.3
    - Ruby (gems/bundler): bundle update pkg
    - .NET (nuget): dotnet add package Pkg --version ver
    - Java (maven): mvn versions:use-latest-releases
    """
    eco = (ecosystem or "").lower().strip()
    pm = (package_manager or "").lower().strip()
    
    if not target_version:
        return "N/A"
        
    ver = target_version.lstrip("v") if eco in ("go", "golang") else target_version

    # Node ecosystem variations
    if pm == "pnpm":
        return f"pnpm add {package}@{target_version}"
    if pm == "yarn":
        return f"yarn add {package}@{target_version}"
    if eco in ("npm", "node", "javascript", "js", "npm_package") or pm == "npm":
        return f"npm install {package}@{target_version}"

    # Python
    if eco in ("python", "pypi", "pip") or pm == "pip":
        return f"pip install {package}=={target_version}"

    # PHP Composer
    if eco in ("composer", "php", "packagist") or pm == "composer":
        return f"composer require {package}:{target_version}"

    # Rust Cargo
    if eco in ("cargo", "rust", "crates.io") or pm == "cargo":
        return f"cargo add {package}@{target_version}"

    # Go
    if eco in ("go", "golang") or pm == "go":
        go_ver = target_version if target_version.startswith("v") else f"v{target_version}"
        return f"go get {package}@{go_ver}"

    # Ruby
    if eco in ("ruby", "gem", "rubygems") or pm in ("bundle", "bundler", "gem"):
        return f"bundle update {package}"

    # .NET NuGet
    if eco in ("nuget", "dotnet", "c#", "csharp") or pm in ("dotnet", "nuget"):
        return f"dotnet add package {package} --version {target_version}"

    # Java Maven
    if eco in ("maven", "java") or pm == "maven":
        return f"mvn versions:use-latest-releases"

    # Default fallback
    return f"upgrade {package} to {target_version}"
