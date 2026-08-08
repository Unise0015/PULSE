import re
from typing import List, Optional
from pulse.version_intelligence.models import PackageManager, PackageManagerCommand

def _parse_major(version_str: str) -> Optional[int]:
    if not version_str:
        return None
    m = re.match(r"(\d+)", version_str.strip())
    return int(m.group(1)) if m else None

def _parse_minor_prefix(version_str: str) -> str:
    if not version_str:
        return "1.0"
    parts = version_str.strip().split(".")
    if len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}"
    return parts[0]

def generate_package_manager_commands(
    pkg_name: str,
    target_version: str,
    ecosystem: str
) -> List[PackageManagerCommand]:
    """Generate package-manager specific update commands based on detected ecosystem.
    
    The recommended command always uses exact version pinning to match the
    verified recommendation. Alternative range-based commands are provided
    as non-recommended options for Debug Mode and report output only.
    """
    eco = (ecosystem or "").lower()
    commands: List[PackageManagerCommand] = []

    if "python" in eco or "pypi" in eco:
        commands.append(
            PackageManagerCommand(
                manager=PackageManager.PIP,
                description="Exact version pin",
                command=f"pip install {pkg_name}=={target_version}",
                recommended=True
            )
        )
        commands.append(
            PackageManagerCommand(
                manager=PackageManager.PIP,
                description="Upgrade to latest available",
                command=f"pip install --upgrade {pkg_name}",
                recommended=False
            )
        )
        commands.append(
            PackageManagerCommand(
                manager=PackageManager.POETRY,
                description="Poetry package update",
                command=f"poetry add {pkg_name}=={target_version}",
                recommended=False
            )
        )
        commands.append(
            PackageManagerCommand(
                manager=PackageManager.UV,
                description="Fast uv package update",
                command=f"uv add {pkg_name}=={target_version}",
                recommended=False
            )
        )

    elif "npm" in eco or "node" in eco:
        commands.append(
            PackageManagerCommand(
                manager=PackageManager.NPM,
                description="npm versioned install",
                command=f"npm install {pkg_name}@{target_version}",
                recommended=True
            )
        )
        commands.append(
            PackageManagerCommand(
                manager=PackageManager.PNPM,
                description="pnpm versioned install",
                command=f"pnpm add {pkg_name}@{target_version}",
                recommended=False
            )
        )
        commands.append(
            PackageManagerCommand(
                manager=PackageManager.YARN,
                description="yarn versioned install",
                command=f"yarn add {pkg_name}@{target_version}",
                recommended=False
            )
        )

    elif "crates" in eco or "rust" in eco or "cargo" in eco:
        commands.append(
            PackageManagerCommand(
                manager=PackageManager.CARGO,
                description="Cargo dependency update",
                command=f"cargo add {pkg_name}@{target_version}",
                recommended=True
            )
        )

    elif "composer" in eco or "php" in eco or "packagist" in eco:
        commands.append(
            PackageManagerCommand(
                manager=PackageManager.COMPOSER,
                description="Composer exact version",
                command=f"composer require {pkg_name}:{target_version}",
                recommended=True
            )
        )

    elif "nuget" in eco or "dotnet" in eco or ".net" in eco:
        commands.append(
            PackageManagerCommand(
                manager=PackageManager.DOTNET,
                description=".NET package addition",
                command=f"dotnet add package {pkg_name} --version {target_version}",
                recommended=True
            )
        )

    elif "rubygems" in eco or "ruby" in eco:
        commands.append(
            PackageManagerCommand(
                manager=PackageManager.GEM,
                description="RubyGems version install",
                command=f"gem install {pkg_name} -v {target_version}",
                recommended=True
            )
        )

    elif "go" in eco or "golang" in eco:
        go_ver = target_version if target_version.startswith("v") else f"v{target_version}"
        commands.append(
            PackageManagerCommand(
                manager=PackageManager.PIP,
                description="Go module update",
                command=f"go get {pkg_name}@{go_ver}",
                recommended=True
            )
        )

    elif "maven" in eco or "java" in eco:
        commands.append(
            PackageManagerCommand(
                manager=PackageManager.PIP,
                description="Maven dependency update",
                command=f"Upgrade {pkg_name} to {target_version} in pom.xml",
                recommended=True
            )
        )

    else:
        commands.append(
            PackageManagerCommand(
                manager=PackageManager.PIP,
                description="Generic upgrade command",
                command=f"Upgrade {pkg_name} to {target_version}",
                recommended=True
            )
        )

    return commands
