import os
import platform
import subprocess
import glob
import logging
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Set
from pulse.domain.models import PackageInfo
from pulse.discoverers.system.base import BaseHostDiscoverer, HostSystemMetadata

logger = logging.getLogger(__name__)

def parse_os_release(os_release_path: Optional[Path] = None) -> Dict[str, str]:
    """Parse /etc/os-release or fallback locations."""
    data = {}
    paths = [os_release_path] if os_release_path else [
        Path("/etc/os-release"),
        Path("/usr/lib/os-release")
    ]
    for p in paths:
        if p and p.exists():
            try:
                for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        data[k.strip()] = v.strip().strip('"').strip("'")
                if data:
                    break
            except Exception as e:
                logger.debug(f"Failed to read os-release at {p}: {e}")
    return data

def normalize_distro_version(ver: str) -> str:
    """Normalize Debian/RPM epoch prefixes for clean version comparisons if needed."""
    if not ver:
        return ""
    return ver.strip()

class LinuxHostDiscoverer(BaseHostDiscoverer):
    """Discovers Linux host operating system packages and distro kernel."""

    def __init__(
        self,
        dpkg_status_path: Optional[Path] = None,
        apk_db_path: Optional[Path] = None,
        pacman_db_path: Optional[Path] = None,
        os_release_path: Optional[Path] = None
    ):
        self.dpkg_status_path = dpkg_status_path or Path("/var/lib/dpkg/status")
        self.apk_db_path = apk_db_path or Path("/lib/apk/db/installed")
        self.pacman_db_path = pacman_db_path or Path("/var/lib/pacman/local")
        self.os_release_path = os_release_path
        self._os_info = parse_os_release(self.os_release_path)

    def is_applicable(self) -> bool:
        return platform.system().lower() == "linux" or self.dpkg_status_path.exists() or self.apk_db_path.exists()

    def get_metadata(self) -> HostSystemMetadata:
        distro_id = self._os_info.get("ID", "linux").lower()
        distro_name = self._os_info.get("PRETTY_NAME", self._os_info.get("NAME", "Linux"))
        distro_version = self._os_info.get("VERSION_ID", self._os_info.get("VERSION", "unknown"))
        kernel_release = platform.release()

        # Identify package manager
        pkg_manager = "unknown"
        if self.dpkg_status_path.exists():
            pkg_manager = "dpkg/apt"
        elif self.apk_db_path.exists():
            pkg_manager = "apk"
        elif self.pacman_db_path.exists():
            pkg_manager = "pacman"
        elif Path("/var/lib/rpm").exists() or Path("/usr/bin/rpm").exists():
            pkg_manager = "rpm"

        return HostSystemMetadata(
            os_name=distro_name,
            os_family="linux",
            distro_id=distro_id,
            distro_version=distro_version,
            kernel_release=kernel_release,
            architecture=platform.machine(),
            package_manager=pkg_manager,
            extra={
                "id_like": self._os_info.get("ID_LIKE", ""),
                "kernel_uname": kernel_release
            }
        )

    def discover(self) -> List[PackageInfo]:
        packages: List[PackageInfo] = []

        # 1. Debian / Ubuntu / Kali / Parrot / Mint (dpkg)
        if self.dpkg_status_path.exists():
            dpkg_pkgs = self._parse_dpkg_status(self.dpkg_status_path)
            packages.extend(dpkg_pkgs)

        # 2. Alpine Linux (apk)
        elif self.apk_db_path.exists():
            apk_pkgs = self._parse_apk_installed(self.apk_db_path)
            packages.extend(apk_pkgs)

        # 3. Arch Linux / Manjaro (pacman)
        elif self.pacman_db_path.exists() and self.pacman_db_path.is_dir():
            pacman_pkgs = self._parse_pacman_db(self.pacman_db_path)
            packages.extend(pacman_pkgs)

        # 4. RPM distros (RHEL / Fedora / CentOS / Rocky / Alma / openSUSE)
        elif Path("/var/lib/rpm").exists() or Path("/usr/bin/rpm").exists():
            rpm_pkgs = self._parse_rpm_packages()
            packages.extend(rpm_pkgs)

        return packages

    def _parse_dpkg_status(self, path: Path) -> List[PackageInfo]:
        packages = []
        distro_id = self._os_info.get("ID", "debian").lower()
        # Canonicalize ecosystem name for OSV
        ecosystem = "Ubuntu" if "ubuntu" in distro_id else "Debian"

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            current_pkg: Dict[str, str] = {}

            for line in content.splitlines():
                line_stripped = line.strip()
                if not line_stripped:
                    # End of block
                    if current_pkg.get("Package") and current_pkg.get("Version"):
                        status = current_pkg.get("Status", "")
                        # Include if installed
                        if "installed" in status or not status:
                            pkg_name = current_pkg["Package"]
                            pkg_ver = current_pkg["Version"]
                            is_kernel = pkg_name.startswith("linux-image-") or pkg_name in ("linux-generic", "linux-image-generic")

                            packages.append(PackageInfo(
                                name=pkg_name,
                                version=pkg_ver,
                                ecosystem=ecosystem,
                                dependency_type="SYSTEM",
                                source_file=str(path),
                                metadata={
                                    "origin": "host",
                                    "package_manager": "dpkg",
                                    "is_kernel": is_kernel,
                                    "arch": current_pkg.get("Architecture", "")
                                }
                            ))
                    current_pkg = {}
                    continue

                if line.startswith("Package: "):
                    current_pkg["Package"] = line.split("Package: ", 1)[1].strip()
                elif line.startswith("Version: "):
                    current_pkg["Version"] = line.split("Version: ", 1)[1].strip()
                elif line.startswith("Status: "):
                    current_pkg["Status"] = line.split("Status: ", 1)[1].strip()
                elif line.startswith("Architecture: "):
                    current_pkg["Architecture"] = line.split("Architecture: ", 1)[1].strip()

            # Catch trailing record if no final newline
            if current_pkg.get("Package") and current_pkg.get("Version"):
                status = current_pkg.get("Status", "")
                if "installed" in status or not status:
                    pkg_name = current_pkg["Package"]
                    pkg_ver = current_pkg["Version"]
                    is_kernel = pkg_name.startswith("linux-image-") or pkg_name in ("linux-generic", "linux-image-generic")
                    packages.append(PackageInfo(
                        name=pkg_name,
                        version=pkg_ver,
                        ecosystem=ecosystem,
                        dependency_type="SYSTEM",
                        source_file=str(path),
                        metadata={
                            "origin": "host",
                            "package_manager": "dpkg",
                            "is_kernel": is_kernel,
                            "arch": current_pkg.get("Architecture", "")
                        }
                    ))
        except Exception as e:
            logger.error(f"Error parsing dpkg status at {path}: {e}")

        return packages

    def _parse_apk_installed(self, path: Path) -> List[PackageInfo]:
        packages = []
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            pkg_name = None
            pkg_ver = None
            pkg_arch = ""

            for line in content.splitlines():
                if line.startswith("P:"):
                    pkg_name = line[2:].strip()
                elif line.startswith("V:"):
                    pkg_ver = line[2:].strip()
                elif line.startswith("A:"):
                    pkg_arch = line[2:].strip()
                elif not line.strip() and pkg_name and pkg_ver:
                    is_kernel = pkg_name in ("linux-lts", "linux-virt", "linux-edge", "linux-vanilla")
                    packages.append(PackageInfo(
                        name=pkg_name,
                        version=pkg_ver,
                        ecosystem="Alpine",
                        dependency_type="SYSTEM",
                        source_file=str(path),
                        metadata={
                            "origin": "host",
                            "package_manager": "apk",
                            "is_kernel": is_kernel,
                            "arch": pkg_arch
                        }
                    ))
                    pkg_name = None
                    pkg_ver = None
                    pkg_arch = ""

            if pkg_name and pkg_ver:
                is_kernel = pkg_name in ("linux-lts", "linux-virt", "linux-edge", "linux-vanilla")
                packages.append(PackageInfo(
                    name=pkg_name,
                    version=pkg_ver,
                    ecosystem="Alpine",
                    dependency_type="SYSTEM",
                    source_file=str(path),
                    metadata={
                        "origin": "host",
                        "package_manager": "apk",
                        "is_kernel": is_kernel,
                        "arch": pkg_arch
                    }
                ))
        except Exception as e:
            logger.error(f"Error parsing apk db at {path}: {e}")

        return packages

    def _parse_pacman_db(self, path: Path) -> List[PackageInfo]:
        packages = []
        try:
            desc_files = list(path.glob("*/desc"))
            for desc_file in desc_files:
                try:
                    content = desc_file.read_text(encoding="utf-8", errors="ignore")
                    lines = content.splitlines()
                    pkg_name = None
                    pkg_ver = None
                    for i, line in enumerate(lines):
                        if line == "%NAME%" and i + 1 < len(lines):
                            pkg_name = lines[i + 1].strip()
                        elif line == "%VERSION%" and i + 1 < len(lines):
                            pkg_ver = lines[i + 1].strip()

                    if pkg_name and pkg_ver:
                        is_kernel = pkg_name in ("linux", "linux-lts", "linux-zen", "linux-hardened")
                        packages.append(PackageInfo(
                            name=pkg_name,
                            version=pkg_ver,
                            ecosystem="Arch",
                            dependency_type="SYSTEM",
                            source_file=str(desc_file),
                            metadata={
                                "origin": "host",
                                "package_manager": "pacman",
                                "is_kernel": is_kernel
                            }
                        ))
                except Exception:
                    continue
        except Exception as e:
            logger.error(f"Error parsing pacman db at {path}: {e}")

        return packages

    def _parse_rpm_packages(self) -> List[PackageInfo]:
        packages = []
        distro_id = self._os_info.get("ID", "rhel").lower()
        ecosystem = "RedHat" if any(x in distro_id for x in ("rhel", "centos", "rocky", "alma")) else "Fedora"

        try:
            res = subprocess.run(
                ["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"],
                capture_output=True,
                text=True,
                timeout=5.0
            )
            if res.returncode == 0 and res.stdout:
                for line in res.stdout.splitlines():
                    parts = line.strip().split("\t")
                    if len(parts) >= 2:
                        name = parts[0].strip()
                        ver = parts[1].strip()
                        arch = parts[2].strip() if len(parts) > 2 else ""
                        is_kernel = name in ("kernel", "kernel-core", "kernel-default", "kernel-devel")
                        packages.append(PackageInfo(
                            name=name,
                            version=ver,
                            ecosystem=ecosystem,
                            dependency_type="SYSTEM",
                            source_file="rpm-database",
                            metadata={
                                "origin": "host",
                                "package_manager": "rpm",
                                "is_kernel": is_kernel,
                                "arch": arch
                            }
                        ))
        except Exception as e:
            logger.debug(f"rpm query skipped or failed: {e}")

        return packages
