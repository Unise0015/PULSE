"""
Linux Host System Discovery for PULSE.

Discovers all installed packages, kernel version, and system metadata
on Debian/Ubuntu/Kali, Alpine, Arch, and RPM-based Linux distributions.

Discovery Strategy:
  1. PRIMARY: Use package manager CLI commands (dpkg-query, apk, pacman, rpm)
     which are the most reliable and always-current source of truth.
  2. FALLBACK: Parse package database files directly if commands are unavailable.
  3. KERNEL: Always detect via platform.release() / uname for display,
     but use the distro kernel PACKAGE entry for CVE matching (avoids
     backport false positives).
"""

import platform
import subprocess
import shutil
import logging
from pathlib import Path
from typing import List, Dict, Optional
from pulse.domain.models import PackageInfo
from pulse.discoverers.system.base import BaseHostDiscoverer, HostSystemMetadata

logger = logging.getLogger(__name__)

# ── OS Release Parser ─────────────────────────────────────────────────────────

def parse_os_release(os_release_path: Optional[Path] = None) -> Dict[str, str]:
    """Parse /etc/os-release to identify the Linux distribution."""
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


# ── Distro Ecosystem Mapping ──────────────────────────────────────────────────

def get_osv_ecosystem(os_info: Dict[str, str]) -> str:
    """Map the Linux distro ID to the correct OSV ecosystem name."""
    distro_id = os_info.get("ID", "").lower()
    id_like = os_info.get("ID_LIKE", "").lower()

    if distro_id == "ubuntu" or "ubuntu" in id_like:
        return "Ubuntu"
    if distro_id in ("debian", "kali", "parrot", "raspbian") or "debian" in id_like:
        return "Debian"
    if distro_id == "alpine":
        return "Alpine"
    if distro_id in ("arch", "manjaro", "endeavouros") or "arch" in id_like:
        return "Arch"

    return "Debian"  # Safe default for unknown Debian-derivatives


# ── Main Discoverer ───────────────────────────────────────────────────────────

class LinuxHostDiscoverer(BaseHostDiscoverer):
    """Discovers Linux host OS packages, kernel, and system metadata.

    On Kali/Debian/Ubuntu:
      Primary:  dpkg-query -W -f='${Package}\\t${Version}\\t${Architecture}\\t${db:Status-Abbrev}\\n'
      Fallback: Parse /var/lib/dpkg/status directly.

    On Alpine:
      Primary:  Parse /lib/apk/db/installed (no subprocess needed).

    On Arch:
      Primary:  Parse /var/lib/pacman/local/*/desc (no subprocess needed).

    On RPM distros:
      Primary:  rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n'
    """

    DPKG_KERNEL_PREFIXES = ("linux-image-",)
    DPKG_KERNEL_EXACT = ("linux-generic", "linux-image-generic")
    APK_KERNEL_NAMES = {"linux-lts", "linux-virt", "linux-edge", "linux-vanilla"}
    PACMAN_KERNEL_NAMES = {"linux", "linux-lts", "linux-zen", "linux-hardened"}
    RPM_KERNEL_NAMES = {"kernel", "kernel-core", "kernel-default", "kernel-devel"}

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
        if platform.system().lower() != "linux":
            return False
        return (
            self.dpkg_status_path.exists()
            or self.apk_db_path.exists()
            or self.pacman_db_path.exists()
            or shutil.which("dpkg-query") is not None
            or shutil.which("rpm") is not None
        )

    def get_metadata(self) -> HostSystemMetadata:
        distro_name = self._os_info.get("PRETTY_NAME",
                        self._os_info.get("NAME", "Linux"))
        distro_id = self._os_info.get("ID", "linux").lower()
        distro_version = self._os_info.get("VERSION_ID",
                          self._os_info.get("VERSION", "unknown"))
        kernel_release = platform.release()

        pkg_manager = "unknown"
        if self.dpkg_status_path.exists() or shutil.which("dpkg-query"):
            pkg_manager = "dpkg/apt"
        elif self.apk_db_path.exists():
            pkg_manager = "apk"
        elif self.pacman_db_path.exists():
            pkg_manager = "pacman"
        elif shutil.which("rpm"):
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
        ecosystem = get_osv_ecosystem(self._os_info)

        # Debian / Ubuntu / Kali
        if self.dpkg_status_path.exists() or shutil.which("dpkg-query"):
            pkgs = self._discover_dpkg(ecosystem)
            if pkgs:
                packages.extend(pkgs)
                logger.info(f"System Discovery: Found {len(pkgs)} dpkg packages ({ecosystem})")
                return packages

        # Alpine
        if self.apk_db_path.exists():
            pkgs = self._parse_apk_installed(self.apk_db_path)
            if pkgs:
                packages.extend(pkgs)
                logger.info(f"System Discovery: Found {len(pkgs)} apk packages")
                return packages

        # Arch / Manjaro
        if self.pacman_db_path.exists() and self.pacman_db_path.is_dir():
            pkgs = self._parse_pacman_db(self.pacman_db_path)
            if pkgs:
                packages.extend(pkgs)
                logger.info(f"System Discovery: Found {len(pkgs)} pacman packages")
                return packages

        # RPM (RHEL / Fedora / CentOS)
        if shutil.which("rpm"):
            pkgs = self._discover_rpm(ecosystem)
            if pkgs:
                packages.extend(pkgs)
                logger.info(f"System Discovery: Found {len(pkgs)} rpm packages")
                return packages

        return packages

    # ── Debian / Ubuntu / Kali ────────────────────────────────────────────────

    def _discover_dpkg(self, ecosystem: str) -> List[PackageInfo]:
        if shutil.which("dpkg-query"):
            pkgs = self._query_dpkg_command(ecosystem)
            if pkgs:
                return pkgs
        if self.dpkg_status_path.exists():
            return self._parse_dpkg_status(self.dpkg_status_path, ecosystem)
        return []

    def _query_dpkg_command(self, ecosystem: str) -> List[PackageInfo]:
        packages = []
        try:
            result = subprocess.run(
                ["dpkg-query", "-W",
                 r"-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n"],
                capture_output=True, text=True, timeout=10.0
            )
            if result.returncode != 0:
                return []

            for line in result.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = line.split("\t")
                if len(parts) < 3:
                    continue

                name = parts[0].strip()
                version = parts[1].strip()
                arch = parts[2].strip()
                status = parts[3].strip() if len(parts) > 3 else ""

                if status and not status.startswith("ii"):
                    continue
                if not name or not version:
                    continue

                is_kernel = (
                    any(name.startswith(p) for p in self.DPKG_KERNEL_PREFIXES)
                    or name in self.DPKG_KERNEL_EXACT
                )

                packages.append(PackageInfo(
                    name=name, version=version,
                    ecosystem=ecosystem, dependency_type="SYSTEM",
                    source_file="dpkg-query",
                    metadata={"origin": "host", "package_manager": "dpkg",
                              "is_kernel": is_kernel, "arch": arch}
                ))

        except subprocess.TimeoutExpired:
            logger.warning("dpkg-query timed out after 10s")
        except FileNotFoundError:
            logger.debug("dpkg-query not found")
        except Exception as e:
            logger.error(f"dpkg-query failed: {e}")

        return packages

    def _parse_dpkg_status(self, path: Path, ecosystem: str) -> List[PackageInfo]:
        packages = []
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            current_pkg: Dict[str, str] = {}

            for line in content.splitlines():
                if not line.strip():
                    if current_pkg.get("Package") and current_pkg.get("Version"):
                        status = current_pkg.get("Status", "")
                        if "install ok installed" in status or not status:
                            name = current_pkg["Package"]
                            version = current_pkg["Version"]
                            is_kernel = (
                                any(name.startswith(p) for p in self.DPKG_KERNEL_PREFIXES)
                                or name in self.DPKG_KERNEL_EXACT
                            )
                            packages.append(PackageInfo(
                                name=name, version=version,
                                ecosystem=ecosystem, dependency_type="SYSTEM",
                                source_file=str(path),
                                metadata={"origin": "host", "package_manager": "dpkg",
                                          "is_kernel": is_kernel,
                                          "arch": current_pkg.get("Architecture", "")}
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

            if current_pkg.get("Package") and current_pkg.get("Version"):
                status = current_pkg.get("Status", "")
                if "install ok installed" in status or not status:
                    name = current_pkg["Package"]
                    version = current_pkg["Version"]
                    is_kernel = (
                        any(name.startswith(p) for p in self.DPKG_KERNEL_PREFIXES)
                        or name in self.DPKG_KERNEL_EXACT
                    )
                    packages.append(PackageInfo(
                        name=name, version=version,
                        ecosystem=ecosystem, dependency_type="SYSTEM",
                        source_file=str(path),
                        metadata={"origin": "host", "package_manager": "dpkg",
                                  "is_kernel": is_kernel,
                                  "arch": current_pkg.get("Architecture", "")}
                    ))
        except Exception as e:
            logger.error(f"Error parsing dpkg status at {path}: {e}")

        return packages

    # ── Alpine ────────────────────────────────────────────────────────────────

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
                    is_kernel = pkg_name in self.APK_KERNEL_NAMES
                    packages.append(PackageInfo(
                        name=pkg_name, version=pkg_ver,
                        ecosystem="Alpine", dependency_type="SYSTEM",
                        source_file=str(path),
                        metadata={"origin": "host", "package_manager": "apk",
                                  "is_kernel": is_kernel, "arch": pkg_arch}
                    ))
                    pkg_name = None
                    pkg_ver = None
                    pkg_arch = ""

            if pkg_name and pkg_ver:
                is_kernel = pkg_name in self.APK_KERNEL_NAMES
                packages.append(PackageInfo(
                    name=pkg_name, version=pkg_ver,
                    ecosystem="Alpine", dependency_type="SYSTEM",
                    source_file=str(path),
                    metadata={"origin": "host", "package_manager": "apk",
                              "is_kernel": is_kernel, "arch": pkg_arch}
                ))
        except Exception as e:
            logger.error(f"Error parsing apk db at {path}: {e}")
        return packages

    # ── Arch / Manjaro ────────────────────────────────────────────────────────

    def _parse_pacman_db(self, path: Path) -> List[PackageInfo]:
        packages = []
        try:
            for desc_file in path.glob("*/desc"):
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
                        is_kernel = pkg_name in self.PACMAN_KERNEL_NAMES
                        packages.append(PackageInfo(
                            name=pkg_name, version=pkg_ver,
                            ecosystem="Arch", dependency_type="SYSTEM",
                            source_file=str(desc_file),
                            metadata={"origin": "host", "package_manager": "pacman",
                                      "is_kernel": is_kernel}
                        ))
                except Exception:
                    continue
        except Exception as e:
            logger.error(f"Error parsing pacman db at {path}: {e}")
        return packages

    # ── RPM (RHEL / Fedora / CentOS) ──────────────────────────────────────────

    def _discover_rpm(self, ecosystem: str) -> List[PackageInfo]:
        packages = []
        try:
            result = subprocess.run(
                ["rpm", "-qa", r"--qf", r"%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"],
                capture_output=True, text=True, timeout=10.0
            )
            if result.returncode == 0 and result.stdout:
                for line in result.stdout.splitlines():
                    parts = line.strip().split("\t")
                    if len(parts) >= 2:
                        name = parts[0].strip()
                        ver = parts[1].strip()
                        arch = parts[2].strip() if len(parts) > 2 else ""
                        is_kernel = name in self.RPM_KERNEL_NAMES
                        packages.append(PackageInfo(
                            name=name, version=ver,
                            ecosystem=ecosystem, dependency_type="SYSTEM",
                            source_file="rpm-database",
                            metadata={"origin": "host", "package_manager": "rpm",
                                      "is_kernel": is_kernel, "arch": arch}
                        ))
        except Exception as e:
            logger.debug(f"rpm query skipped or failed: {e}")
        return packages
