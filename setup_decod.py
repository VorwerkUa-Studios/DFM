"""
Decod Universal Environment & Dependency Installer:
Cross-platform setup wizard supporting:
- Windows 10 / Windows 11
- Void Linux (xbps)
- Fedora (dnf)
- Arch / Manjaro (pacman)
- Debian / Ubuntu (apt)

Provides JSON APIs and CLI flags for Mnemosyne (Rust GUI) to render checkboxes.
"""

import os
import sys
import platform
import shutil
import subprocess
import urllib.request
import zipfile
import tarfile
import io
import json
from typing import Dict, Any, List, Optional

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BIN_DIR = os.path.join(BASE_DIR, "bin")
os.makedirs(BIN_DIR, exist_ok=True)

PYTHON_PACKAGES = ["frida", "lief", "capstone", "psutil", "rich", "pydantic"]

GITHUB_RELEASES = {
    "repak": {
        "repo": "trumank/repak",
        "tag": "v0.2.3",
        "windows_zip": "https://github.com/trumank/repak/releases/download/v0.2.3/repak_cli-x86_64-pc-windows-msvc.zip",
        "linux_tar": "https://github.com/trumank/repak/releases/download/v0.2.3/repak_cli-x86_64-unknown-linux-gnu.tar.gz",
        "exe_name": "repak.exe" if os.name == "nt" else "repak"
    },
    "uesave": {
        "repo": "trumank/uesave",
        "tag": "v0.7.1",
        "windows_zip": "https://github.com/trumank/uesave/releases/download/v0.7.1/uesave_cli-x86_64-pc-windows-msvc.zip",
        "linux_tar": "https://github.com/trumank/uesave/releases/download/v0.7.1/uesave_cli-x86_64-unknown-linux-gnu.tar.gz",
        "exe_name": "uesave.exe" if os.name == "nt" else "uesave"
    }
}

def detect_distro() -> str:
    """Detect Linux distribution or Windows version."""
    sys_name = platform.system().lower()
    if sys_name == "windows":
        rel = platform.release()
        return f"Windows {rel}"

    # Check Linux releases
    if os.path.exists("/etc/void-release") or shutil.which("xbps-install"):
        return "Void Linux"
    elif os.path.exists("/etc/fedora-release") or shutil.which("dnf"):
        return "Fedora Linux"
    elif os.path.exists("/etc/arch-release") or shutil.which("pacman"):
        return "Arch Linux"
    elif os.path.exists("/etc/debian_version") or shutil.which("apt-get"):
        return "Debian/Ubuntu"

    return "Generic Linux"

def get_package_manager_cmd() -> Optional[List[str]]:
    distro = detect_distro()
    if "Void" in distro:
        return ["sudo", "xbps-install", "-S"]
    elif "Fedora" in distro:
        return ["sudo", "dnf", "install", "-y"]
    elif "Arch" in distro:
        return ["sudo", "pacman", "-S", "--noconfirm"]
    elif "Debian" in distro:
        return ["sudo", "apt-get", "install", "-y"]
    elif "Windows" in distro and shutil.which("winget"):
        return ["winget", "install"]
    return None

def check_status() -> Dict[str, Any]:
    """Check what components are currently installed or missing."""
    distro = detect_distro()

    # 1. Python packages
    py_status = {}
    for pkg in PYTHON_PACKAGES:
        try:
            __import__(pkg)
            py_status[pkg] = True
        except ImportError:
            py_status[pkg] = False

    # 2. UE5 binaries in Decod/bin
    ue_status = {}
    for name, cfg in GITHUB_RELEASES.items():
        bin_path = os.path.join(BIN_DIR, cfg["exe_name"])
        ue_status[name] = os.path.exists(bin_path)

    # 3. System tools
    sys_status = {
        "ffmpeg": shutil.which("ffmpeg") is not None,
        "ffprobe": shutil.which("ffprobe") is not None,
        "gcc": shutil.which("gcc") is not None
    }

    # 4. Linux stealth library
    libstealth_path = os.path.join(BASE_DIR, "stealth", "linux", "libstealth.so")
    stealth_status = os.path.exists(libstealth_path) if platform.system() != "Windows" else True

    return {
        "os": distro,
        "platform": platform.system(),
        "arch": platform.machine(),
        "components": {
            "python_deps": {
                "name": "Python Reverse Engineering Packages",
                "installed": all(py_status.values()),
                "details": py_status
            },
            "ue5_tools": {
                "name": "Unreal Engine 5 Modding Tools (repak, uesave)",
                "installed": all(ue_status.values()),
                "details": ue_status
            },
            "media_tools": {
                "name": "FFmpeg Multimedia Suite",
                "installed": sys_status["ffmpeg"] and sys_status["ffprobe"],
                "details": sys_status
            },
            "linux_stealth": {
                "name": "Linux Anti-Anti-Debug Library (libstealth.so)",
                "installed": stealth_status
            }
        }
    }

def install_python_deps():
    """Install missing Python packages."""
    print("[*] Installing Python packages...")
    cmd = [sys.executable, "-m", "pip", "install"] + PYTHON_PACKAGES
    subprocess.check_call(cmd)

def install_ue5_tools():
    """Download portable binaries for repak and uesave into Decod/bin."""
    is_win = platform.system() == "Windows"

    for name, cfg in GITHUB_RELEASES.items():
        target_path = os.path.join(BIN_DIR, cfg["exe_name"])
        if os.path.exists(target_path):
            print(f"[+] {name} already present at {target_path}")
            continue

        url = cfg["windows_zip"] if is_win else cfg["linux_tar"]
        print(f"[*] Downloading {name} from {url}...")

        req = urllib.request.Request(url, headers={"User-Agent": "Decod-Installer"})
        with urllib.request.urlopen(req) as resp:
            content = resp.read()

        if is_win:
            with zipfile.ZipFile(io.BytesIO(content)) as z:
                for f in z.namelist():
                    if f.endswith(".exe"):
                        with open(target_path, "wb") as out:
                            out.write(z.read(f))
                        print(f"[+] Extracted {target_path}")
        else:
            with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as tar:
                for member in tar.getmembers():
                    if member.name.endswith(name) or member.name.endswith(name + "_cli"):
                        f = tar.extractfile(member)
                        with open(target_path, "wb") as out:
                            out.write(f.read())
                        os.chmod(target_path, 0o755)
                        print(f"[+] Extracted {target_path}")

def build_linux_stealth():
    """Build libstealth.so on Linux using gcc."""
    if platform.system() == "Windows":
        return

    stealth_dir = os.path.join(BASE_DIR, "stealth", "linux")
    src = os.path.join(stealth_dir, "libstealth.c")
    out = os.path.join(stealth_dir, "libstealth.so")

    if not os.path.exists(src):
        return

    print("[*] Compiling libstealth.so...")
    cmd = ["gcc", "-Wall", "-Wextra", "-fPIC", "-shared", "-ldl", "-O2", "-o", out, src]
    subprocess.check_call(cmd)
    print(f"[+] Compiled {out}")

def main():
    if "--status" in sys.argv:
        status = check_status()
        print(json.dumps(status, indent=2))
        return

    if "--install-all" in sys.argv:
        print(f"[*] Starting Decod Setup for {detect_distro()}...")
        install_python_deps()
        install_ue5_tools()
        if platform.system() != "Windows":
            build_linux_stealth()
        print("\n[+] All Decod components successfully installed!")
        return

    print("Decod Universal Installer")
    print("Usage:")
    print("  python setup_decod.py --status       # Output component status as JSON")
    print("  python setup_decod.py --install-all  # Automatically install/download all missing parts")

if __name__ == "__main__":
    main()
