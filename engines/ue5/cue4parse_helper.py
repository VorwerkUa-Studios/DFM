"""Headless CUE4Parse integration for Unreal PAK and IoStore archives."""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict


BASE_DIR = Path(__file__).resolve().parents[2]
CUE4PARSE_PROJECT = BASE_DIR / "tools" / "ue5" / "cue4parse_cli" / "Decod.Cue4Parse.csproj"


def _resolve_paks_directory(game_root: str) -> Path:
    root = Path(game_root)
    if not root.exists():
        raise FileNotFoundError(f"Unreal game root not found: {game_root}")

    candidates = [
        root / "Content" / "Paks",
        root / "Stalker2" / "Content" / "Paks",
        root,
    ]
    for candidate in candidates:
        if candidate.is_dir() and (
            any(candidate.glob("*.utoc")) or any(candidate.glob("*.pak"))
        ):
            return candidate.resolve()
    raise FileNotFoundError(f"No .utoc or .pak files found under: {game_root}")


def scan_ue_iostore_assets(
    game_root: str,
    output_path: str,
    filter_query: str = "",
    max_results: int = 2000,
    game_version: str = "GAME_UE5_5",
    probe_asset: str = "",
    package_type: str = "all",
    extract_dir: str = "",
    batch_probe_assets: list[str] | None = None,
) -> Dict[str, Any]:
    """Index Unreal package names and optionally parse one package through CUE4Parse."""
    if max_results < 1 or max_results > 100_000:
        raise ValueError("max_results must be between 1 and 100000")
    if package_type not in {"all", "maps", "assets"}:
        raise ValueError("package_type must be 'all', 'maps', or 'assets'")
    if extract_dir and not probe_asset:
        if not batch_probe_assets:
            raise ValueError("probe_asset is required unless batch_probe_assets is supplied when extract_dir is set")
    if batch_probe_assets is not None:
        if probe_asset:
            raise ValueError("probe_asset and batch_probe_assets cannot be used together")
        if not extract_dir:
            raise ValueError("extract_dir is required when batch_probe_assets is set")
        batch_probe_assets = list(dict.fromkeys(asset.strip() for asset in batch_probe_assets))
        if not batch_probe_assets or any(not asset for asset in batch_probe_assets):
            raise ValueError("batch_probe_assets must contain non-empty package paths")
    if not CUE4PARSE_PROJECT.is_file():
        raise FileNotFoundError(f"CUE4Parse CLI project not found: {CUE4PARSE_PROJECT}")
    dotnet = shutil.which("dotnet")
    if not dotnet:
        raise RuntimeError(".NET SDK is required to run the Decod CUE4Parse CLI")

    paks_directory = _resolve_paks_directory(game_root)
    output = Path(output_path).resolve()
    batch_temp = tempfile.TemporaryDirectory() if batch_probe_assets is not None else None
    try:
        if batch_temp is not None:
            manifest_path = Path(batch_temp.name) / "probe-assets.json"
            manifest_path.write_text(json.dumps(batch_probe_assets), encoding="utf-8")
            probe_asset = f"@batch:{manifest_path}"
        command = [
            dotnet,
            "run",
            "--project",
            str(CUE4PARSE_PROJECT),
            "--",
            str(paks_directory),
            str(output),
            game_version,
            filter_query,
            str(max_results),
            probe_asset,
            package_type,
            extract_dir,
        ]
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=3600,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("CUE4Parse IoStore scan exceeded its 60-minute time limit") from error
    finally:
        if batch_temp is not None:
            batch_temp.cleanup()
    if result.returncode != 0:
        detail = "\n".join(part.strip() for part in (result.stderr, result.stdout) if part.strip())
        raise RuntimeError(
            f"CUE4Parse IoStore scan failed with exit code {result.returncode}: {detail[-3000:]}"
        )

    output_lines = [line for line in result.stdout.splitlines() if line.strip()]
    if not output_lines:
        raise RuntimeError("CUE4Parse IoStore scan completed without a JSON summary")
    try:
        summary = json.loads(output_lines[-1])
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"CUE4Parse IoStore scan returned invalid JSON: {output_lines[-1][-1000:]}"
        ) from error
    if summary.get("status") != "success":
        raise RuntimeError(f"CUE4Parse IoStore scan did not succeed: {summary}")
    return summary
