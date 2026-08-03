#!/usr/bin/env python3
"""Build the deterministic, credential-free flagship recipe test site."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path


MARKER = ".bridgefu-demo-site-build"
ZIP_TIME = (1980, 1, 1, 0, 0, 0)
PUBLIC_FILES = ("index.html", "style.css", "app.js", "app.js.LEGAL.txt")
RELEASE_STAGING_MARKER = ".bridgefu-release-staging"


def output_is_allowed(
    output: Path, repository_root: Path, release_staging_root: Path | None
) -> bool:
    """Allow normal target builds or a marker-bound release staging directory."""
    resolved_output = output.resolve()
    target = (repository_root / "target").resolve()
    if resolved_output != target and target in resolved_output.parents:
        return True
    if release_staging_root is None:
        return False
    staging = release_staging_root.resolve()
    marker = staging / RELEASE_STAGING_MARKER
    return (
        resolved_output != staging
        and staging in resolved_output.parents
        and marker.is_file()
        and not marker.is_symlink()
        and marker.read_text(encoding="utf-8")
        == "bridgefu recipe release staging\n"
    )


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def installed_packages(node_modules: Path) -> list[dict[str, str]]:
    packages: list[dict[str, str]] = []
    for manifest in sorted(node_modules.glob("*/package.json")) + sorted(
        node_modules.glob("@*/*/package.json")
    ):
        value = json.loads(manifest.read_text(encoding="utf-8"))
        name = value.get("name")
        version = value.get("version")
        license_name = value.get("license", "UNKNOWN")
        if isinstance(name, str) and isinstance(version, str):
            packages.append(
                {
                    "name": name,
                    "version": version,
                    "license": license_name
                    if isinstance(license_name, str)
                    else "SEE-PACKAGE",
                }
            )
    return sorted(packages, key=lambda item: (item["name"], item["version"]))


def zip_file(source: Path, output: Path, names: tuple[str, ...]) -> None:
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in names:
            info = zipfile.ZipInfo(name, ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, (source / name).read_bytes())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("target/recipe-demo-site"))
    parser.add_argument("--release-staging-root", type=Path)
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    source = root / "recipes" / "vapi-amazon-connect-screen-pop" / "demo-site"
    output = args.output if args.output.is_absolute() else root / args.output
    if not output_is_allowed(output, root, args.release_staging_root):
        raise SystemExit(
            "demo-site output must be inside the repository target directory or "
            "the active release staging directory"
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    work = Path(tempfile.mkdtemp(prefix="bridgefu-demo-site-"))
    try:
        shutil.copyfile(source / "package.json", work / "package.json")
        shutil.copyfile(source / "package-lock.json", work / "package-lock.json")
        subprocess.run(
            [
                "npm",
                "ci",
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
            ],
            cwd=work,
            check=True,
            stdout=subprocess.DEVNULL,
        )
        public = work / "public"
        public.mkdir()
        app_source = work / "app.js"
        shutil.copyfile(source / "src" / "app.js", app_source)
        shutil.copyfile(source / "index.html", public / "index.html")
        shutil.copyfile(source / "style.css", public / "style.css")
        subprocess.run(
            [
                os.fspath(work / "node_modules" / ".bin" / "esbuild"),
                os.fspath(app_source),
                "--bundle",
                "--format=esm",
                "--platform=browser",
                "--target=es2022",
                "--minify",
                "--legal-comments=external",
                f"--outfile={public / 'app.js'}",
            ],
            cwd=work,
            check=True,
            stdout=subprocess.DEVNULL,
        )
        legal_comments = public / "app.js.LEGAL.txt"
        if not legal_comments.is_file():
            legal_comments.write_text(
                "Third-party package names, versions, and license identifiers are in "
                "third-party-licenses.json.\n",
                encoding="utf-8",
            )
        licenses = {
            "schema_version": 1,
            "generated_from": "demo-site/package-lock.json",
            "packages": installed_packages(work / "node_modules"),
        }
        (public / "third-party-licenses.json").write_text(
            json.dumps(licenses, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        names = PUBLIC_FILES + ("third-party-licenses.json",)
        archive = staging / "demo-site.zip"
        zip_file(public, archive, names)
        manifest = {
            "schema_version": 1,
            "recipe": "vapi-amazon-connect-screen-pop@1",
            "package_lock_sha256": digest(source / "package-lock.json"),
            "archive_sha256": digest(archive),
            "files": [
                {
                    "path": name,
                    "sha256": digest(public / name),
                    "size_bytes": (public / name).stat().st_size,
                }
                for name in names
            ],
        }
        (staging / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (staging / MARKER).write_text("bridgefu recipe demo-site build\n", encoding="utf-8")
        if output.exists():
            if not (output / MARKER).is_file():
                raise SystemExit(f"refusing to replace unmarked output directory: {output}")
            shutil.rmtree(output)
        staging.replace(output)
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        raise
    finally:
        shutil.rmtree(work, ignore_errors=True)
    print(output / "demo-site.zip")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
