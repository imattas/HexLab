#!/usr/bin/env python3
"""Wrap the relocatable macOS CPack tree in a Finder-launchable .app."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import shutil
import stat
import tarfile
import tempfile
import zipfile


def archive_path(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if path.is_absolute() or "\\" in name or any(part == ".." for part in path.parts):
        raise ValueError(f"unsafe package path: {name!r}")
    return path


def find_install_prefix(archive: tarfile.TarFile) -> tuple[str, ...]:
    prefixes = set()
    for member in archive.getmembers():
        parts = archive_path(member.name).parts
        if len(parts) >= 2 and parts[-2:] == ("bin", "hexlab") and member.isfile():
            prefixes.add(parts[:-2])
    if len(prefixes) != 1:
        raise ValueError("package must contain exactly one bin/hexlab executable")
    return next(iter(prefixes))


def safe_link_target(relative: PurePosixPath, linkname: str) -> None:
    target = PurePosixPath(linkname)
    if target.is_absolute() or "\\" in linkname:
        raise ValueError(f"unsafe symbolic link: {relative} -> {linkname}")
    stack = list(relative.parent.parts)
    for part in target.parts:
        if part in ("", "."):
            continue
        if part == "..":
            if not stack:
                raise ValueError(f"symbolic link escapes package: {relative} -> {linkname}")
            stack.pop()
        else:
            stack.append(part)


def extract_install_tree(archive: tarfile.TarFile, prefix: tuple[str, ...], destination: Path) -> None:
    selected: list[tuple[tarfile.TarInfo, PurePosixPath]] = []
    seen: set[PurePosixPath] = set()
    for member in archive.getmembers():
        path = archive_path(member.name)
        if path.parts[: len(prefix)] != prefix:
            continue
        tail = path.parts[len(prefix) :]
        if not tail:
            continue
        relative = PurePosixPath(*tail)
        if relative in seen:
            raise ValueError(f"duplicate package entry: {relative}")
        seen.add(relative)
        if member.isdir() or member.isfile():
            selected.append((member, relative))
        elif member.issym():
            safe_link_target(relative, member.linkname)
            selected.append((member, relative))
        else:
            raise ValueError(f"unsupported package entry type: {relative}")

    # Create regular files before symlinks so package links cannot redirect a
    # later extraction write outside the staging tree.
    selected.sort(key=lambda row: (row[0].issym(), len(row[1].parts), str(row[1])))
    for member, relative in selected:
        target = destination.joinpath(*relative.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        if member.isdir():
            target.mkdir(exist_ok=True)
            continue
        if member.issym():
            os.symlink(member.linkname, target)
            continue
        source = archive.extractfile(member)
        if source is None:
            raise ValueError(f"cannot read package file: {relative}")
        with source, target.open("wb") as output:
            shutil.copyfileobj(source, output)
        target.chmod(member.mode & 0o777)


def copy_tree(source: Path, destination: Path) -> None:
    if source.exists():
        shutil.copytree(source, destination, symlinks=True, dirs_exist_ok=True)


def zip_bundle(bundle: Path, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(bundle.rglob("*")):
            relative = path.relative_to(bundle.parent).as_posix()
            info = zipfile.ZipInfo(relative)
            info.create_system = 3
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(info, os.readlink(path))
            elif path.is_dir():
                info.external_attr = (stat.S_IFDIR | (mode & 0o777)) << 16
                archive.writestr(info, b"")
            else:
                info.external_attr = (stat.S_IFREG | (mode & 0o777)) << 16
                archive.writestr(info, path.read_bytes())


def create_bundle(archive_pathname: Path, output: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="hexlab-app-bundle-") as temporary:
        staging = Path(temporary)
        with tarfile.open(archive_pathname, "r:gz") as source:
            prefix = find_install_prefix(source)
            install_tree = staging / "install"
            install_tree.mkdir()
            extract_install_tree(source, prefix, install_tree)

        binary_dir = install_tree / "bin"
        library_dir = install_tree / "lib"
        if not (binary_dir / "hexlab").is_file() or not (binary_dir / "hexlab_cli").is_file():
            raise ValueError("package must contain both bin/hexlab and bin/hexlab_cli")
        if not library_dir.is_dir():
            raise ValueError("package is missing its lib/ runtime directory")
        manifest_path = install_tree / "share" / "hexlab" / "package-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        bundle = staging / "HexLab.app"
        contents = bundle / "Contents"
        macos = contents / "MacOS"
        macos.mkdir(parents=True)
        copy_tree(binary_dir, macos)
        copy_tree(library_dir, contents / "lib")
        copy_tree(install_tree / "share", contents / "Resources" / "share")
        copy_tree(install_tree / "include", contents / "Resources" / "include")

        manifest["layout"]["tools_directory"] = "Contents/MacOS"
        manifest["layout"]["runtime_directory"] = "Contents/lib"
        manifest["layout"]["headers_directory"] = "Contents/Resources/include"
        manifest["layout"]["documentation_directory"] = "Contents/Resources/share/hexlab/docs"
        manifest["layout"]["runtime_search_directory"] = "Contents/lib"
        bundled_manifest = contents / "Resources" / "share" / "hexlab" / "package-manifest.json"
        bundled_manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

        info = {
            "CFBundleDevelopmentRegion": "en",
            "CFBundleExecutable": "hexlab",
            "CFBundleIdentifier": "org.hexlab.HexLab",
            "CFBundleInfoDictionaryVersion": "6.0",
            "CFBundleName": "HexLab",
            "CFBundlePackageType": "APPL",
            "CFBundleShortVersionString": str(manifest.get("version", "0.1.0")),
            "CFBundleVersion": str(manifest.get("version", "0.1.0")),
            "LSApplicationCategoryType": "public.app-category.developer-tools",
            "NSHighResolutionCapable": True,
        }
        with (contents / "Info.plist").open("wb") as plist:
            plistlib.dump(info, plist, sort_keys=True)
        (contents / "PkgInfo").write_bytes(b"APPL????")
        zip_bundle(bundle, output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path, help="CPack relocatable macOS TGZ")
    parser.add_argument("--output", required=True, type=Path, help="output .app.zip path")
    args = parser.parse_args()
    create_bundle(args.archive, args.output)
    print(f"Created Finder app bundle: {args.output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, tarfile.TarError, json.JSONDecodeError) as error:
        raise SystemExit(f"Could not create HexLab.app: {error}")
