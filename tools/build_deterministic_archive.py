#!/usr/bin/env python3
"""Create a byte-reproducible Splunk .spl (tar.gz) application archive."""

import gzip
import pathlib
import sys
import tarfile


EXCLUDED_PARTS = {".DS_Store", "__MACOSX", "__pycache__"}


def excluded(path: pathlib.Path, root: pathlib.Path) -> bool:
    relative = path.relative_to(root)
    return any(
        part in EXCLUDED_PARTS
        or part.startswith("._")
        or part.endswith(".pyc")
        for part in relative.parts
    )


def normalized_info(tar: tarfile.TarFile, path: pathlib.Path, arcname: str):
    info = tar.gettarinfo(str(path), arcname=arcname)
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = 0
    info.pax_headers = {}
    return info


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: build_deterministic_archive.py APP_DIR OUTPUT_TMP")

    root = pathlib.Path(sys.argv[1]).resolve()
    output = pathlib.Path(sys.argv[2]).resolve()
    if not root.is_dir():
        raise SystemExit("application directory does not exist: " + str(root))
    if output == root or root in output.parents:
        raise SystemExit("output must be outside the application directory")

    paths = [root] + sorted(
        (path for path in root.rglob("*") if not excluded(path, root)),
        key=lambda path: path.relative_to(root).as_posix(),
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as raw_output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw_output, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for path in paths:
                    relative = path.relative_to(root)
                    arcname = root.name if relative == pathlib.Path(".") else (
                        root.name + "/" + relative.as_posix()
                    )
                    info = normalized_info(archive, path, arcname)
                    if info.isreg():
                        with path.open("rb") as source:
                            archive.addfile(info, source)
                    elif info.isdir() or info.issym() or info.islnk():
                        archive.addfile(info)
                    else:
                        raise SystemExit("unsupported archive member: " + str(path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
