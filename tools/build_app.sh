#!/bin/bash
set -euo pipefail

project_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
app_name=TA_au2_linux
version=1.4.8
package_dir="$project_dir/package"
dist_dir="$project_dir/dist"
artifact="$dist_dir/$app_name-$version.spl"
tmp_artifact="$artifact.tmp"

python3 "$project_dir/tools/compile_verification.py"
python3 "$project_dir/tools/validate_app.py" "$package_dir/$app_name"
mkdir -p "$dist_dir"
rm -f "$tmp_artifact"
trap 'rm -f "$tmp_artifact"' EXIT HUP INT TERM

python3 "$project_dir/tools/build_deterministic_archive.py" \
  "$package_dir/$app_name" \
  "$tmp_artifact"

mv "$tmp_artifact" "$artifact"
trap - EXIT HUP INT TERM

python3 "$project_dir/tools/validate_app.py" "$package_dir/$app_name" --archive "$artifact"
python3 "$project_dir/tools/write_checksums.py"
echo "Built $artifact"
