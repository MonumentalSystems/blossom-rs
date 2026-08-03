#!/usr/bin/env bash
set -euo pipefail

version="8.28.0"
platform="$(uname -s)"
machine="$(uname -m)"

case "${platform}-${machine}" in
  Darwin-arm64)
    archive="gitleaks_${version}_darwin_arm64.tar.gz"
    expected_sha256="d942f3ad147250c9edbaab3fed9e482f98d3b59ba10ae97b8d75647e3ade492c"
    ;;
  Darwin-x86_64)
    archive="gitleaks_${version}_darwin_x64.tar.gz"
    expected_sha256="edf5a507008b0d2ef4959575772772770586409c1f6f74dabf19cbe7ec341ced"
    ;;
  Linux-aarch64 | Linux-arm64)
    archive="gitleaks_${version}_linux_arm64.tar.gz"
    expected_sha256="eff65261156100e5d94a6b3dec313d532fddfe19ae1590bf7a2b4f2699128356"
    ;;
  Linux-x86_64)
    archive="gitleaks_${version}_linux_x64.tar.gz"
    expected_sha256="a65b5253807a68ac0cafa4414031fd740aeb55f54fb7e55f386acb52e6a840eb"
    ;;
  *)
    echo "Unsupported Gitleaks runner platform: ${platform}-${machine}" >&2
    exit 1
    ;;
esac

runner_temp="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
install_dir="$(mktemp -d "${runner_temp%/}/gitleaks.XXXXXX")"
archive_path="${install_dir}/${archive}"

curl --proto '=https' --tlsv1.2 -fsSLo "$archive_path" \
  "https://github.com/gitleaks/gitleaks/releases/download/v${version}/${archive}"

if command -v sha256sum >/dev/null 2>&1; then
  actual_sha256="$(sha256sum "$archive_path" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  actual_sha256="$(shasum -a 256 "$archive_path" | awk '{print $1}')"
else
  echo "No SHA-256 verification tool is available" >&2
  exit 1
fi

if [[ "$actual_sha256" != "$expected_sha256" ]]; then
  echo "Gitleaks archive checksum mismatch" >&2
  exit 1
fi

tar -xzf "$archive_path" -C "$install_dir" gitleaks
chmod 0755 "${install_dir}/gitleaks"
"${install_dir}/gitleaks" version

if [[ -n "${GITHUB_PATH:-}" ]]; then
  printf '%s\n' "$install_dir" >> "$GITHUB_PATH"
else
  printf 'Gitleaks installed at %s\n' "${install_dir}/gitleaks"
fi
