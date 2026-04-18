#!/bin/sh
set -e

REPO="AhirTech1/zero-trust-hive"
INSTALL_DIR="/usr/local/bin"

echo "==> Detecting OS and Architecture..."
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "${OS}" in
    linux|darwin) ;;
    *) echo "✗ Error: Unsupported OS ${OS}"; exit 1 ;;
esac

case "${ARCH}" in
    x86_64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "✗ Error: Unsupported architecture ${ARCH}"; exit 1 ;;
esac

echo "==> Fetching latest release from GitHub API..."
RELEASE_JSON=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest")
VERSION=$(echo "$RELEASE_JSON" | grep -o '"tag_name": *"[^"]*"' | grep -o '"[^"]*"$' | tr -d '"')

if [ -z "$VERSION" ]; then
    echo "✗ Error: Could not fetch the latest release version."
    exit 1
fi

echo "==> Found version: ${VERSION}"

# Determine tarball name (GoReleaser format: zero-trust-hive_1.0.0_linux_amd64.tar.gz)
VERSION_NO_V="${VERSION#v}"
TARBALL="zero-trust-hive_${VERSION_NO_V}_${OS}_${ARCH}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${TARBALL}"

echo "==> Downloading ${DOWNLOAD_URL}..."
TMP_DIR=$(mktemp -d)
cd "$TMP_DIR"

HTTP_CODE=$(curl -sL -w "%{http_code}" -o "${TARBALL}" "${DOWNLOAD_URL}")

if [ "$HTTP_CODE" != "200" ]; then
    echo "✗ Error: Download failed with HTTP status ${HTTP_CODE}."
    cd - >/dev/null
    rm -rf "$TMP_DIR"
    exit 1
fi

echo "==> Extracting..."
tar -xzf "${TARBALL}" || {
    echo "✗ Error: Extraction failed."
    cd - >/dev/null
    rm -rf "$TMP_DIR"
    exit 1
}

echo "==> Installing binaries to ${INSTALL_DIR} (requires sudo)..."
sudo mkdir -p "${INSTALL_DIR}"

# Move binaries to PATH (handling both 'cli' or 'hive' names from goreleaser)
if [ -f "cli" ]; then
    sudo mv cli "${INSTALL_DIR}/hive"
elif [ -f "hive" ]; then
    sudo mv hive "${INSTALL_DIR}/hive"
fi

[ -f "gateway" ] && sudo mv gateway "${INSTALL_DIR}/gateway"
[ -f "agent" ] && sudo mv agent "${INSTALL_DIR}/agent"

# Ensure executable permissions
sudo chmod +x "${INSTALL_DIR}/hive" "${INSTALL_DIR}/gateway" "${INSTALL_DIR}/agent" 2>/dev/null || true

cd - >/dev/null
rm -rf "$TMP_DIR"

echo "==> ✓ Installation complete! Type 'hive' to get started."
