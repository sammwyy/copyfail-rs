#!/bin/bash

# Configuration
BINARY_URL="https://github.com/sammwyy/copyfail-rs/releases/download/poc/copyfail-rs_x86-64"

# Create a temporary directory and ensure it's deleted on exit
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

# Download the binary
echo "[+] Downloading PoC binary..."
if ! curl -L "$BINARY_URL" -o "$TMP_DIR/copyfail-rs" 2>/dev/null; then
    echo "[-] Failed to download binary. Please check your internet connection."
    exit 1
fi

# Set executable permissions
chmod +x "$TMP_DIR/copyfail-rs"

# Run the binary with passed arguments
echo "[+] Running copyfail-rs..."
"$TMP_DIR/copyfail-rs" "$@"
