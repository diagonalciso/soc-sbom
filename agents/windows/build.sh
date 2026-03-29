#!/bin/bash
# Cross-compile SBOMGuard Windows agent from Linux.
# Requires Go: https://go.dev/dl/

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if ! command -v go &>/dev/null; then
    echo "ERROR: Go is not installed. Download from https://go.dev/dl/"
    exit 1
fi

echo "Fetching dependencies..."
go mod tidy

echo "Building sbom_agent.exe (windows/amd64)..."
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
    go build -ldflags="-s -w" -o sbom_agent.exe .

echo ""
echo "Built: $(pwd)/sbom_agent.exe"
ls -lh sbom_agent.exe
echo ""
echo "Deploy to Windows, then run:"
echo "  sbom_agent.exe -install          (register weekly task, admin required)"
echo "  sbom_agent.exe -dry-run          (test without uploading)"
echo "  sbom_agent.exe -server http://x  (override server)"
