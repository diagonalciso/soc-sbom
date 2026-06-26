#!/bin/bash
# SBOMGuard Linux agent installer — adds a weekly cron job.
#
# Usage:  ./install.sh [SERVER_URL]
# Default server: http://10.10.0.40:8082/api/sbom

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT="$SCRIPT_DIR/sbom_agent.py"
SERVER="${1:-http://10.10.0.40:8082/api/sbom/import}"
LOG="/var/log/sbomguard_agent.log"

if [ ! -f "$AGENT" ]; then
    echo "ERROR: sbom_agent.py not found at $AGENT"
    exit 1
fi

chmod +x "$AGENT"

# Run every Sunday at 02:00
CRON_LINE="0 2 * * 0 python3 $AGENT --server $SERVER >> $LOG 2>&1"

# Remove any existing SBOMGuard line, then add fresh
( crontab -l 2>/dev/null | grep -v "sbom_agent" ) | crontab - || true
( crontab -l 2>/dev/null; echo "$CRON_LINE" ) | crontab -

echo "Installed: weekly cron (Sun 02:00)"
echo "  server : $SERVER"
echo "  log    : $LOG"
echo ""
echo "Run now  : python3 $AGENT"
echo "Dry run  : python3 $AGENT --dry-run"
echo "Remove   : crontab -e  (delete the sbom_agent line)"
