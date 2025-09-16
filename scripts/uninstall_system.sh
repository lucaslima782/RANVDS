#!/usr/bin/env bash
set -euo pipefail

# System uninstaller for RANVDS
# - Removes /usr/local/bin/ranvds
# - Optionally purges /usr/local/share/ranvds and /usr/local/etc/ranvds when --purge is given
# Usage:
#   sudo scripts/uninstall_system.sh [--purge]

if [[ ${EUID} -ne 0 ]]; then
  echo "Please run as root (use sudo)." >&2
  exit 1
fi

PURGE=${1:-""}

if [[ -f /usr/local/bin/ranvds ]]; then
  rm -f /usr/local/bin/ranvds
  echo "Removed /usr/local/bin/ranvds"
else
  echo "/usr/local/bin/ranvds not found (already removed?)"
fi

if [[ "$PURGE" == "--purge" ]]; then
  if [[ -d /usr/local/share/ranvds ]]; then
    rm -rf /usr/local/share/ranvds
    echo "Purged /usr/local/share/ranvds"
  else
    echo "/usr/local/share/ranvds not found"
  fi
  if [[ -d /usr/local/etc/ranvds ]]; then
    rm -rf /usr/local/etc/ranvds
    echo "Purged /usr/local/etc/ranvds"
  else
    echo "/usr/local/etc/ranvds not found"
  fi
else
  echo "Kept data directory /usr/local/share/ranvds and configuration directory /usr/local/etc/ranvds (use --purge to remove)"
fi

echo "Done."
