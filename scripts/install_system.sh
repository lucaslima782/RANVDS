#!/usr/bin/env bash
set -euo pipefail

# System installer for RANVDS (Nuitka onefile)
# - Installs binary to /usr/local/bin/ranvds
# - Creates /usr/local/share/ranvds/{PCAPs,Results}
# - Creates /usr/local/etc/ranvds
# - By default, gives ownership to the invoking sudo user so the app can write there
# - Optional --shared: create a 'ranvds' group, set 2775 permissions for shared write access
#
# Usage:
#   sudo scripts/install_system.sh [--bin PATH/TO/ranvds] [--config PATH/TO/Config] [--shared]
#   # Backward compatible positional args are also supported:
#   # sudo scripts/install_system.sh [PATH/TO/ranvds] [PATH/TO/Config] [--shared]
#
# Defaults:
#   --bin    dist/nuitka/ranvds
#   --config Config

if [[ ${EUID} -ne 0 ]]; then
  echo "Please run as root (use sudo)." >&2
  exit 1
fi

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BIN_SRC="dist/nuitka/ranvds"
CFG_SRC="config"
SHARED=0

# Parse flags (with backward-compatible positional args)
POS_ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin)
      BIN_SRC="${2:-}"
      if [[ -z "$BIN_SRC" ]]; then
        echo "--bin requires a path" >&2
        exit 1
      fi
      shift 2
      ;;
    --config|--cfg)
      CFG_SRC="${2:-}"
      if [[ -z "$CFG_SRC" ]]; then
        echo "--config requires a path" >&2
        exit 1
      fi
      shift 2
      ;;
    --shared)
      SHARED=1
      shift
      ;;
    -*)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
    *)
      POS_ARGS+=("$1")
      shift
      ;;
  esac
done

# Apply positional args if provided: [bin] [config] [--shared handled above]
if [[ ${#POS_ARGS[@]} -ge 1 ]]; then BIN_SRC="${POS_ARGS[0]}"; fi
if [[ ${#POS_ARGS[@]} -ge 2 ]]; then CFG_SRC="${POS_ARGS[1]}"; fi

if [[ ! -f "$BIN_SRC" ]]; then
  echo "Binary not found: $BIN_SRC" >&2
  exit 1
fi
if [[ ! -x "$BIN_SRC" ]]; then
  echo "Binary is not executable, fixing permissions: $BIN_SRC" >&2
  chmod +x "$BIN_SRC"
fi

install -Dm755 "$BIN_SRC" /usr/local/bin/ranvds

ETC_DIR="/usr/local/etc/ranvds"
SYSTEM_DIR=/usr/local/share/ranvds
PCAPS_DIR="$SYSTEM_DIR/PCAPs"
RESULTS_DIR="$SYSTEM_DIR/Results"


mkdir -p "$PCAPS_DIR" "$RESULTS_DIR" "$ETC_DIR"

OWNER_USER="${SUDO_USER:-root}"

if [[ "$SHARED" -eq 1 ]]; then
  # Create a shared-writable directory using a dedicated group
  if ! getent group ranvds >/dev/null 2>&1; then
    groupadd ranvds
    echo "Created group 'ranvds'. Add users with: sudo usermod -aG ranvds <username>"
  fi
  chgrp -R ranvds "$SYSTEM_DIR" "$ETC_DIR"
  chmod -R 2775 "$SYSTEM_DIR" "$ETC_DIR"
  echo "Configured $SYSTEM_DIR and $ETC_DIR for shared write (group ranvds, 2775)."
else
  # Make current sudo user the owner so they can write outputs
  chown -R "$OWNER_USER":"$OWNER_USER" "$SYSTEM_DIR" "$ETC_DIR"
  chmod -R 0755 "$SYSTEM_DIR" "$ETC_DIR"
  echo "Configured $SYSTEM_DIR and $ETC_DIR for user '$OWNER_USER' (owner-writable)."
fi

cp "$CFG_SRC/mcc-mnc.csv" "$ETC_DIR"
cp "$CFG_SRC/translations.cfg" "$ETC_DIR"
cp "$CFG_SRC/fields.cfg" "$ETC_DIR"
if [[ -f "$CFG_SRC/scat.lua" ]]; then
  cp "$CFG_SRC/scat.lua" "$ETC_DIR"
  OWNER_HOME="$(getent passwd "$OWNER_USER" | cut -d: -f6 || true)"
  if [[ -n "$OWNER_HOME" ]]; then
    USER_PLUGIN_DIR="$OWNER_HOME/.local/lib/wireshark/plugins"
    mkdir -p "$USER_PLUGIN_DIR"
    cp "$CFG_SRC/scat.lua" "$USER_PLUGIN_DIR/scat.lua"
    chown "$OWNER_USER":"$OWNER_USER" "$USER_PLUGIN_DIR/scat.lua"
    echo "Installed Wireshark Lua plugin for user $OWNER_USER at $USER_PLUGIN_DIR/scat.lua"
  else
    echo "Warning: could not determine home directory for $OWNER_USER; skipped Wireshark plugin installation."
  fi
else
  echo "Warning: scat.lua not found in $CFG_SRC; Wireshark Lua plugin not installed."
fi

ICON_SRC="$PROJECT_ROOT/RANVDS.png"
DESKTOP_DIR="/usr/local/share/applications"
if [[ -f "$ICON_SRC" ]]; then
  install -Dm644 "$ICON_SRC" "$SYSTEM_DIR/RANVDS.png"
  mkdir -p "$DESKTOP_DIR"
  cat > "$DESKTOP_DIR/ranvds.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=RANVDS
Comment=Radio Access Network Vulnerability Detection System
Exec=/usr/local/bin/ranvds
Icon=$SYSTEM_DIR/RANVDS.png
Terminal=false
Categories=Mobile;Network;Security;
EOF
  echo "Installed desktop entry at $DESKTOP_DIR/ranvds.desktop"
else
  echo "Warning: RANVDS.png not found at $ICON_SRC; desktop entry not installed."
fi

echo "Installed /usr/local/bin/ranvds"
echo "Data directory: $SYSTEM_DIR (PCAPs, Results)"
echo "Configuration directory: $ETC_DIR"
echo "Done. You can launch the app by running: ranvds"
