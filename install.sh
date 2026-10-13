#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  printf 'Usage: %s [INSTALL-DIRECTORY]\nDefault: ~/.local/bin\n' "${0##*/}"
  exit 0
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEST_DIR="${1:-$HOME/.local/bin}"
DEST_DIR="${DEST_DIR/#\~/$HOME}"

mkdir -p -- "$DEST_DIR"
if [[ -e "$DEST_DIR/autopwn" ]]; then
  printf 'Refusing to overwrite existing file: %s/autopwn\n' "$DEST_DIR" >&2
  exit 1
fi
install -m 0755 -- "$SCRIPT_DIR/autopwn.py" "$DEST_DIR/autopwn"
printf 'Installed offline CLI: %s/autopwn\n' "$DEST_DIR"
case ":${PATH}:" in
  *":${DEST_DIR}:"*) ;;
  *) printf 'Add this to PATH if needed: export PATH="%s:$PATH"\n' "$DEST_DIR" ;;
esac
