#!/bin/bash
# =============================================================================
#  Aletheia - macOS READ-ONLY investigation launcher
#
#  Run from Terminal:   bash "/Volumes/<USB NAME>/aletheia/mac/run_mac_investigation.command"
#
#  * Installs NOTHING on the Mac and changes NO settings or data.
#  * Never triggers the "install command line developer tools" prompt.
#  * Writes ONLY to the output folder (default: the USB stick this script is on).
#  * Never offers or runs remediation.
# =============================================================================
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
bold() { printf "\033[1m%s\033[0m\n" "$*"; }
warn() { printf "\033[33m[!] %s\033[0m\n" "$*"; }
fail() { printf "\033[31m[X] %s\033[0m\n" "$*"; exit 1; }

clear
bold "=================================================================="
bold "  ALETHEIA - macOS read-only forensic investigation"
bold "=================================================================="
echo "  This tool only READS information. It does not delete, change,"
echo "  reset or install anything on this Mac. Results are saved to the"
echo "  output folder you choose (by default the USB stick)."
echo

# ---------------------------------------------------------------- 1. Python
PY=""
if [ -x "$ROOT/python/bin/python3" ]; then
  PY="$ROOT/python/bin/python3"                      # portable Python on the USB (preferred)
elif /usr/bin/xcode-select -p >/dev/null 2>&1 && [ -x /usr/bin/python3 ]; then
  PY="/usr/bin/python3"                              # Apple's Python - only if already installed
else
  for c in /opt/homebrew/bin/python3 /usr/local/bin/python3 \
           /Library/Frameworks/Python.framework/Versions/Current/bin/python3; do
    if [ -x "$c" ]; then PY="$c"; break; fi
  done
fi
if [ -z "$PY" ]; then
  warn "No Python 3 is available on this Mac or on the USB stick."
  echo "    To stay read-only we will NOT install anything on this Mac."
  echo "    Put a portable Python on the USB as described in the User Guide (Step 1.4),"
  echo "    in the folder: $ROOT/python"
  echo "    Nothing has been changed on this Mac."
  exit 1
fi
PYVER="$("$PY" -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null)"
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' || fail "Python $PYVER is too old (need 3.9+). Use the portable Python from the User Guide."
echo "  Python: $PY ($PYVER)"

# ----------------------------------------------------- 2. Full Disk Access
# ~/Library/Safari is protected by macOS privacy controls on every Mac: if we can list it, FDA is granted.
if /bin/ls "$HOME/Library/Safari" >/dev/null 2>&1; then
  echo "  Full Disk Access: OK"
else
  warn "Terminal does NOT have Full Disk Access."
  echo "    Without it, Mail, Messages, Safari and privacy-permission data cannot be read"
  echo "    and those report sections will be empty."
  echo "    Fix: System Settings > Privacy & Security > Full Disk Access > enable 'Terminal',"
  echo "         then QUIT Terminal completely (Cmd+Q), reopen it and run this script again."
  read -r -p "    Continue anyway with reduced coverage? [y/N] " a
  [ "${a:-n}" = "y" ] || [ "${a:-n}" = "Y" ] || { echo "Stopped. Nothing was changed."; exit 1; }
fi
echo

# ------------------------------------------------------------ 3. Case info
bold "Case details (recorded in the chain-of-custody log)"
read -r -p "  Examiner full name            : " EXAMINER
while [ -z "$EXAMINER" ]; do read -r -p "  Examiner full name (required) : " EXAMINER; done
read -r -p "  Case / ticket number          : " CASEID
read -r -p "  Client / device owner name    : " CLIENT
read -r -p "  Organization                  : " ORG
read -r -p "  Evidence item (model, serial) : " ITEM
echo
echo "  Watch list: e-mail addresses, names or phone numbers to search for in"
echo "  Mail, Messages and browser history. Separate several with commas."
read -r -p "  Watch for                     : " WATCH
read -r -p "  How many days back to search logs [90]: " DAYS
DAYS="${DAYS:-90}"
case "$DAYS" in ''|*[!0-9]*) DAYS=90 ;; esac
read -r -p "  Collect message TEXT too? (default: dates/contacts only) [y/N]: " CONTENT
DEFAULT_OUT="$ROOT/cases"
read -r -p "  Save results to [$DEFAULT_OUT]: " OUT
OUT="${OUT:-$DEFAULT_OUT}"
mkdir -p "$OUT" 2>/dev/null || fail "Cannot write to $OUT"

ARGS=(scan --examiner "$EXAMINER" --profile standard --days "$DAYS" --output "$OUT" --no-prompt --analysis-only
      --purpose "Owner-authorised read-only examination (macOS investigation)")
[ -n "$CASEID" ] && ARGS+=(--case-id "$CASEID")
[ -n "$CLIENT" ] && ARGS+=(--client "$CLIENT")
[ -n "$ORG" ]    && ARGS+=(--org "$ORG")
[ -n "$ITEM" ]   && ARGS+=(--evidence-item "$ITEM")
[ -n "$WATCH" ]  && ARGS+=(--watch "$WATCH")
case "$CONTENT" in y|Y) ARGS+=(--include-content) ;; esac

echo
bold "Ready. Please do not use this Mac (and keep it on power) until finished."
echo "  Typical duration: 10-40 minutes (most time is reading the system log)."
echo "  You will now be asked for this Mac's administrator password (needed to READ"
echo "  system-protected logs). Nothing is changed with it."
echo
START="$(date '+%Y-%m-%d %H:%M:%S %z')"
sudo "$PY" "$ROOT/run_aletheia.py" "${ARGS[@]}"
RC=$?
echo
bold "=================================================================="
echo "  Started : $START"
echo "  Finished: $(date '+%Y-%m-%d %H:%M:%S %z')   (exit code $RC)"
echo "  Results : $OUT"
echo
echo "  NEXT: do NOT open the report on this Mac (opening it in a browser would"
echo "  create new browsing history). Quit Terminal, eject the USB stick, and open"
echo "  report/report.html on YOUR computer (see User Guide, Step 6)."
bold "=================================================================="
