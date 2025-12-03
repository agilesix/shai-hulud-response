#!/usr/bin/env bash

###############################################################################
# SHAI-HULUD 2.0 SCANNER - LINUX/UBUNTU BASH VERSION
# Version: 2.0.8-ubuntu
#
# This script is a Linux/Ubuntu port of the original macOS zsh scanner.
# It:
# 1. Launches a background copy of itself (for MDM/remote tooling compatibility)
# 2. Scans npm projects for compromised package versions
# 3. Looks for malicious Shai-Hulud 2.0 files/workflows
# 4. Sends results to a webhook
#
# NOTES:
# - Requires bash 4+ (associative arrays), which is standard on modern Ubuntu.
# - This version is Linux-only. Keep using the original zsh script for macOS.
###############################################################################

###############################################################################
# CONFIG
###############################################################################

WEBHOOK_URL="https://kandji-ack-worker.anthony-arashiro.workers.dev/scan"
SECRET="YOUR_SHARED_SECRET_HERE"
SCANNER_VERSION="2.0.8"
MAX_PROJECTS=200

# Malicious files dropped by Shai-Hulud 2.0
MALICIOUS_FILES=(
  "setup_bun.js"
  "bun_environment.js"
  "actionsSecrets.json"
)

MALICIOUS_WORKFLOW_PATTERNS=(
  "SHA1HULUD"
  "formatter_"
)

# PERFORMANCE SETTINGS
NICE_LEVEL=10
DELAY_BETWEEN_PROJECTS=0.2
SKIP_IF_ON_BATTERY=false

# Compromised packages list (plain text, one package:version per line)
PACKAGES_URL="https://raw.githubusercontent.com/agilesix/shai-hulud-response/main/ioc/compromised-packages.txt"

# Default scan roots on Ubuntu
SCAN_DIRS=(
  "/home"
)

WORK_DIR="/var/tmp/shai-hulud"
LOCK_FILE="/tmp/shai-hulud-scanner.lock"
LOG_FILE="${WORK_DIR}/scanner.log"

###############################################################################
# UTILITY FUNCTIONS
###############################################################################

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >&2
}

# Try to determine the "console" / primary user on Linux
get_console_user() {
  local user=""
  # Try logname (most reliable when run from user context)
  user=$(logname 2>/dev/null || true)
  if [[ -z "$user" || "$user" == "root" ]]; then
    # Fallback: first non-root user from 'who'
    user=$(who 2>/dev/null | awk '$1 != "root" {print $1; exit}')
  fi
  if [[ -z "$user" || "$user" == "root" ]]; then
    # Final fallback: current uid's username
    user=$(id -un 2>/dev/null || echo "")
  fi
  echo "$user"
}

# Detect basic power source information on Linux via /sys
get_power_source() {
  local status="Unknown"

  if [[ -d /sys/class/power_supply ]]; then
    local bat=""
    # Prefer a BAT* device
    for d in /sys/class/power_supply/BAT*; do
      [[ -e "$d" ]] || continue
      bat="$d"
      break
    done

    if [[ -n "$bat" ]]; then
      if [[ -r "$bat/status" ]]; then
        status=$(cat "$bat/status" 2>/dev/null)
      fi
    fi
  fi

  echo "$status"
}

cleanup() {
  log "Cleaning up..."
  [[ -n "${TEMP_DIR:-}" ]] && rm -rf "${TEMP_DIR}"
  rm -f "${LOCK_FILE}"
}
trap cleanup EXIT

###############################################################################
# CHECK IF WE'RE THE BACKGROUND PROCESS
###############################################################################

if [[ "$1" == "--background" ]]; then
  shift
  TEMP_DIR="$1"
  # Ensure TEMP_DIR exists and is writable
  mkdir -p "${TEMP_DIR}" || {
    echo "ERROR: Cannot create temp directory: ${TEMP_DIR}" >&2
    exit 1
  }
  # Ensure WORK_DIR exists for log file
  mkdir -p "${WORK_DIR}" || {
    echo "ERROR: Cannot create work directory: ${WORK_DIR}" >&2
    exit 1
  }
  # Redirect stderr (log output) to log file in background mode, keep stdout for function returns
  exec 2>> "${LOG_FILE}"
else
  ###########################################################################
  # FOREGROUND MODE - Launch background and exit
  ###########################################################################

  echo "=== Shai-Hulud 2.0 Scanner Launcher v${SCANNER_VERSION} (Linux) ==="
  echo "Timestamp: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"

  # Check for existing run
  if [[ -f "$LOCK_FILE" ]]; then
    EXISTING_PID=$(cat "$LOCK_FILE" 2>/dev/null)
    if [[ -n "$EXISTING_PID" ]] && kill -0 "$EXISTING_PID" 2>/dev/null; then
      echo "Scanner already running (PID: $EXISTING_PID). Exiting."
      exit 0
    fi
    rm -f "$LOCK_FILE"
  fi

  # Setup
  mkdir -p "${WORK_DIR}"
  TEMP_DIR="${WORK_DIR}/scan-$$"
  mkdir -p "${TEMP_DIR}"

  # Copy this script to temp location for background execution
  SCRIPT_COPY="${TEMP_DIR}/scanner.sh"
  cp "$0" "${SCRIPT_COPY}"
  chmod +x "${SCRIPT_COPY}"

  echo "Launching scanner in background..."

  # Double-fork daemonization
  ( ( /usr/bin/env bash "${SCRIPT_COPY}" --background "${TEMP_DIR}" >> "${LOG_FILE}" 2>&1 ) & )

  # Give it a moment to start
  sleep 1

  # Try to find the backgrounded process
  BG_PID=$(pgrep -f "scanner.sh --background" 2>/dev/null | tail -1)

  if [[ -n "$BG_PID" ]]; then
    echo "$BG_PID" > "$LOCK_FILE"
    echo "✅ Scanner launched (PID: $BG_PID)"
    echo "Log: ${LOG_FILE}"
    echo "Results will be sent to webhook when complete."
  else
    echo "⚠️  Scanner may have exited - check ${LOG_FILE}"
  fi

  echo "Launcher exiting."
  exit 0
fi

###############################################################################
# BACKGROUND MODE - ACTUAL SCANNING STARTS HERE
###############################################################################

log "=== Background Scanner Started (PID: $$) ==="

###############################################################################
# ENVIRONMENT CHECKS & ERROR CAPTURE
###############################################################################

WARNINGS=""

# Check if user is logged in at console
CONSOLE_USER=$(get_console_user)
if [[ -z "$CONSOLE_USER" || "$CONSOLE_USER" == "root" ]]; then
  WARNINGS="${WARNINGS}No non-root user logged in; "
  log "WARNING: No non-root user detected"
fi

# Check power source
POWER_SOURCE=$(get_power_source)
if [[ "$POWER_SOURCE" == "Discharging" ]]; then
  WARNINGS="${WARNINGS}Running on battery; "
  log "INFO: Running on battery power"
fi

# Check Linux distro/version
OS_VERSION=""
if [[ -r /etc/os-release ]]; then
  OS_VERSION=$(grep '^PRETTY_NAME=' /etc/os-release | sed 's/PRETTY_NAME=//; s/"//g')
elif command -v lsb_release >/dev/null 2>&1; then
  OS_VERSION=$(lsb_release -d | cut -f2-)
else
  OS_VERSION="Unknown"
fi
log "INFO: Linux version: ${OS_VERSION}"

# Check available disk space
AVAILABLE_SPACE_KB=$(df -k /var/tmp 2>/dev/null | tail -1 | awk '{print $4}')
if [[ -n "$AVAILABLE_SPACE_KB" && "$AVAILABLE_SPACE_KB" -lt 1048576 ]]; then
  WARNINGS="${WARNINGS}Low disk space (<1GB); "
  log "WARNING: Low disk space on /var/tmp"
fi

###############################################################################
# PERFORMANCE SAFEGUARDS
###############################################################################

# Check if on battery (optional skip)
if [[ "$SKIP_IF_ON_BATTERY" == "true" ]]; then
  POWER_SOURCE=$(get_power_source)
  if [[ "$POWER_SOURCE" == "Discharging" ]]; then
    log "On battery power - skipping scan (SKIP_IF_ON_BATTERY=true)"
    curl -s -X POST -H "Content-Type: application/json" \
      -d "{\"secret\": \"${SECRET}\", \"serial\": \"${SERIAL}\", \"hostname\": \"${HOSTNAME}\", \"user\": \"${CURRENT_USER}\", \"os\": \"Linux\", \"status\": \"skipped\", \"high_risk_count\": 0, \"medium_risk_count\": 0, \"low_risk_count\": 0, \"high_risk_details\": \"\", \"medium_risk_details\": \"\", \"scan_duration_ms\": 0, \"scanner_version\": \"${SCANNER_VERSION}\", \"raw_output\": \"Skipped - on battery power\", \"malicious_files_found\": 0}" \
      "${WEBHOOK_URL}"
    exit 0
  fi
fi

# Lower CPU priority
renice ${NICE_LEVEL} $$ >/dev/null 2>&1 || true

###############################################################################
# ERROR HANDLING FUNCTION
###############################################################################

send_error() {
  local msg="$1"
  log "ERROR: $msg"
  # Ensure device info is available (may be called early)
  local error_serial="${SERIAL:-unknown}"
  local error_hostname="${HOSTNAME:-unknown}"
  local error_user="${CURRENT_USER:-unknown}"
  # Escape the error message for JSON
  local msg_escaped
  msg_escaped=$(echo "$msg" | sed 's/\\/\\\\/g; s/"/\\"/g; s/$/\\n/' | tr -d '\n' | sed 's/\\n$//')
  curl -s -X POST -H "Content-Type: application/json" \
    -d "{\"secret\": \"${SECRET}\", \"serial\": \"${error_serial}\", \"hostname\": \"${error_hostname}\", \"user\": \"${error_user}\", \"os\": \"Linux\", \"status\": \"error\", \"high_risk_count\": 0, \"medium_risk_count\": 0, \"low_risk_count\": 0, \"high_risk_details\": \"\", \"medium_risk_details\": \"\", \"scan_duration_ms\": 0, \"scanner_version\": \"${SCANNER_VERSION}\", \"raw_output\": \"${msg_escaped}\", \"malicious_files_found\": 0}" \
    "${WEBHOOK_URL}"
}

###############################################################################
# GATHER DEVICE INFO
###############################################################################

log "Step 1: Gathering device info..."

CURRENT_USER=$(get_console_user)

# Best-effort serial number on Linux (may require root on some hardware)
SERIAL=""
if [[ -r /sys/class/dmi/id/product_serial ]]; then
  SERIAL=$(cat /sys/class/dmi/id/product_serial 2>/dev/null)
fi
if [[ -z "$SERIAL" ]]; then
  SERIAL="unknown"
fi

# Hostname
if command -v hostnamectl >/dev/null 2>&1; then
  HOSTNAME=$(hostnamectl --static 2>/dev/null || hostname 2>/dev/null || echo "unknown")
else
  HOSTNAME=$(hostname 2>/dev/null || echo "unknown")
fi

START_TIME=$(date +%s)

log "Host: ${HOSTNAME} | Serial: ${SERIAL} | User: ${CURRENT_USER}"

###############################################################################
# DOWNLOAD COMPROMISED PACKAGES LIST
###############################################################################

log "Step 2: Downloading compromised packages list..."

# Ensure TEMP_DIR exists
mkdir -p "${TEMP_DIR}" || {
  send_error "Cannot create temp directory: ${TEMP_DIR}"
  exit 1
}

PACKAGES_FILE="${TEMP_DIR}/compromised-packages.txt"

# Download with better error handling
CURL_OUTPUT=$(curl -fsSL --connect-timeout 30 --max-time 60 "${PACKAGES_URL}" -o "${PACKAGES_FILE}" 2>&1)
CURL_EXIT=$?

if [[ $CURL_EXIT -ne 0 ]] || [[ ! -f "${PACKAGES_FILE}" ]]; then
  log "ERROR: curl failed with exit code $CURL_EXIT"
  log "ERROR: curl output: ${CURL_OUTPUT}"
  send_error "Failed to download compromised packages list: ${CURL_OUTPUT}"
  exit 1
fi

# Verify file was downloaded and has content
if [[ ! -s "${PACKAGES_FILE}" ]]; then
  log "ERROR: Downloaded file is empty or missing"
  send_error "Downloaded compromised packages list is empty"
  exit 1
fi

# Build associative array of compromised packages for O(1) lookup
declare -A COMPROMISED
while IFS= read -r line; do
  # Skip comments and empty lines
  [[ "$line" =~ ^[[:space:]]*# ]] && continue
  [[ -z "${line// }" ]] && continue
  # Trim leading/trailing whitespace
  line="${line#"${line%%[![:space:]]*}"}"
  line="${line%"${line##*[![:space:]]}"}"
  [[ -n "$line" ]] && COMPROMISED["$line"]=1
done < "${PACKAGES_FILE}"

PACKAGE_COUNT=${#COMPROMISED[@]}
log "Loaded ${PACKAGE_COUNT} compromised package signatures"

###############################################################################
# FIND NPM PROJECTS
###############################################################################

log "Step 3: Finding npm projects..."
NPM_PROJECTS=()

for base_dir in "${SCAN_DIRS[@]}"; do
  if [[ -d "$base_dir" ]]; then
    while IFS= read -r -d '' pkg_json; do
      project_dir=$(dirname "$pkg_json")
      NPM_PROJECTS+=("$project_dir")

      if [[ ${#NPM_PROJECTS[@]} -ge $MAX_PROJECTS ]]; then
        log "Reached project limit (${MAX_PROJECTS})"
        break 2
      fi
    done < <(find "$base_dir" -maxdepth 6 -name "package.json" -type f \
      -not -path "*/node_modules/*" \
      -not -path "*/.npm/*" \
      -not -path "*/.nvm/versions/*" \
      -not -path "*/.cache/*" \
      -not -path "*/.Trash/*" \
      -not -path "*/.vscode/*" \
      -not -path "*/.cursor/*" \
      -not -path "*/.local/share/Trash/*" \
      -not -path "*/*shai-hulud-detect*/*" \
      -print0 2>/dev/null)
  fi
done

log "Found ${#NPM_PROJECTS[@]} npm projects to scan"

###############################################################################
# FUNCTION: Parse package-lock.json and check for compromised packages
###############################################################################

check_lockfile() {
  local lockfile="$1"
  local findings=()

  [[ ! -f "$lockfile" ]] && return

  # Detect lockfile version
  local lockfile_version
  lockfile_version=$(grep -o '"lockfileVersion"[[:space:]]*:[[:space:]]*[0-9]*' "$lockfile" | grep -o '[0-9]*' | head -1)

  if [[ "$lockfile_version" == "2" || "$lockfile_version" == "3" ]]; then
    # lockfileVersion 2 or 3: packages are in "packages" object
    # Format: "node_modules/package-name": { "version": "x.y.z" }

    # Extract package paths and versions using awk
    while IFS='|' read -r pkg_path version; do
      [[ -z "$pkg_path" || -z "$version" ]] && continue

      # Extract package name from path (e.g., "node_modules/@scope/pkg" -> "@scope/pkg")
      local pkg_name=""
      if [[ "$pkg_path" =~ node_modules/(.+) ]]; then
        pkg_name="${BASH_REMATCH[1]}"
      else
        continue
      fi

      # Check if this package:version is compromised
      local check_key="${pkg_name}:${version}"
      if [[ -n "${COMPROMISED[$check_key]}" ]]; then
        findings+=("${pkg_name}@${version}")
      fi
    done < <(awk '
      BEGIN { in_packages = 0; current_pkg = ""; }
      /"packages"[[:space:]]*:[[:space:]]*\{/ { in_packages = 1; next }
      in_packages && /^[[:space:]]*"node_modules\/[^"]+":/ {
        match($0, /"node_modules\/[^"]+"/);
        current_pkg = substr($0, RSTART+1, RLENGTH-2);
      }
      in_packages && current_pkg != "" && /"version"[[:space:]]*:/ {
        match($0, /"version"[[:space:]]*:[[:space:]]*"[^"]+"/);
        version_part = substr($0, RSTART, RLENGTH);
        match(version_part, /:[[:space:]]*"[^"]+"/);
        version = substr(version_part, RSTART+2, RLENGTH-3);
        gsub(/^[[:space:]"]+|[[:space:]"]+$/, "", version);
        if (current_pkg != "" && version != "") {
          print current_pkg "|" version;
        }
        current_pkg = "";
      }
    ' "$lockfile" 2>/dev/null)

  elif [[ "$lockfile_version" == "1" || -z "$lockfile_version" ]]; then
    # lockfileVersion 1: packages are in "dependencies" object (older format)
    # Format: "package-name": { "version": "x.y.z" }

    while IFS='|' read -r pkg_name version; do
      [[ -z "$pkg_name" || -z "$version" ]] && continue

      local check_key="${pkg_name}:${version}"
      if [[ -n "${COMPROMISED[$check_key]}" ]]; then
        findings+=("${pkg_name}@${version}")
      fi
    done < <(awk '
      BEGIN { in_deps = 0; current_pkg = ""; brace_count = 0; }
      /"dependencies"[[:space:]]*:[[:space:]]*\{/ { in_deps = 1; brace_count = 1; next }
      in_deps {
        # Track brace depth
        gsub(/[^{}]/, "");
        for (i = 1; i <= length($0); i++) {
          c = substr($0, i, 1);
          if (c == "{") brace_count++;
          else if (c == "}") brace_count--;
        }
        if (brace_count <= 0) { in_deps = 0; next; }
      }
      in_deps && /"[^"]+":.*\{/ && !/"dependencies":/ && !/"requires":/ && !/"dev":/ {
        match($0, /"[^"]+"/);
        current_pkg = substr($0, RSTART+1, RLENGTH-2);
      }
      in_deps && current_pkg != "" && /"version"[[:space:]]*:/ {
        match($0, /"version"[[:space:]]*:[[:space:]]*"[^"]+"/);
        version_part = substr($0, RSTART, RLENGTH);
        match(version_part, /:[[:space:]]*"[^"]+"/);
        version = substr(version_part, RSTART+2, RLENGTH-3);
        gsub(/^[[:space:]"]+|[[:space:]"]+$/, "", version);
        if (current_pkg != "" && version != "") {
          print current_pkg "|" version;
        }
        current_pkg = "";
      }
    ' "$lockfile" 2>/dev/null)
  fi

  # Return findings
  if [[ ${#findings[@]} -gt 0 ]]; then
    printf '%s\n' "${findings[@]}"
  fi
}

###############################################################################
# MALICIOUS FILE DETECTION
# Detects files dropped by Shai-Hulud 2.0 payload execution
###############################################################################

scan_malicious_files() {
  local scan_dir="$1"
  local found_files=()

  log "Scanning for malicious files..."

  # Check for known malicious files
  for filename in "${MALICIOUS_FILES[@]}"; do
    while IFS= read -r -d '' file; do
      # Skip node_modules and test-cases directories to reduce noise
      if [[ "$file" != *"/node_modules/"* ]] && \
         [[ "$file" != *"/test-cases/"* ]] && \
         [[ "$file" != *"/shai-hulud-detect"* ]]; then
        found_files+=("$file")
        log "  ⚠️  CRITICAL: Found malicious file: $file"
      fi
    done < <(find "$scan_dir" -name "$filename" -type f -print0 2>/dev/null)
  done

  # Check for malicious GitHub workflow files
  if [[ -d "$scan_dir/.github/workflows" ]]; then
    # Check for formatter_*.yml files (Shai-Hulud 2.0 backdoor)
    while IFS= read -r -d '' file; do
      found_files+=("$file")
      log "  ⚠️  CRITICAL: Found suspicious workflow: $file"
    done < <(find "$scan_dir/.github/workflows" -name "formatter_*.yml" -type f -print0 2>/dev/null)

    # Check for SHA1HULUD references in workflow files
    while IFS= read -r file; do
      found_files+=("$file")
      log "  ⚠️  CRITICAL: Found SHA1HULUD reference in: $file"
    done < <(grep -l -r "SHA1HULUD" "$scan_dir/.github/workflows" 2>/dev/null || true)

    # Check for suspicious 'on: discussion' triggers (persistence backdoor)
    while IFS= read -r file; do
      if awk '/^on:/{found=1; next} found && /discussion:/{exit 0} found && !/^\s/ && !/^$/{found=0} END {exit !found}' "$file" 2>/dev/null || \
         grep -q "on:.*discussion" "$file" 2>/dev/null; then
        found_files+=("$file")
        log "  ⚠️  WARNING: Found discussion trigger backdoor in: $file"
      fi
    done < <(find "$scan_dir/.github/workflows" -name "*.yml" -type f 2>/dev/null)
  fi

  # Check for .dev-env directory (rogue runner installation)
  if [[ -d "$HOME/.dev-env" ]]; then
    found_files+=("$HOME/.dev-env")
    log "  ⚠️  CRITICAL: Found rogue runner directory: $HOME/.dev-env"
  fi

  # Deduplicate found_files array (same file might match multiple patterns)
  local unique_files=()
  local seen
  local file
  local unique
  for file in "${found_files[@]}"; do
    seen=0
    for unique in "${unique_files[@]}"; do
      if [[ "$file" == "$unique" ]]; then
        seen=1
        log "  (duplicate removed: $file)"
        break
      fi
    done
    if [[ $seen -eq 0 ]]; then
      unique_files+=("$file")
    fi
  done

  # Log all detected files with full paths
  log "Detected malicious files/directories (${#unique_files[@]} total):"
  for file in "${unique_files[@]}"; do
    log "  - $file"
  done

  # Write results to desktop file for easy viewing (best-effort)
  local RESULTS_DIR="${HOME}/Desktop"
  mkdir -p "${RESULTS_DIR}" 2>/dev/null || true
  local RESULTS_FILE="${RESULTS_DIR}/shai-hulud-scan-results.txt"

  {
    echo "Shai-Hulud 2.0 Scanner - Malicious File Detection Results"
    echo "Scan Date: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Scanner Version: ${SCANNER_VERSION}"
    echo "Hostname: ${HOSTNAME}"
    echo "User: ${CURRENT_USER}"
    echo ""
    echo "Total Malicious Items Found: ${#unique_files[@]}"
    echo ""
    echo "Detected Files/Directories:"
    echo "=========================="
    for file in "${unique_files[@]}"; do
      echo "  - $file"
    done
    echo ""
    echo "End of Report"
  } > "${RESULTS_FILE}" 2>/dev/null || true

  log "Results written to: ${RESULTS_FILE}"

  echo "${#unique_files[@]}"
}

###############################################################################
# SCAN PROJECTS
###############################################################################

log "Step 4: Scanning projects for compromised packages..."

HIGH_RISK_COUNT=0
MEDIUM_RISK_COUNT=0
LOW_RISK_COUNT=0
HIGH_RISK_DETAILS=""
MEDIUM_RISK_DETAILS=""
RAW_OUTPUT=""
OVERALL_STATUS="clean"
MALICIOUS_FILE_COUNT=0

PROJECT_COUNT=0

for project in "${NPM_PROJECTS[@]}"; do
  PROJECT_COUNT=$((PROJECT_COUNT + 1))

  if [[ $PROJECT_COUNT -gt $MAX_PROJECTS ]]; then
    RAW_OUTPUT="${RAW_OUTPUT}[Stopped at limit] "
    break
  fi

  display_path="${project}"
  if [[ ${#project} -gt 50 ]]; then
    display_path="...${project: -47}"
  fi

  # Check for lockfile
  LOCKFILE=""
  if [[ -f "${project}/package-lock.json" ]]; then
    LOCKFILE="${project}/package-lock.json"
  elif [[ -f "${project}/npm-shrinkwrap.json" ]]; then
    LOCKFILE="${project}/npm-shrinkwrap.json"
  fi

  high_in_project=0
  project_findings=""

  if [[ -n "$LOCKFILE" ]]; then
    # Get findings from lockfile
    findings_output=$(check_lockfile "$LOCKFILE")

    if [[ -n "$findings_output" ]]; then
      # Count findings
      high_in_project=$(echo "$findings_output" | wc -l | tr -d ' ')
      project_findings=$(echo "$findings_output" | tr '\n' ', ' | sed 's/,$//')
    fi
  fi

  HIGH_RISK_COUNT=$((HIGH_RISK_COUNT + high_in_project))

  if [[ $high_in_project -gt 0 ]]; then
    OVERALL_STATUS="affected"
    HIGH_RISK_DETAILS="${HIGH_RISK_DETAILS}${display_path}: ${project_findings} | "
    RAW_OUTPUT="${RAW_OUTPUT}[${display_path}] HIGH:${high_in_project} "
    log "  ⚠️  ${display_path}: HIGH RISK (${project_findings})"
  else
    RAW_OUTPUT="${RAW_OUTPUT}[${display_path}] clean "
  fi

  # Brief pause between projects
  sleep ${DELAY_BETWEEN_PROJECTS}
done

if [[ ${#NPM_PROJECTS[@]} -eq 0 ]]; then
  RAW_OUTPUT="No npm projects found"
  OVERALL_STATUS="clean"
fi

# Scan for malicious files in home directory
MALICIOUS_FILE_COUNT=$(scan_malicious_files "$HOME" 2>&1 | tail -1)

# Ensure MALICIOUS_FILE_COUNT is a number (default to 0 if not)
MALICIOUS_FILE_COUNT=$(echo "${MALICIOUS_FILE_COUNT}" | tr -d '[:space:]')
if [[ -z "$MALICIOUS_FILE_COUNT" || ! "$MALICIOUS_FILE_COUNT" =~ ^[0-9]+$ ]]; then
  MALICIOUS_FILE_COUNT=0
fi

# Always log the malicious file count (even if 0)
if [[ ${MALICIOUS_FILE_COUNT:-0} -gt 0 ]]; then
  log "⚠️  CRITICAL: Found $MALICIOUS_FILE_COUNT malicious files/directories!"
  # Add to high risk count
  HIGH_RISK_COUNT=$((HIGH_RISK_COUNT + MALICIOUS_FILE_COUNT))
  HIGH_RISK_DETAILS="${HIGH_RISK_DETAILS}MALICIOUS_FILES:${MALICIOUS_FILE_COUNT};"
  OVERALL_STATUS="affected"
else
  log "No malicious files found (malicious_files_found: 0)"
fi

# Prepend any warnings to raw output
if [[ -n "$WARNINGS" ]]; then
  RAW_OUTPUT="[WARNINGS: ${WARNINGS}] ${RAW_OUTPUT}"
fi

###############################################################################
# SEND RESULTS
###############################################################################

END_TIME=$(date +%s)
SCAN_DURATION=$(( (END_TIME - START_TIME) * 1000 ))

log "Step 5: Sending results..."
log "Status: ${OVERALL_STATUS} | High: ${HIGH_RISK_COUNT} | Medium: ${MEDIUM_RISK_COUNT} | Duration: ${SCAN_DURATION}ms"

# Truncate for webhook
RAW_OUTPUT="${RAW_OUTPUT:0:5000}"
HIGH_RISK_DETAILS="${HIGH_RISK_DETAILS:0:1000}"
MEDIUM_RISK_DETAILS="${MEDIUM_RISK_DETAILS:0:1000}"

# Escape special characters for JSON
escape_json() {
  local str="$1"
  str="${str//\\/\\\\}"
  str="${str//\"/\\\"}"
  str="${str//$'\n'/\\n}"
  str="${str//$'\r'/\\r}"
  str="${str//$'\t'/\\t}"
  echo "$str"
}

RAW_OUTPUT_ESCAPED=$(escape_json "$RAW_OUTPUT")
HIGH_RISK_DETAILS_ESCAPED=$(escape_json "$HIGH_RISK_DETAILS")
MEDIUM_RISK_DETAILS_ESCAPED=$(escape_json "$MEDIUM_RISK_DETAILS")

# Send results to webhook
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" \
  -d "{\"secret\": \"${SECRET}\", \"serial\": \"${SERIAL}\", \"hostname\": \"${HOSTNAME}\", \"user\": \"${CURRENT_USER}\", \"os\": \"Linux\", \"status\": \"${OVERALL_STATUS}\", \"high_risk_count\": ${HIGH_RISK_COUNT}, \"medium_risk_count\": ${MEDIUM_RISK_COUNT}, \"low_risk_count\": ${LOW_RISK_COUNT}, \"high_risk_details\": \"${HIGH_RISK_DETAILS_ESCAPED}\", \"medium_risk_details\": \"${MEDIUM_RISK_DETAILS_ESCAPED}\", \"scan_duration_ms\": ${SCAN_DURATION}, \"scanner_version\": \"${SCANNER_VERSION}\", \"raw_output\": \"${RAW_OUTPUT_ESCAPED}\", \"malicious_files_found\": ${MALICIOUS_FILE_COUNT:-0}}" \
  "${WEBHOOK_URL}" 2>/dev/null)

if [[ "${HTTP_CODE}" == "200" ]]; then
  log "✅ Results sent successfully to webhook"
else
  log "⚠️  Webhook returned: ${HTTP_CODE}"
fi
log "=== Scanner Complete ==="
exit 0
