#!/bin/zsh

###############################################################################
# SHAI-HULUD 2.0 SCANNER - NATIVE ZSH VERSION
# Version: 2.0.6
# 
# This script handles everything:
# 1. When run by Kandji, it copies itself and launches in background
# 2. The backgrounded copy does the actual scanning
# 3. Results are sent to webhook when complete
#
# Features:
# - No Bash 5 dependency: Native zsh lockfile parsing
# - No timeout: Backgrounds itself so Kandji exits immediately
# - Version-aware: Checks exact package:version against compromised list
# - Performance-friendly: Runs at reduced priority
# - Error capture: Reports environment issues to Google Sheets
#
# Changes in v2.0.6:
# - Removed dependency on Cobenian shai-hulud-detector.sh (requires Bash 5)
# - Native zsh parsing of package-lock.json (lockfileVersion 2 and 3)
# - Direct version matching against compromised-packages.txt
# - Fixed double-fork daemonization for MDM compatibility
###############################################################################

###############################################################################
# CONFIG
###############################################################################

WEBHOOK_URL="https://kandji-ack-worker.anthony-arashiro.workers.dev/scan"
SECRET="YOUR_SHARED_SECRET_HERE"
SCANNER_VERSION="2.0.7"
MAX_PROJECTS=200

# PERFORMANCE SETTINGS
NICE_LEVEL=10
DELAY_BETWEEN_PROJECTS=0.2
SKIP_IF_ON_BATTERY=false

# Compromised packages list (plain text, one package:version per line)
PACKAGES_URL="https://raw.githubusercontent.com/mutsuoara/a6-shai-hulud-response/main/ioc/compromised-packages.txt"

SCAN_DIRS=(
  "/Users"
)

WORK_DIR="/var/tmp/shai-hulud"
LOCK_FILE="/tmp/shai-hulud-scanner.lock"
LOG_FILE="${WORK_DIR}/scanner.log"

###############################################################################
# CHECK IF WE'RE THE BACKGROUND PROCESS
###############################################################################

if [[ "$1" == "--background" ]]; then
  shift
  TEMP_DIR="$1"
else
  ###########################################################################
  # FOREGROUND MODE - Launch background and exit
  ###########################################################################
  
  echo "=== Shai-Hulud 2.0 Scanner Launcher v${SCANNER_VERSION} ==="
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
  
  # Double-fork daemonization (works in MDM environments without controlling terminal)
  ( ( /bin/zsh "${SCRIPT_COPY}" --background "${TEMP_DIR}" >> "${LOG_FILE}" 2>&1 ) & )
  
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

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

cleanup() {
  log "Cleaning up..."
  rm -rf "${TEMP_DIR}"
  rm -f "${LOCK_FILE}"
}
trap cleanup EXIT

log "=== Background Scanner Started (PID: $$) ==="

###############################################################################
# ENVIRONMENT CHECKS & ERROR CAPTURE
###############################################################################

WARNINGS=""

# Check if user is logged in at console
CONSOLE_USER=$(/usr/bin/stat -f%Su /dev/console 2>/dev/null)
if [[ "$CONSOLE_USER" == "root" || -z "$CONSOLE_USER" ]]; then
  WARNINGS="${WARNINGS}No user logged in at console; "
  log "WARNING: No user logged in at console (loginwindow)"
fi

# Check power source
POWER_SOURCE=$(pmset -g batt 2>/dev/null | head -1 | grep -o "'.*'" | tr -d "'" || echo "Unknown")
if [[ "$POWER_SOURCE" == *"Battery"* ]]; then
  WARNINGS="${WARNINGS}Running on battery; "
  log "INFO: Running on battery power"
fi

# Check macOS version
MACOS_VERSION=$(sw_vers -productVersion 2>/dev/null || echo "Unknown")
log "INFO: macOS version: ${MACOS_VERSION}"

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
  POWER_SOURCE=$(pmset -g batt | head -1)
  if [[ "$POWER_SOURCE" == *"Battery"* ]]; then
    log "On battery power - skipping scan (SKIP_IF_ON_BATTERY=true)"
    curl -s -X POST -H "Content-Type: application/json" \
      -d "{\"secret\": \"${SECRET}\", \"serial\": \"${SERIAL}\", \"hostname\": \"${HOSTNAME}\", \"user\": \"${CURRENT_USER}\", \"os\": \"macOS\", \"status\": \"skipped\", \"high_risk_count\": 0, \"medium_risk_count\": 0, \"low_risk_count\": 0, \"high_risk_details\": \"\", \"medium_risk_details\": \"\", \"scan_duration_ms\": 0, \"scanner_version\": \"${SCANNER_VERSION}\", \"raw_output\": \"Skipped - on battery power\"}" \
      "${WEBHOOK_URL}"
    exit 0
  fi
fi

# Lower CPU priority
renice ${NICE_LEVEL} $$ >/dev/null 2>&1 || true

###############################################################################
# GATHER DEVICE INFO
###############################################################################

log "Step 1: Gathering device info..."

CURRENT_USER=$(/usr/bin/stat -f%Su /dev/console)
SERIAL=$(/usr/sbin/ioreg -l | /usr/bin/awk -F\" '/IOPlatformSerialNumber/ { print $4 }')
HOSTNAME=$(/usr/sbin/scutil --get ComputerName 2>/dev/null || hostname)
START_TIME=$(date +%s)

log "Host: ${HOSTNAME} | Serial: ${SERIAL} | User: ${CURRENT_USER}"

###############################################################################
# DOWNLOAD COMPROMISED PACKAGES LIST
###############################################################################

log "Step 2: Downloading compromised packages list..."

PACKAGES_FILE="${TEMP_DIR}/compromised-packages.txt"

send_error() {
  local msg="$1"
  log "ERROR: $msg"
  curl -s -X POST -H "Content-Type: application/json" \
    -d "{\"secret\": \"${SECRET}\", \"serial\": \"${SERIAL}\", \"hostname\": \"${HOSTNAME}\", \"user\": \"${CURRENT_USER}\", \"os\": \"macOS\", \"status\": \"error\", \"high_risk_count\": 0, \"medium_risk_count\": 0, \"low_risk_count\": 0, \"high_risk_details\": \"\", \"medium_risk_details\": \"\", \"scan_duration_ms\": 0, \"scanner_version\": \"${SCANNER_VERSION}\", \"raw_output\": \"${msg}\"}" \
    "${WEBHOOK_URL}"
}

if ! curl -fsSL --connect-timeout 30 --max-time 60 "${PACKAGES_URL}" -o "${PACKAGES_FILE}" 2>&1; then
  send_error "Failed to download compromised packages list"
  exit 1
fi

# Build associative array of compromised packages for O(1) lookup
typeset -A COMPROMISED
while IFS= read -r line; do
  # Skip comments and empty lines
  [[ "$line" =~ ^[[:space:]]*# ]] && continue
  [[ -z "${line// }" ]] && continue
  # Trim whitespace
  line="${line## }"
  line="${line%% }"
  [[ -n "$line" ]] && COMPROMISED[$line]=1
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
      -not -path "*/Library/Caches/*" \
      -not -path "*/.cache/*" \
      -not -path "*/.Trash/*" \
      -not -path "*/.vscode/*" \
      -not -path "*/.cursor/*" \
      -not -path "*/Application Support/*" \
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
  local lockfile_version=$(grep -o '"lockfileVersion"[[:space:]]*:[[:space:]]*[0-9]*' "$lockfile" | grep -o '[0-9]*' | head -1)
  
  if [[ "$lockfile_version" == "2" || "$lockfile_version" == "3" ]]; then
    # lockfileVersion 2 or 3: packages are in "packages" object
    # Format: "node_modules/package-name": { "version": "x.y.z" }
    
    # Extract package paths and versions using awk
    while IFS='|' read -r pkg_path version; do
      [[ -z "$pkg_path" || -z "$version" ]] && continue
      
      # Extract package name from path (e.g., "node_modules/@scope/pkg" -> "@scope/pkg")
      local pkg_name=""
      if [[ "$pkg_path" =~ node_modules/(.+) ]]; then
        pkg_name="${match[1]}"
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

PROJECT_COUNT=0

for project in "${NPM_PROJECTS[@]}"; do
  PROJECT_COUNT=$((PROJECT_COUNT + 1))
  
  if [[ $PROJECT_COUNT -gt $MAX_PROJECTS ]]; then
    RAW_OUTPUT="${RAW_OUTPUT}[Stopped at limit] "
    break
  fi
  
  display_path="${project}"
  [[ ${#project} -gt 50 ]] && display_path="...${project: -47}"
  
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

[[ ${#NPM_PROJECTS[@]} -eq 0 ]] && RAW_OUTPUT="No npm projects found" && OVERALL_STATUS="clean"

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

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" \
  -d "{\"secret\": \"${SECRET}\", \"serial\": \"${SERIAL}\", \"hostname\": \"${HOSTNAME}\", \"user\": \"${CURRENT_USER}\", \"os\": \"macOS\", \"status\": \"${OVERALL_STATUS}\", \"high_risk_count\": ${HIGH_RISK_COUNT}, \"medium_risk_count\": ${MEDIUM_RISK_COUNT}, \"low_risk_count\": ${LOW_RISK_COUNT}, \"high_risk_details\": \"${HIGH_RISK_DETAILS_ESCAPED}\", \"medium_risk_details\": \"${MEDIUM_RISK_DETAILS_ESCAPED}\", \"scan_duration_ms\": ${SCAN_DURATION}, \"scanner_version\": \"${SCANNER_VERSION}\", \"raw_output\": \"${RAW_OUTPUT_ESCAPED}\"}" \
  "${WEBHOOK_URL}" 2>/dev/null)

if [[ "${HTTP_CODE}" == "200" ]]; then
  log "✅ Results sent successfully"
else
  log "⚠️  Webhook returned: ${HTTP_CODE}"
fi

log "=== Scanner Complete ==="
exit 0