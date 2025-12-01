#!/bin/zsh

###############################################################################
# SHAI-HULUD 2.0 SCANNER - SELF-BACKGROUNDING (ALL-IN-ONE)
# Version: 2.0.3
# 
# This single script handles everything:
# 1. When run by Kandji, it copies itself and launches in background
# 2. The backgrounded copy does the actual scanning
# 3. Results are sent to webhook when complete
#
# Features:
# - No timeout: Backgrounds itself so Kandji exits immediately
# - Version-aware: Uses Cobenian detector for accurate detection
# - Performance-friendly: Runs at reduced priority
# - Error capture: Reports environment issues to Google Sheets
#
# No need to host separate files - just deploy this one script to Kandji.
###############################################################################

###############################################################################
# CONFIG
###############################################################################

WEBHOOK_URL="https://kandji-ack-worker.anthony-arashiro.workers.dev/scan"
SECRET='agile6isawesome!@#$QWERandSuperAWEsome'
SCANNER_VERSION="2.0.3"
MAX_PROJECTS=200

# PERFORMANCE SETTINGS
# Balanced settings - runs efficiently without hogging resources
NICE_LEVEL=10              # Moderate-low priority (0=normal, 19=lowest)
DELAY_BETWEEN_PROJECTS=0.2 # Brief pause to prevent sustained 100% CPU
SKIP_IF_ON_BATTERY=false   # Set to true to skip scan when on battery

# Cobenian scanner URLs (does proper version checking)
DETECTOR_URL="https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/shai-hulud-detector.sh"
PACKAGES_URL="https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/compromised-packages.txt"

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
  # We ARE the background process - do the actual scanning
  shift
  TEMP_DIR="$1"
  
  # Continue to scanning section below
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
  
  # Launch detached background process
  nohup /bin/zsh "${SCRIPT_COPY}" --background "${TEMP_DIR}" >> "${LOG_FILE}" 2>&1 &
  BG_PID=$!
  disown $BG_PID
  
  # Write lock file
  echo $BG_PID > "$LOCK_FILE"
  
  sleep 1
  
  if kill -0 $BG_PID 2>/dev/null; then
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

# Check if screen is locked or display is off
DISPLAY_STATE=$(ioreg -n IODisplayWrangler 2>/dev/null | grep -i "currentpowerstate" | head -1 | awk '{print $NF}')
if [[ "$DISPLAY_STATE" == "0" ]]; then
  WARNINGS="${WARNINGS}Display is off/sleeping; "
  log "INFO: Display appears to be off or sleeping"
fi

# Check macOS version for compatibility logging
MACOS_VERSION=$(sw_vers -productVersion 2>/dev/null || echo "Unknown")
log "INFO: macOS version: ${MACOS_VERSION}"

# Check available disk space (warn if < 1GB)
AVAILABLE_SPACE_KB=$(df -k /var/tmp 2>/dev/null | tail -1 | awk '{print $4}')
if [[ -n "$AVAILABLE_SPACE_KB" && "$AVAILABLE_SPACE_KB" -lt 1048576 ]]; then
  WARNINGS="${WARNINGS}Low disk space (<1GB); "
  log "WARNING: Low disk space on /var/tmp"
fi

# Check network connectivity to GitHub
if ! curl -s --connect-timeout 5 -o /dev/null "https://github.com"; then
  log "ERROR: Cannot reach github.com - network may be unavailable"
  # Still try to continue, will fail at download step with proper error
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

# Lower our CPU priority slightly so we don't compete with user apps
renice ${NICE_LEVEL} $$ >/dev/null 2>&1 || true

###############################################################################
# GATHER DEVICE INFO
###############################################################################

log "Step 1: Gathering device info..."

CURRENT_USER=$(/usr/bin/stat -f%Su /dev/console)
SERIAL=$(/usr/sbin/ioreg -l | /usr/bin/awk -F\" '/IOPlatformSerialNumber/ { print $4 }')
HOSTNAME=$(/usr/sbin/scutil --get ComputerName 2>/dev/null || hostname)
TIMESTAMP_UTC=$(/bin/date -u +"%Y-%m-%dT%H:%M:%SZ")
START_TIME=$(date +%s)

log "Host: ${HOSTNAME} | Serial: ${SERIAL} | User: ${CURRENT_USER}"

###############################################################################
# DOWNLOAD COBENIAN SCANNER
###############################################################################

log "Step 2: Downloading Cobenian scanner..."

DETECTOR_SCRIPT="${TEMP_DIR}/shai-hulud-detector.sh"
PACKAGES_FILE="${TEMP_DIR}/compromised-packages.txt"

send_error() {
  local msg="$1"
  log "ERROR: $msg"
  curl -s -X POST -H "Content-Type: application/json" \
    -d "{\"secret\": \"${SECRET}\", \"serial\": \"${SERIAL}\", \"hostname\": \"${HOSTNAME}\", \"user\": \"${CURRENT_USER}\", \"os\": \"macOS\", \"status\": \"error\", \"high_risk_count\": 0, \"medium_risk_count\": 0, \"low_risk_count\": 0, \"high_risk_details\": \"\", \"medium_risk_details\": \"\", \"scan_duration_ms\": 0, \"scanner_version\": \"${SCANNER_VERSION}\", \"raw_output\": \"${msg}\"}" \
    "${WEBHOOK_URL}"
}

if ! curl -fsSL --connect-timeout 30 --max-time 60 "${DETECTOR_URL}" -o "${DETECTOR_SCRIPT}" 2>&1; then
  send_error "Failed to download Cobenian detector script"
  exit 1
fi

if ! curl -fsSL --connect-timeout 30 --max-time 60 "${PACKAGES_URL}" -o "${PACKAGES_FILE}" 2>&1; then
  send_error "Failed to download compromised packages list"
  exit 1
fi

chmod +x "${DETECTOR_SCRIPT}"

PACKAGE_COUNT=$(grep -v '^#' "${PACKAGES_FILE}" | grep -v '^$' | wc -l | tr -d ' ')
log "Downloaded detector + ${PACKAGE_COUNT} compromised package signatures"

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
# RUN COBENIAN SCANNER
###############################################################################

log "Step 4: Running Cobenian scanner..."

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
  
  PROJECT_START=$(date +%s)
  
  # Run Cobenian detector
  cd "${TEMP_DIR}"
  SCAN_OUTPUT=$("${DETECTOR_SCRIPT}" "$project" 2>&1) || true
  EXIT_CODE=$?
  
  PROJECT_END=$(date +%s)
  PROJECT_DURATION=$((PROJECT_END - PROJECT_START))
  
  # Parse output
  high_in_project=0
  medium_in_project=0
  
  if echo "$SCAN_OUTPUT" | grep -q "HIGH RISK"; then
    high_in_project=$(echo "$SCAN_OUTPUT" | grep -c "HIGH RISK" 2>/dev/null || echo 0)
  fi
  if echo "$SCAN_OUTPUT" | grep -q "MEDIUM RISK"; then
    medium_in_project=$(echo "$SCAN_OUTPUT" | grep -c "MEDIUM RISK" 2>/dev/null || echo 0)
  fi
  
  # Fallback to exit code
  [[ $EXIT_CODE -eq 1 && $high_in_project -eq 0 ]] && high_in_project=1
  [[ $EXIT_CODE -eq 2 && $medium_in_project -eq 0 ]] && medium_in_project=1
  
  HIGH_RISK_COUNT=$((HIGH_RISK_COUNT + high_in_project))
  MEDIUM_RISK_COUNT=$((MEDIUM_RISK_COUNT + medium_in_project))
  
  if [[ $high_in_project -gt 0 ]]; then
    OVERALL_STATUS="affected"
    high_detail=$(echo "$SCAN_OUTPUT" | grep -A1 "HIGH RISK" | grep -v "HIGH RISK" | head -3 | tr '\n' '; ' | tr -cd '[:print:]' | cut -c1-150)
    HIGH_RISK_DETAILS="${HIGH_RISK_DETAILS}${display_path}: ${high_detail} | "
    RAW_OUTPUT="${RAW_OUTPUT}[${display_path}] HIGH:${high_in_project} "
    log "  ⚠️  ${display_path}: HIGH RISK"
  elif [[ $medium_in_project -gt 0 ]]; then
    [[ "$OVERALL_STATUS" == "clean" ]] && OVERALL_STATUS="warning"
    RAW_OUTPUT="${RAW_OUTPUT}[${display_path}] MEDIUM:${medium_in_project} "
    log "  ⚡ ${display_path}: MEDIUM RISK"
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

# Truncate
RAW_OUTPUT="${RAW_OUTPUT:0:5000}"
HIGH_RISK_DETAILS="${HIGH_RISK_DETAILS:0:1000}"
MEDIUM_RISK_DETAILS="${MEDIUM_RISK_DETAILS:0:1000}"

HTTP_CODE=$(python3 << PYTHON_SCRIPT
import json
import urllib.request
import urllib.error

data = {
    "secret": """${SECRET}""",
    "serial": """${SERIAL}""",
    "hostname": """${HOSTNAME}""",
    "user": """${CURRENT_USER}""",
    "os": "macOS",
    "status": """${OVERALL_STATUS}""",
    "high_risk_count": ${HIGH_RISK_COUNT},
    "medium_risk_count": ${MEDIUM_RISK_COUNT},
    "low_risk_count": ${LOW_RISK_COUNT},
    "high_risk_details": """${HIGH_RISK_DETAILS}""",
    "medium_risk_details": """${MEDIUM_RISK_DETAILS}""",
    "scan_duration_ms": ${SCAN_DURATION},
    "scanner_version": """${SCANNER_VERSION}""",
    "raw_output": """${RAW_OUTPUT}"""
}

req = urllib.request.Request(
    "${WEBHOOK_URL}",
    data=json.dumps(data).encode('utf-8'),
    headers={"Content-Type": "application/json"},
    method="POST"
)

try:
    with urllib.request.urlopen(req, timeout=30) as response:
        print(response.status)
except urllib.error.HTTPError as e:
    print(e.code)
except Exception as e:
    print("0")
PYTHON_SCRIPT
)

if [[ "${HTTP_CODE}" == "200" ]]; then
  log "✅ Results sent successfully"
else
  log "⚠️  Webhook returned: ${HTTP_CODE}"
fi

log "=== Scanner Complete ==="
exit 0