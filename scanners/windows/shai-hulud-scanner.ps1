#Requires -Version 5.1

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

$WEBHOOK_URL = "https://kandji-ack-worker.anthony-arashiro.workers.dev/scan"
$SECRET = 'agile6isawesome!@#$QWERandSuperAWEsome'
$SCANNER_VERSION = "2.0.3"
$MAX_PROJECTS = 200

# PERFORMANCE SETTINGS
# Balanced settings - runs efficiently without hogging resources
$DELAY_BETWEEN_PROJECTS = 0.2  # Brief pause to prevent sustained 100% CPU
$SKIP_IF_ON_BATTERY = $false  # Set to $true to skip scan when on battery

# Cobenian scanner URLs (does proper version checking)
$DETECTOR_URL = "https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/shai-hulud-detector.sh"
$PACKAGES_URL = "https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/compromised-packages.txt"

$SCAN_DIRS = @(
    "C:\Users"
)

$WORK_DIR = Join-Path $env:TEMP "shai-hulud"
$LOCK_FILE = Join-Path $env:TEMP "shai-hulud-scanner.lock"
$LOG_FILE = Join-Path $WORK_DIR "scanner.log"

###############################################################################
# CHECK IF WE'RE THE BACKGROUND PROCESS
###############################################################################

if ($args[0] -eq "--background") {
    # We ARE the background process - do the actual scanning
    $TEMP_DIR = $args[1]
    
    # Continue to scanning section below
} else {
    ###########################################################################
    # FOREGROUND MODE - Launch background and exit
    ###########################################################################
    
    Write-Host "=== Shai-Hulud 2.0 Scanner Launcher v$SCANNER_VERSION ==="
    Write-Host "Timestamp: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    
    # Check for existing run
    if (Test-Path $LOCK_FILE) {
        $EXISTING_PID = Get-Content $LOCK_FILE -ErrorAction SilentlyContinue
        if ($EXISTING_PID -and (Get-Process -Id $EXISTING_PID -ErrorAction SilentlyContinue)) {
            Write-Host "Scanner already running (PID: $EXISTING_PID). Exiting."
            exit 0
        }
        Remove-Item $LOCK_FILE -Force -ErrorAction SilentlyContinue
    }
    
    # Setup
    New-Item -ItemType Directory -Path $WORK_DIR -Force | Out-Null
    $TEMP_DIR = Join-Path $WORK_DIR "scan-$PID"
    New-Item -ItemType Directory -Path $TEMP_DIR -Force | Out-Null
    
    # Copy this script to temp location for background execution
    $SCRIPT_COPY = Join-Path $TEMP_DIR "scanner.ps1"
    Copy-Item $MyInvocation.PSCommandPath $SCRIPT_COPY -Force
    
    Write-Host "Launching scanner in background..."
    
    # Launch detached background process
    $job = Start-Job -ScriptBlock {
        param($ScriptPath, $TempDir, $LogFile)
        & $ScriptPath --background $TempDir *>> $LogFile
    } -ArgumentList $SCRIPT_COPY, $TEMP_DIR, $LOG_FILE
    
    # Write lock file with job ID (PowerShell job IDs are different from PIDs)
    $job.Id | Out-File $LOCK_FILE -Force
    
    Start-Sleep -Seconds 1
    
    if ($job.State -eq "Running") {
        Write-Host "✅ Scanner launched (Job ID: $($job.Id))"
        Write-Host "Log: $LOG_FILE"
        Write-Host "Results will be sent to webhook when complete."
    } else {
        Write-Host "⚠️  Scanner may have exited - check $LOG_FILE"
    }
    
    Write-Host "Launcher exiting."
    exit 0
}

###############################################################################
# BACKGROUND MODE - ACTUAL SCANNING STARTS HERE
###############################################################################

function Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output "[$timestamp] $Message"
}

function Cleanup {
    Log "Cleaning up..."
    if ($TEMP_DIR -and (Test-Path $TEMP_DIR)) {
        Remove-Item $TEMP_DIR -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $LOCK_FILE) {
        Remove-Item $LOCK_FILE -Force -ErrorAction SilentlyContinue
    }
}

# Register cleanup on exit
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action { Cleanup } | Out-Null

Log "=== Background Scanner Started (PID: $PID) ==="

###############################################################################
# ENVIRONMENT CHECKS & ERROR CAPTURE
###############################################################################

$WARNINGS = ""

# Check if user is logged in at console
try {
    $CURRENT_USER = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    if ($CURRENT_USER -match "SYSTEM" -or $CURRENT_USER -match "NT AUTHORITY") {
        $WARNINGS += "No user logged in at console; "
        Log "WARNING: Running as system account"
    }
} catch {
    $WARNINGS += "Could not determine user; "
    Log "WARNING: Could not determine current user"
}

# Check power source
try {
    $battery = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue
    if ($battery) {
        if ($battery.BatteryStatus -eq 2) {  # 2 = On battery
            $WARNINGS += "Running on battery; "
            Log "INFO: Running on battery power"
        }
    }
} catch {
    # Battery check failed, continue
}

# Check Windows version for compatibility logging
try {
    $OS_VERSION = (Get-CimInstance Win32_OperatingSystem).Version
    Log "INFO: Windows version: $OS_VERSION"
} catch {
    Log "INFO: Could not determine Windows version"
}

# Check available disk space (warn if < 1GB)
try {
    $drive = Get-PSDrive -Name (Split-Path $env:TEMP -Qualifier).TrimEnd(':')
    $availableSpaceGB = $drive.Free / 1GB
    if ($availableSpaceGB -lt 1) {
        $WARNINGS += "Low disk space (<1GB); "
        Log "WARNING: Low disk space on $env:TEMP"
    }
} catch {
    # Disk space check failed, continue
}

# Check network connectivity to GitHub
try {
    $response = Invoke-WebRequest -Uri "https://github.com" -Method Head -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
} catch {
    Log "ERROR: Cannot reach github.com - network may be unavailable"
    # Still try to continue, will fail at download step with proper error
}

###############################################################################
# PERFORMANCE SAFEGUARDS
###############################################################################

# Check if on battery (optional skip)
if ($SKIP_IF_ON_BATTERY) {
    try {
        $battery = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue
        if ($battery -and $battery.BatteryStatus -eq 2) {
            Log "On battery power - skipping scan (SKIP_IF_ON_BATTERY=true)"
            $body = @{
                secret = $SECRET
                serial = $SERIAL
                hostname = $HOSTNAME
                user = $CURRENT_USER
                os = "Windows"
                status = "skipped"
                high_risk_count = 0
                medium_risk_count = 0
                low_risk_count = 0
                high_risk_details = ""
                medium_risk_details = ""
                scan_duration_ms = 0
                scanner_version = $SCANNER_VERSION
                raw_output = "Skipped - on battery power"
            } | ConvertTo-Json
            
            Invoke-RestMethod -Uri $WEBHOOK_URL -Method Post -Body $body -ContentType "application/json" -ErrorAction SilentlyContinue | Out-Null
            exit 0
        }
    } catch {
        # Continue if battery check fails
    }
}

# Lower our CPU priority so we don't compete with user apps
try {
    $process = Get-Process -Id $PID
    $process.PriorityClass = "BelowNormal"
} catch {
    # Priority change failed, continue
}

###############################################################################
# GATHER DEVICE INFO
###############################################################################

Log "Step 1: Gathering device info..."

try {
    $CURRENT_USER = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
} catch {
    $CURRENT_USER = $env:USERNAME
}

try {
    $SERIAL = (Get-CimInstance Win32_BaseBoard).SerialNumber
    if (-not $SERIAL) {
        $SERIAL = (Get-CimInstance Win32_BIOS).SerialNumber
    }
} catch {
    $SERIAL = "Unknown"
}

$HOSTNAME = $env:COMPUTERNAME
$TIMESTAMP_UTC = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$START_TIME = (Get-Date).ToUniversalTime()

Log "Host: $HOSTNAME | Serial: $SERIAL | User: $CURRENT_USER"

###############################################################################
# DOWNLOAD COBENIAN SCANNER
###############################################################################

Log "Step 2: Downloading Cobenian scanner..."

$DETECTOR_SCRIPT = Join-Path $TEMP_DIR "shai-hulud-detector.sh"
$PACKAGES_FILE = Join-Path $TEMP_DIR "compromised-packages.txt"

function Send-Error {
    param([string]$Message)
    Log "ERROR: $Message"
    
    $body = @{
        secret = $SECRET
        serial = $SERIAL
        hostname = $HOSTNAME
        user = $CURRENT_USER
        os = "Windows"
        status = "error"
        high_risk_count = 0
        medium_risk_count = 0
        low_risk_count = 0
        high_risk_details = ""
        medium_risk_details = ""
        scan_duration_ms = 0
        scanner_version = $SCANNER_VERSION
        raw_output = $Message
    } | ConvertTo-Json
    
    try {
        Invoke-RestMethod -Uri $WEBHOOK_URL -Method Post -Body $body -ContentType "application/json" -ErrorAction SilentlyContinue | Out-Null
    } catch {
        # Error sending error report, continue
    }
}

try {
    Invoke-WebRequest -Uri $DETECTOR_URL -OutFile $DETECTOR_SCRIPT -TimeoutSec 60 -ErrorAction Stop
} catch {
    Send-Error "Failed to download Cobenian detector script"
    exit 1
}

try {
    Invoke-WebRequest -Uri $PACKAGES_URL -OutFile $PACKAGES_FILE -TimeoutSec 60 -ErrorAction Stop
} catch {
    Send-Error "Failed to download compromised packages list"
    exit 1
}

# Count packages (excluding comments and empty lines)
$PACKAGE_COUNT = (Get-Content $PACKAGES_FILE | Where-Object { $_ -notmatch '^\s*#' -and $_ -notmatch '^\s*$' }).Count
Log "Downloaded detector + $PACKAGE_COUNT compromised package signatures"

###############################################################################
# FIND NPM PROJECTS
###############################################################################

Log "Step 3: Finding npm projects..."
$NPM_PROJECTS = @()

foreach ($baseDir in $SCAN_DIRS) {
    if (Test-Path $baseDir) {
        $packageFiles = Get-ChildItem -Path $baseDir -Filter "package.json" -Recurse -Depth 6 -File -ErrorAction SilentlyContinue | 
            Where-Object {
                $fullPath = $_.FullName
                $fullPath -notmatch '\\node_modules\\' -and
                $fullPath -notmatch '\\.npm\\' -and
                $fullPath -notmatch '\\.nvm\\versions\\' -and
                $fullPath -notmatch '\\Library\\Caches\\' -and
                $fullPath -notmatch '\\.cache\\' -and
                $fullPath -notmatch '\\\$Recycle\.Bin\\' -and
                $fullPath -notmatch '\\.vscode\\' -and
                $fullPath -notmatch '\\.cursor\\' -and
                $fullPath -notmatch '\\AppData\\Local\\Application Data\\'
            }
        
        foreach ($pkgFile in $packageFiles) {
            $projectDir = $pkgFile.DirectoryName
            $NPM_PROJECTS += $projectDir
            
            if ($NPM_PROJECTS.Count -ge $MAX_PROJECTS) {
                Log "Reached project limit ($MAX_PROJECTS)"
                break
            }
        }
        
        if ($NPM_PROJECTS.Count -ge $MAX_PROJECTS) {
            break
        }
    }
}

Log "Found $($NPM_PROJECTS.Count) npm projects to scan"

###############################################################################
# RUN COBENIAN SCANNER
###############################################################################

Log "Step 4: Running Cobenian scanner..."

$HIGH_RISK_COUNT = 0
$MEDIUM_RISK_COUNT = 0
$LOW_RISK_COUNT = 0
$HIGH_RISK_DETAILS = ""
$MEDIUM_RISK_DETAILS = ""
$RAW_OUTPUT = ""
$OVERALL_STATUS = "clean"

$PROJECT_COUNT = 0

foreach ($project in $NPM_PROJECTS) {
    $PROJECT_COUNT++
    
    if ($PROJECT_COUNT -gt $MAX_PROJECTS) {
        $RAW_OUTPUT += "[Stopped at limit] "
        break
    }
    
    $displayPath = $project
    if ($project.Length -gt 50) {
        $displayPath = "..." + $project.Substring($project.Length - 47)
    }
    
    $PROJECT_START = Get-Date
    
    # Run Cobenian detector
    # Note: The detector script is a bash script, so we need to run it via WSL, Git Bash, or similar
    # For Windows, we'll try to use Git Bash if available, otherwise we'll need to adapt
    $SCAN_OUTPUT = ""
    $EXIT_CODE = 0
    
    try {
        # Try to find bash (Git Bash, WSL, or MSYS2)
        $bashPath = $null
        $possibleBashPaths = @(
            "C:\Program Files\Git\bin\bash.exe",
            "C:\Program Files (x86)\Git\bin\bash.exe",
            "$env:LOCALAPPDATA\Programs\Git\bin\bash.exe",
            "bash.exe"  # If in PATH
        )
        
        foreach ($path in $possibleBashPaths) {
            if (Test-Path $path -ErrorAction SilentlyContinue) {
                $bashPath = $path
                break
            }
        }
        
        if (-not $bashPath) {
            # Try to find bash in PATH
            $bashPath = (Get-Command bash -ErrorAction SilentlyContinue).Source
        }
        
        if ($bashPath) {
            Push-Location $TEMP_DIR
            $process = Start-Process -FilePath $bashPath -ArgumentList $DETECTOR_SCRIPT, $project -NoNewWindow -Wait -PassThru -RedirectStandardOutput "$TEMP_DIR\scan_output.txt" -RedirectStandardError "$TEMP_DIR\scan_error.txt"
            $EXIT_CODE = $process.ExitCode
            $SCAN_OUTPUT = Get-Content "$TEMP_DIR\scan_output.txt" -Raw -ErrorAction SilentlyContinue
            $SCAN_ERROR = Get-Content "$TEMP_DIR\scan_error.txt" -Raw -ErrorAction SilentlyContinue
            if ($SCAN_ERROR) {
                $SCAN_OUTPUT += "`n$SCAN_ERROR"
            }
            Pop-Location
        } else {
            throw "Bash not found - cannot run detector script"
        }
    } catch {
        $SCAN_OUTPUT = "ERROR: Could not run detector: $_"
        $EXIT_CODE = 1
    }
    
    $PROJECT_END = Get-Date
    $PROJECT_DURATION = ($PROJECT_END - $PROJECT_START).TotalSeconds
    
    # Parse output
    $highInProject = 0
    $mediumInProject = 0
    
    if ($SCAN_OUTPUT -match "HIGH RISK") {
        $highInProject = ([regex]::Matches($SCAN_OUTPUT, "HIGH RISK")).Count
    }
    if ($SCAN_OUTPUT -match "MEDIUM RISK") {
        $mediumInProject = ([regex]::Matches($SCAN_OUTPUT, "MEDIUM RISK")).Count
    }
    
    # Fallback to exit code
    if ($EXIT_CODE -eq 1 -and $highInProject -eq 0) {
        $highInProject = 1
    }
    if ($EXIT_CODE -eq 2 -and $mediumInProject -eq 0) {
        $mediumInProject = 1
    }
    
    $HIGH_RISK_COUNT += $highInProject
    $MEDIUM_RISK_COUNT += $mediumInProject
    
    if ($highInProject -gt 0) {
        $OVERALL_STATUS = "affected"
        $highDetail = ($SCAN_OUTPUT | Select-String -Pattern "HIGH RISK" -Context 0,1 | Select-Object -First 3 | ForEach-Object { $_.Line -replace "HIGH RISK", "" -replace "`n", "; " -replace "`r", "" }).Trim() -join "; "
        if ($highDetail.Length -gt 150) {
            $highDetail = $highDetail.Substring(0, 150)
        }
        $HIGH_RISK_DETAILS += "$displayPath`: $highDetail | "
        $RAW_OUTPUT += "[$displayPath] HIGH:$highInProject "
        Log "  ⚠️  $displayPath`: HIGH RISK"
    } elseif ($mediumInProject -gt 0) {
        if ($OVERALL_STATUS -eq "clean") {
            $OVERALL_STATUS = "warning"
        }
        $RAW_OUTPUT += "[$displayPath] MEDIUM:$mediumInProject "
        Log "  ⚡ $displayPath`: MEDIUM RISK"
    } else {
        $RAW_OUTPUT += "[$displayPath] clean "
    }
    
    # Brief pause between projects
    Start-Sleep -Seconds $DELAY_BETWEEN_PROJECTS
}

if ($NPM_PROJECTS.Count -eq 0) {
    $RAW_OUTPUT = "No npm projects found"
    $OVERALL_STATUS = "clean"
}

# Prepend any warnings to raw output
if ($WARNINGS) {
    $RAW_OUTPUT = "[WARNINGS: $WARNINGS] $RAW_OUTPUT"
}

###############################################################################
# SEND RESULTS
###############################################################################

$END_TIME = Get-Date
$SCAN_DURATION = [math]::Round((($END_TIME - $START_TIME).TotalMilliseconds))

Log "Step 5: Sending results..."
Log "Status: $OVERALL_STATUS | High: $HIGH_RISK_COUNT | Medium: $MEDIUM_RISK_COUNT | Duration: ${SCAN_DURATION}ms"

# Truncate
if ($RAW_OUTPUT.Length -gt 5000) {
    $RAW_OUTPUT = $RAW_OUTPUT.Substring(0, 5000)
}
if ($HIGH_RISK_DETAILS.Length -gt 1000) {
    $HIGH_RISK_DETAILS = $HIGH_RISK_DETAILS.Substring(0, 1000)
}
if ($MEDIUM_RISK_DETAILS.Length -gt 1000) {
    $MEDIUM_RISK_DETAILS = $MEDIUM_RISK_DETAILS.Substring(0, 1000)
}

$body = @{
    secret = $SECRET
    serial = $SERIAL
    hostname = $HOSTNAME
    user = $CURRENT_USER
    os = "Windows"
    status = $OVERALL_STATUS
    high_risk_count = $HIGH_RISK_COUNT
    medium_risk_count = $MEDIUM_RISK_COUNT
    low_risk_count = $LOW_RISK_COUNT
    high_risk_details = $HIGH_RISK_DETAILS
    medium_risk_details = $MEDIUM_RISK_DETAILS
    scan_duration_ms = $SCAN_DURATION
    scanner_version = $SCANNER_VERSION
    raw_output = $RAW_OUTPUT
}

try {
    $response = Invoke-RestMethod -Uri $WEBHOOK_URL -Method Post -Body ($body | ConvertTo-Json) -ContentType "application/json" -ErrorAction Stop
    $HTTP_CODE = 200
} catch {
    if ($_.Exception.Response) {
        $HTTP_CODE = [int]$_.Exception.Response.StatusCode
    } else {
        $HTTP_CODE = 0
    }
}

if ($HTTP_CODE -eq 200) {
    Log "✅ Results sent successfully"
} else {
    Log "⚠️  Webhook returned: $HTTP_CODE"
}

Log "=== Scanner Complete ==="
exit 0
