#Requires -Version 5.1

<#
.SYNOPSIS
    Shai-Hulud 2.0 Scanner - Native PowerShell Edition
    
.DESCRIPTION
    Scans Windows endpoints for npm packages compromised by the Shai-Hulud 
    supply chain attack. Downloads Cobenian's compromised packages list and
    performs all scanning natively in PowerShell (no bash/WSL required).
    
    Features:
    - Self-backgrounding: Action1 exits immediately, scan runs independently
    - Version-aware: Checks exact package:version pairs (no false positives)
    - Performance-friendly: Runs at reduced priority
    - Error capture: Reports environment issues to Google Sheets
    
.VERSION
    2.0.6
    
.NOTES
    Deploy via Action1 MDM. Results sent to webhook -> Google Sheets.
#>

###############################################################################
# CONFIG
###############################################################################

$WEBHOOK_URL = "https://kandji-ack-worker.anthony-arashiro.workers.dev/scan"
$SECRET = "YOUR_SHARED_SECRET_HERE"
$SCANNER_VERSION = "2.0.7"
$MAX_PROJECTS = 200

# PERFORMANCE SETTINGS
$DELAY_BETWEEN_PROJECTS = 0.2  # Seconds between projects
$SKIP_IF_ON_BATTERY = $false   # Set to $true to skip when on battery

# Cobenian packages list (we only need this - scanning logic is native PowerShell)
$PACKAGES_URL = "https://raw.githubusercontent.com/mutsuoara/a6-shai-hulud-response/main/ioc/compromised-packages.txt"

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
    $TEMP_DIR = $args[1]
    # Continue to scanning section below
} else {
    ###########################################################################
    # FOREGROUND MODE - Launch background and exit immediately
    ###########################################################################
    
    Write-Host "=== Shai-Hulud 2.0 Scanner Launcher v$SCANNER_VERSION ==="
    Write-Host "Timestamp: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    
    # Check for existing run
    if (Test-Path $LOCK_FILE) {
        $lockContent = Get-Content $LOCK_FILE -ErrorAction SilentlyContinue
        if ($lockContent) {
            $existingPid = [int]$lockContent
            $existingProcess = Get-Process -Id $existingPid -ErrorAction SilentlyContinue
            if ($existingProcess) {
                Write-Host "Scanner already running (PID: $existingPid). Exiting."
                exit 0
            }
        }
        Remove-Item $LOCK_FILE -Force -ErrorAction SilentlyContinue
    }
    
    # Setup directories
    New-Item -ItemType Directory -Path $WORK_DIR -Force | Out-Null
    $TEMP_DIR = Join-Path $WORK_DIR "scan-$PID"
    New-Item -ItemType Directory -Path $TEMP_DIR -Force | Out-Null
    
    # Copy script for background execution
    $SCRIPT_COPY = Join-Path $TEMP_DIR "scanner.ps1"
    Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $SCRIPT_COPY -Force
    
    Write-Host "Launching scanner in background..."
    
    # Launch truly detached background process using Start-Process
    # This creates a new process that survives parent exit
    $processArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$SCRIPT_COPY`" --background `"$TEMP_DIR`""
    $bgProcess = Start-Process -FilePath "powershell.exe" `
        -ArgumentList $processArgs `
        -WindowStyle Hidden `
        -PassThru `
        -RedirectStandardOutput (Join-Path $TEMP_DIR "stdout.log") `
        -RedirectStandardError (Join-Path $TEMP_DIR "stderr.log")
    
    # Write lock file with actual PID
    $bgProcess.Id | Out-File -FilePath $LOCK_FILE -Force
    
    Start-Sleep -Seconds 2
    
    # Verify process started
    $checkProcess = Get-Process -Id $bgProcess.Id -ErrorAction SilentlyContinue
    if ($checkProcess) {
        Write-Host "Scanner launched (PID: $($bgProcess.Id))"
        Write-Host "Log: $LOG_FILE"
        Write-Host "Results will be sent to webhook when complete."
    } else {
        Write-Host "WARNING: Scanner may have exited - check logs"
    }
    
    Write-Host "Launcher exiting."
    exit 0
}

###############################################################################
# BACKGROUND MODE - ACTUAL SCANNING STARTS HERE
###############################################################################

# Redirect all output to log file
Start-Transcript -Path $LOG_FILE -Append -Force | Out-Null

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] $Message"
}

function Remove-LockAndCleanup {
    Write-Log "Cleaning up..."
    if ($TEMP_DIR -and (Test-Path $TEMP_DIR)) {
        Remove-Item -Path $TEMP_DIR -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $LOCK_FILE) {
        Remove-Item -Path $LOCK_FILE -Force -ErrorAction SilentlyContinue
    }
    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
}

# Write our PID to lock file
$PID | Out-File -FilePath $LOCK_FILE -Force

Write-Log "=== Background Scanner Started (PID: $PID) ==="

###############################################################################
# ENVIRONMENT CHECKS & ERROR CAPTURE
###############################################################################

$WARNINGS = @()

# Get current user
try {
    $CURRENT_USER = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    if ($CURRENT_USER -match "SYSTEM|NT AUTHORITY") {
        $WARNINGS += "Running as SYSTEM account"
        Write-Log "WARNING: Running as SYSTEM account"
    }
} catch {
    $CURRENT_USER = $env:USERNAME
    if (-not $CURRENT_USER) { $CURRENT_USER = "Unknown" }
    $WARNINGS += "Could not determine user"
}

# Check power source
try {
    $battery = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue
    if ($battery -and $battery.BatteryStatus -eq 1) {
        $WARNINGS += "Running on battery"
        Write-Log "INFO: Running on battery power"
    }
} catch { }

# Check Windows version
try {
    $osInfo = Get-CimInstance Win32_OperatingSystem
    Write-Log "INFO: Windows $($osInfo.Caption) - $($osInfo.Version)"
} catch {
    Write-Log "INFO: Could not determine Windows version"
}

# Check disk space
try {
    $tempDrive = (Get-Item $env:TEMP).PSDrive
    $freeGB = [math]::Round($tempDrive.Free / 1GB, 2)
    if ($freeGB -lt 1) {
        $WARNINGS += "Low disk space (${freeGB}GB)"
        Write-Log "WARNING: Low disk space on temp drive"
    }
} catch { }

# Check network connectivity
try {
    $null = Invoke-WebRequest -Uri "https://github.com" -Method Head -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
} catch {
    Write-Log "WARNING: Cannot reach github.com"
    $WARNINGS += "Network connectivity issue"
}

###############################################################################
# PERFORMANCE SAFEGUARDS
###############################################################################

# Optional: Skip if on battery
if ($SKIP_IF_ON_BATTERY) {
    try {
        $battery = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue
        if ($battery -and $battery.BatteryStatus -eq 1) {
            Write-Log "On battery power - skipping scan"
            # Send skip notification and exit
            $skipBody = @{
                secret = $SECRET
                serial = "Unknown"
                hostname = $env:COMPUTERNAME
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
            } | ConvertTo-Json -Compress
            
            try {
                Invoke-RestMethod -Uri $WEBHOOK_URL -Method Post -Body $skipBody -ContentType "application/json" -TimeoutSec 30 | Out-Null
            } catch { }
            
            Remove-LockAndCleanup
            exit 0
        }
    } catch { }
}

# Lower CPU priority
try {
    $currentProcess = Get-Process -Id $PID
    $currentProcess.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal
    Write-Log "Set process priority to BelowNormal"
} catch {
    Write-Log "Could not adjust process priority"
}

###############################################################################
# GATHER DEVICE INFO
###############################################################################

Write-Log "Step 1: Gathering device info..."

$SERIAL = "Unknown"
try {
    $bios = Get-CimInstance Win32_BIOS -ErrorAction Stop
    $SERIAL = $bios.SerialNumber
    if (-not $SERIAL -or $SERIAL -eq "To be filled by O.E.M.") {
        $board = Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue
        if ($board.SerialNumber) {
            $SERIAL = $board.SerialNumber
        }
    }
} catch {
    Write-Log "WARNING: Could not get serial number"
}

$HOSTNAME = $env:COMPUTERNAME
$START_TIME = Get-Date

Write-Log "Host: $HOSTNAME | Serial: $SERIAL | User: $CURRENT_USER"

###############################################################################
# DOWNLOAD COMPROMISED PACKAGES LIST
###############################################################################

Write-Log "Step 2: Downloading compromised packages list..."

$PACKAGES_FILE = Join-Path $TEMP_DIR "compromised-packages.txt"

function Send-ErrorReport {
    param([string]$Message)
    Write-Log "ERROR: $Message"
    
    $errorBody = @{
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
    } | ConvertTo-Json -Compress
    
    try {
        Invoke-RestMethod -Uri $WEBHOOK_URL -Method Post -Body $errorBody -ContentType "application/json" -TimeoutSec 30 | Out-Null
    } catch {
        Write-Log "Failed to send error report"
    }
}

try {
    Invoke-WebRequest -Uri $PACKAGES_URL -OutFile $PACKAGES_FILE -TimeoutSec 60 -UseBasicParsing -ErrorAction Stop
} catch {
    Send-ErrorReport "Failed to download compromised packages list: $_"
    Remove-LockAndCleanup
    exit 1
}

# Parse compromised packages into hashtable for O(1) lookups
# Format: package_name:version
$CompromisedPackages = @{}
$packageLines = Get-Content $PACKAGES_FILE -ErrorAction SilentlyContinue

foreach ($line in $packageLines) {
    $line = $line.Trim()
    if ($line -and -not $line.StartsWith('#')) {
        $CompromisedPackages[$line] = $true
    }
}

$PACKAGE_COUNT = $CompromisedPackages.Count
Write-Log "Loaded $PACKAGE_COUNT compromised package:version signatures"

###############################################################################
# NATIVE POWERSHELL LOCKFILE PARSER
###############################################################################

function Get-CompromisedPackagesInProject {
    param(
        [string]$ProjectPath,
        [hashtable]$CompromisedList
    )
    
    $findings = @()
    
    # Check package-lock.json first (has exact versions)
    $lockFile = Join-Path $ProjectPath "package-lock.json"
    
    if (Test-Path $lockFile) {
        try {
            $lockContent = Get-Content $lockFile -Raw -ErrorAction Stop
            
            # PowerShell 5.1 CANNOT parse JSON with empty string keys like "": {...}
            # npm lockfile v3 uses this for the root package. We must remove it.
            # Replace "": { with "__root__": { to make it parseable
            $lockContent = $lockContent -replace '""\s*:\s*\{', '"__root__": {'
            
            $lock = $lockContent | ConvertFrom-Json -ErrorAction Stop
            
            # npm lockfile v2/v3 format (lockfileVersion 2 or 3)
            if ($lock.packages) {
                foreach ($pkgPath in $lock.packages.PSObject.Properties.Name) {
                    # Skip root package (either empty or our renamed __root__)
                    if (-not $pkgPath -or $pkgPath -eq "__root__") { continue }
                    
                    $pkgInfo = $lock.packages.$pkgPath
                    $version = $pkgInfo.version
                    
                    if (-not $version) { continue }
                    
                    # Extract package name from path like "node_modules/@scope/pkg"
                    $pkgName = $pkgPath
                    if ($pkgPath -match 'node_modules[/\\](.+)$') {
                        $pkgName = $Matches[1]
                    }
                    
                    # Check against compromised list
                    $checkKey = "${pkgName}:${version}"
                    if ($CompromisedList.ContainsKey($checkKey)) {
                        $findings += "${pkgName}@${version}"
                    }
                }
            }
            
            # npm lockfile v1 format (older)
            if ($findings.Count -eq 0 -and $lock.dependencies) {
                $depsToCheck = New-Object System.Collections.Queue
                
                foreach ($depName in $lock.dependencies.PSObject.Properties.Name) {
                    $depsToCheck.Enqueue(@{Name = $depName; Info = $lock.dependencies.$depName})
                }
                
                while ($depsToCheck.Count -gt 0) {
                    $dep = $depsToCheck.Dequeue()
                    $depName = $dep.Name
                    $depInfo = $dep.Info
                    
                    if ($depInfo.version) {
                        $checkKey = "${depName}:$($depInfo.version)"
                        if ($CompromisedList.ContainsKey($checkKey)) {
                            $findings += "${depName}@$($depInfo.version)"
                        }
                    }
                    
                    # Check nested dependencies
                    if ($depInfo.dependencies) {
                        foreach ($nestedName in $depInfo.dependencies.PSObject.Properties.Name) {
                            $depsToCheck.Enqueue(@{Name = $nestedName; Info = $depInfo.dependencies.$nestedName})
                        }
                    }
                }
            }
        } catch {
            Write-Log "    Warning: Could not parse lockfile in $ProjectPath - $_"
        }
    } else {
        # Fallback: check package.json for exact versions only
        $pkgJsonFile = Join-Path $ProjectPath "package.json"
        
        if (Test-Path $pkgJsonFile) {
            try {
                $pkgContent = Get-Content $pkgJsonFile -Raw -ErrorAction Stop
                $pkg = $pkgContent | ConvertFrom-Json -ErrorAction Stop
                
                $depTypes = @('dependencies', 'devDependencies', 'optionalDependencies')
                
                foreach ($depType in $depTypes) {
                    if ($pkg.$depType) {
                        foreach ($depName in $pkg.$depType.PSObject.Properties.Name) {
                            $versionSpec = $pkg.$depType.$depName
                            
                            # Only check exact versions (no ^, ~, >, <, *, etc.)
                            if ($versionSpec -and $versionSpec -notmatch '[\^~><*|x ]') {
                                $checkKey = "${depName}:${versionSpec}"
                                if ($CompromisedList.ContainsKey($checkKey)) {
                                    $findings += "${depName}@${versionSpec}"
                                }
                            }
                        }
                    }
                }
            } catch {
                Write-Log "    Warning: Could not parse package.json in $ProjectPath"
            }
        }
    }
    
    return $findings | Select-Object -Unique
}

###############################################################################
# FIND NPM PROJECTS
###############################################################################

Write-Log "Step 3: Finding npm projects..."

$NPM_PROJECTS = @()

foreach ($baseDir in $SCAN_DIRS) {
    if (-not (Test-Path $baseDir)) { continue }
    
    try {
        $packageFiles = Get-ChildItem -Path $baseDir -Filter "package.json" -Recurse -Depth 6 -File -ErrorAction SilentlyContinue |
            Where-Object {
                $fp = $_.FullName
                $fp -notmatch '\\node_modules\\' -and
                $fp -notmatch '\\.npm\\' -and
                $fp -notmatch '\\.nvm\\' -and
                $fp -notmatch '\\AppData\\Local\\' -and
                $fp -notmatch '\\AppData\\Roaming\\' -and
                $fp -notmatch '\\\$Recycle\.Bin\\' -and
                $fp -notmatch '\\.vscode\\' -and
                $fp -notmatch '\\.cursor\\' -and
                $fp -notmatch '\\temp\\' -and
                $fp -notmatch '\\tmp\\'
            }
        
        foreach ($pkgFile in $packageFiles) {
            $NPM_PROJECTS += $pkgFile.DirectoryName
            
            if ($NPM_PROJECTS.Count -ge $MAX_PROJECTS) {
                Write-Log "Reached project limit ($MAX_PROJECTS)"
                break
            }
        }
    } catch {
        Write-Log "Warning: Error scanning $baseDir"
    }
    
    if ($NPM_PROJECTS.Count -ge $MAX_PROJECTS) { break }
}

# Remove duplicates
$NPM_PROJECTS = $NPM_PROJECTS | Select-Object -Unique

Write-Log "Found $($NPM_PROJECTS.Count) npm projects to scan"

###############################################################################
# SCAN PROJECTS
###############################################################################

Write-Log "Step 4: Scanning projects..."

$HIGH_RISK_COUNT = 0
$MEDIUM_RISK_COUNT = 0
$LOW_RISK_COUNT = 0
$HIGH_RISK_DETAILS = ""
$MEDIUM_RISK_DETAILS = ""
$RAW_OUTPUT = ""
$OVERALL_STATUS = "clean"

$projectNum = 0

foreach ($project in $NPM_PROJECTS) {
    $projectNum++
    
    if ($projectNum -gt $MAX_PROJECTS) {
        $RAW_OUTPUT += "[Stopped at limit] "
        break
    }
    
    # Truncate path for display
    $displayPath = $project
    if ($project.Length -gt 50) {
        $displayPath = "..." + $project.Substring($project.Length - 47)
    }
    
    $projectStart = Get-Date
    
    # Run native scanner
    $findings = Get-CompromisedPackagesInProject -ProjectPath $project -CompromisedList $CompromisedPackages
    
    $projectEnd = Get-Date
    $projectDuration = [math]::Round(($projectEnd - $projectStart).TotalSeconds, 1)
    
    $highInProject = $findings.Count
    
    if ($highInProject -gt 0) {
        $OVERALL_STATUS = "affected"
        $HIGH_RISK_COUNT += $highInProject
        
        $findingsStr = ($findings | Select-Object -First 5) -join "; "
        if ($findingsStr.Length -gt 150) {
            $findingsStr = $findingsStr.Substring(0, 147) + "..."
        }
        
        $HIGH_RISK_DETAILS += "${displayPath}: ${findingsStr} | "
        $RAW_OUTPUT += "[${displayPath}] COMPROMISED:${highInProject} "
        Write-Log "  FOUND ${highInProject} compromised: $displayPath"
        Write-Log "    Packages: $($findings -join ', ')"
    } else {
        $RAW_OUTPUT += "[${displayPath}] clean "
    }
    
    # Brief pause between projects
    Start-Sleep -Seconds $DELAY_BETWEEN_PROJECTS
}

if ($NPM_PROJECTS.Count -eq 0) {
    $RAW_OUTPUT = "No npm projects found"
    $OVERALL_STATUS = "clean"
}

# Add warnings to output
if ($WARNINGS.Count -gt 0) {
    $warningsStr = $WARNINGS -join "; "
    $RAW_OUTPUT = "[WARNINGS: $warningsStr] $RAW_OUTPUT"
}

###############################################################################
# SEND RESULTS
###############################################################################

$END_TIME = Get-Date
$SCAN_DURATION = [math]::Round(($END_TIME - $START_TIME).TotalMilliseconds)

Write-Log "Step 5: Sending results..."
Write-Log "Status: $OVERALL_STATUS | High: $HIGH_RISK_COUNT | Duration: ${SCAN_DURATION}ms"

# Truncate fields
if ($RAW_OUTPUT.Length -gt 5000) {
    $RAW_OUTPUT = $RAW_OUTPUT.Substring(0, 5000)
}
if ($HIGH_RISK_DETAILS.Length -gt 1000) {
    $HIGH_RISK_DETAILS = $HIGH_RISK_DETAILS.Substring(0, 1000)
}

$resultBody = @{
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
} | ConvertTo-Json -Compress

try {
    $response = Invoke-RestMethod -Uri $WEBHOOK_URL -Method Post -Body $resultBody -ContentType "application/json" -TimeoutSec 30
    Write-Log "Results sent successfully"
} catch {
    Write-Log "WARNING: Failed to send results - $_"
}

###############################################################################
# CLEANUP AND EXIT
###############################################################################

Write-Log "=== Scanner Complete ==="

if ($HIGH_RISK_COUNT -gt 0) {
    Write-Log "ACTION REQUIRED: Found $HIGH_RISK_COUNT compromised package(s)"
} else {
    Write-Log "No compromised packages found"
}

Remove-LockAndCleanup
exit 0