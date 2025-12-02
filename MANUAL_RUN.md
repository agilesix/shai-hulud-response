# Manual Scanner Execution Guide

This guide explains how to manually run the Shai-Hulud scanners on macOS and Windows for testing or one-off scans.

## Prerequisites

### macOS
- macOS 10.15 or later
- zsh shell (default on macOS Catalina+)
- `curl` command (pre-installed)
- Internet connection (the scanner automatically downloads the IOC list from GitHub - no manual download needed)

### Windows
- Windows 10 or later
- PowerShell 5.1 or later
- Internet connection (the scanner automatically downloads the IOC list from GitHub - no manual download needed)

**Note:** You do NOT need to manually download the `compromised-packages.txt` file. The scanner automatically downloads it from the public GitHub repository (`https://raw.githubusercontent.com/agilesix/shai-hulud-response/main/ioc/compromised-packages.txt`) during execution.

## Step 1: Download the Scanner

### macOS

```bash
# Clone the repository or download the scanner file
cd ~/Downloads
curl -O https://raw.githubusercontent.com/agilesix/shai-hulud-response/main/scanners/macos/shai-hulud-scanner.sh
chmod +x shai-hulud-scanner.sh
```

Or if you have the repo cloned:
```bash
cd /path/to/a6-shai-hulud-response/scanners/macos
chmod +x shai-hulud-scanner.sh
```

### Windows

```powershell
# Clone the repository or download the scanner file
cd $env:USERPROFILE\Downloads
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/agilesix/shai-hulud-response/main/scanners/windows/shai-hulud-scanner.ps1" -OutFile "shai-hulud-scanner.ps1"
```

Or if you have the repo cloned:
```powershell
cd C:\path\to\a6-shai-hulud-response\scanners\windows
```

**If you get an execution policy error:**
```powershell
# Run PowerShell as Administrator, then:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## Step 2: Choose Your Mode

After downloading, you have two options:

### Option A: Production Mode (With Webhook)
- Results sent to Google Sheets via webhook
- Requires secret from 1Password
- Use for production scans or when you need results tracked

### Option B: Local Testing Mode (No Webhook)
- Results displayed in console
- No secret required
- Use for local testing, debugging, or one-off scans

---

## Option A: Production Mode (With Webhook)

### macOS - Production Mode

1. **Configure the Secret**

Edit the scanner file:
```bash
nano shai-hulud-scanner.sh
# or
vim shai-hulud-scanner.sh
```

Find this line (around line 31):
```bash
SECRET="YOUR_SHARED_SECRET_HERE"
```

Replace `YOUR_SHARED_SECRET_HERE` with the actual secret from 1Password (vault: "Shai-Hulud Scanner").

2. **Run the Scanner**

```bash
./shai-hulud-scanner.sh
```

The scanner will:
- Launch in background automatically
- Automatically download the IOC list from the public GitHub repo
- Scan all npm projects under `/Users`
- Send results to the webhook
- Log output to `/var/tmp/shai-hulud/scanner.log`

3. **Check Results**

**View the log:**
```bash
tail -f /var/tmp/shai-hulud/scanner.log
```

**Check if scanner is running:**
```bash
ps aux | grep shai-hulud
```

**Check lock file:**
```bash
cat /tmp/shai-hulud-scanner.lock
```

### Windows - Production Mode

1. **Configure the Secret**

Edit the scanner file in a text editor (Notepad, VS Code, etc.):

Find this line (around line 30):
```powershell
$SECRET = "YOUR_SHARED_SECRET_HERE"
```

Replace `YOUR_SHARED_SECRET_HERE` with the actual secret from 1Password (vault: "Shai-Hulud Scanner").

2. **Run the Scanner**

```powershell
.\shai-hulud-scanner.ps1
```

The scanner will:
- Launch in background automatically
- Automatically download the IOC list from the public GitHub repo
- Scan all npm projects under `C:\Users`
- Send results to the webhook
- Log output to `%TEMP%\shai-hulud\scanner.log`

3. **Check Results**

**View the log:**
```powershell
Get-Content $env:TEMP\shai-hulud\scanner.log -Tail 50 -Wait
```

**Check if scanner is running:**
```powershell
Get-Process | Where-Object {$_.ProcessName -like "*powershell*"} | Select-Object Id, ProcessName, StartTime
```

**Check lock file:**
```powershell
Get-Content $env:TEMP\shai-hulud-scanner.lock
```

---

## Option B: Local Testing Mode (No Webhook/Google Sheets)

For local testing without needing the secret or webhook access, modify the scripts to output results to the console instead of sending to Google Sheets.

### macOS - Local Testing Mode

1. **Open the scanner file:**
```bash
nano shai-hulud-scanner.sh
# or
vim shai-hulud-scanner.sh
```

2. **Modify the `send_error()` function** (around line 198) to output to console instead of webhook:

**Find this function:**
```bash
send_error() {
  local msg="$1"
  log "ERROR: $msg"
  curl -s -X POST -H "Content-Type: application/json" \
    -d "{\"secret\": \"${SECRET}\", \"serial\": \"${SERIAL}\", \"hostname\": \"${HOSTNAME}\", \"user\": \"${CURRENT_USER}\", \"os\": \"macOS\", \"status\": \"error\", \"high_risk_count\": 0, \"medium_risk_count\": 0, \"low_risk_count\": 0, \"high_risk_details\": \"\", \"medium_risk_details\": \"\", \"scan_duration_ms\": 0, \"scanner_version\": \"${SCANNER_VERSION}\", \"raw_output\": \"${msg}\"}" \
    "${WEBHOOK_URL}"
}
```

**Replace with:**
```bash
send_error() {
  local msg="$1"
  log "ERROR: $msg"
  echo ""
  echo "❌ ERROR (Local Testing Mode): $msg" >&2
  echo "This error would normally be sent to the webhook." >&2
}
```

3. **Find the "SEND RESULTS" section** (around line 432) and replace the webhook submission with console output:

**Find this block:**
```bash
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" \
  -d "{\"secret\": \"${SECRET}\", \"serial\": \"${SERIAL}\", \"hostname\": \"${HOSTNAME}\", \"user\": \"${CURRENT_USER}\", \"os\": \"macOS\", \"status\": \"${OVERALL_STATUS}\", \"high_risk_count\": ${HIGH_RISK_COUNT}, \"medium_risk_count\": ${MEDIUM_RISK_COUNT}, \"low_risk_count\": ${LOW_RISK_COUNT}, \"high_risk_details\": \"${HIGH_RISK_DETAILS_ESCAPED}\", \"medium_risk_details\": \"${MEDIUM_RISK_DETAILS_ESCAPED}\", \"scan_duration_ms\": ${SCAN_DURATION}, \"scanner_version\": \"${SCANNER_VERSION}\", \"raw_output\": \"${RAW_OUTPUT_ESCAPED}\"}" \
  "${WEBHOOK_URL}" 2>/dev/null)

if [[ "${HTTP_CODE}" == "200" ]]; then
  log "✅ Results sent successfully"
else
  log "⚠️  Webhook returned: ${HTTP_CODE}"
fi
```

**Replace with:**
```bash
# LOCAL TESTING MODE - Output to console instead of webhook
echo ""
echo "=========================================="
echo "SCAN RESULTS (Local Testing Mode)"
echo "=========================================="
echo "Hostname: ${HOSTNAME}"
echo "Serial: ${SERIAL}"
echo "User: ${CURRENT_USER}"
echo "OS: macOS"
echo "Status: ${OVERALL_STATUS}"
echo "High Risk Count: ${HIGH_RISK_COUNT}"
echo "Medium Risk Count: ${MEDIUM_RISK_COUNT}"
echo "Low Risk Count: ${LOW_RISK_COUNT}"
echo "Scan Duration: ${SCAN_DURATION}ms"
echo "Scanner Version: ${SCANNER_VERSION}"
echo ""
if [[ ${HIGH_RISK_COUNT} -gt 0 ]]; then
  echo "⚠️  HIGH RISK FINDINGS:"
  echo "${HIGH_RISK_DETAILS}"
  echo ""
fi
if [[ ${MEDIUM_RISK_COUNT} -gt 0 ]]; then
  echo "⚡ MEDIUM RISK FINDINGS:"
  echo "${MEDIUM_RISK_DETAILS}"
  echo ""
fi
echo "Raw Output: ${RAW_OUTPUT}"
echo "=========================================="
log "✅ Results displayed in console (local testing mode)"
```

4. **Run the scanner:**
```bash
./shai-hulud-scanner.sh --background /var/tmp/shai-hulud/scan-test
```

Or to see output immediately, you can also modify the script to skip the backgrounding by commenting out the foreground mode section.

### Windows - Local Testing Mode

1. **Open the scanner file** in a text editor (Notepad, VS Code, etc.)

2. **Modify the `Send-ErrorReport()` function** (around line 281) to output to console instead of webhook:

**Find this function:**
```powershell
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
```

**Replace with:**
```powershell
function Send-ErrorReport {
    param([string]$Message)
    Write-Log "ERROR: $Message"
    Write-Host ""
    Write-Host "❌ ERROR (Local Testing Mode): $Message" -ForegroundColor Red
    Write-Host "This error would normally be sent to the webhook." -ForegroundColor Yellow
}
```

3. **Find the "SEND RESULTS" section** (around line 568) and replace the webhook submission with console output:

**Find this block:**
```powershell
try {
    $response = Invoke-RestMethod -Uri $WEBHOOK_URL -Method Post -Body $resultBody -ContentType "application/json" -TimeoutSec 30
    Write-Log "Results sent successfully"
} catch {
    Write-Log "WARNING: Failed to send results - $_"
}
```

**Replace with:**
```powershell
# LOCAL TESTING MODE - Output to console instead of webhook
Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "SCAN RESULTS (Local Testing Mode)" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Hostname: $HOSTNAME"
Write-Host "Serial: $SERIAL"
Write-Host "User: $CURRENT_USER"
Write-Host "OS: Windows"
Write-Host "Status: $OVERALL_STATUS"
Write-Host "High Risk Count: $HIGH_RISK_COUNT"
Write-Host "Medium Risk Count: $MEDIUM_RISK_COUNT"
Write-Host "Low Risk Count: $LOW_RISK_COUNT"
Write-Host "Scan Duration: ${SCAN_DURATION}ms"
Write-Host "Scanner Version: $SCANNER_VERSION"
Write-Host ""
if ($HIGH_RISK_COUNT -gt 0) {
    Write-Host "⚠️  HIGH RISK FINDINGS:" -ForegroundColor Red
    Write-Host $HIGH_RISK_DETAILS
    Write-Host ""
}
if ($MEDIUM_RISK_COUNT -gt 0) {
    Write-Host "⚡ MEDIUM RISK FINDINGS:" -ForegroundColor Yellow
    Write-Host $MEDIUM_RISK_DETAILS
    Write-Host ""
}
Write-Host "Raw Output: $RAW_OUTPUT"
Write-Host "==========================================" -ForegroundColor Cyan
Write-Log "✅ Results displayed in console (local testing mode)"
```

4. **Run the scanner:**
```powershell
.\shai-hulud-scanner.ps1 --background "$env:TEMP\shai-hulud\scan-test"
```

**Note:** When running in local testing mode, you don't need to set the `SECRET` variable - it won't be used.

### Quick Local Test (Skip Backgrounding)

For even simpler local testing, you can also modify the scripts to skip the backgrounding entirely:

**macOS:** Comment out the foreground mode section (lines ~59-107) and have it go straight to scanning.

**Windows:** Comment out the foreground mode section (lines ~56-95) and have it go straight to scanning.

---

## Expected Output

### Production Mode - Successful Scan (Clean)
```
=== Shai-Hulud 2.0 Scanner Launcher v2.0.7 ===
Timestamp: 2025-12-01T23:00:00Z
Launching scanner in background...
✅ Scanner launched (PID: 12345)
Log: /var/tmp/shai-hulud/scanner.log
Results will be sent to webhook when complete.
Launcher exiting.
```

### Production Mode - Compromised Packages Found
The scanner will report findings in the log and send them to the webhook. Check Google Sheets for detailed results.

### Local Testing Mode - Sample Output
```
==========================================
SCAN RESULTS (Local Testing Mode)
==========================================
Hostname: MyMacBook
Serial: C02X12345678
User: john.doe
OS: macOS
Status: affected
High Risk Count: 2
Medium Risk Count: 0
Low Risk Count: 0
Scan Duration: 45230ms
Scanner Version: 2.0.7

⚠️  HIGH RISK FINDINGS:
/Users/john/project1: chalk@5.6.1, debug@4.3.5 | 

Raw Output: [/Users/john/project1] HIGH:2 [/Users/john/project2] clean 
==========================================
```

---

## Troubleshooting

### macOS Issues

**Scanner won't run:**
```bash
# Check permissions
ls -l shai-hulud-scanner.sh
chmod +x shai-hulud-scanner.sh

# Check if zsh is available
which zsh
```

**Can't download IOC list:**
```bash
# Test connectivity
curl -I https://raw.githubusercontent.com/agilesix/shai-hulud-response/main/ioc/compromised-packages.txt
```

**401 Unauthorized error (Production Mode only):**
- Verify the `SECRET` variable matches the Cloudflare Worker secret
- Check 1Password for the correct secret value
- Note: This error won't occur in Local Testing Mode

### Windows Issues

**Execution policy error:**
```powershell
# Run as Administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Can't download IOC list:**
```powershell
# Test connectivity
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/agilesix/shai-hulud-response/main/ioc/compromised-packages.txt" -Method Head
```

**401 Unauthorized error (Production Mode only):**
- Verify the `$SECRET` variable matches the Cloudflare Worker secret
- Check 1Password for the correct secret value
- Note: This error won't occur in Local Testing Mode

**Scanner process not found:**
- Check Task Manager for PowerShell processes
- Look for processes with "shai-hulud" in the command line

---

## Manual Background Execution

If you want to run the scanner completely in the background from the start:

### macOS
```bash
nohup ./shai-hulud-scanner.sh > /dev/null 2>&1 &
```

### Windows
```powershell
Start-Process powershell.exe -ArgumentList "-File", ".\shai-hulud-scanner.ps1" -WindowStyle Hidden
```

---

## Stopping a Running Scanner

### macOS
```bash
# Find the process
ps aux | grep shai-hulud

# Kill by PID (replace 12345 with actual PID)
kill 12345

# Or remove lock file and kill
rm /tmp/shai-hulud-scanner.lock
pkill -f shai-hulud
```

### Windows
```powershell
# Find the process
Get-Process | Where-Object {$_.Path -like "*shai-hulud*"}

# Kill by PID (replace 12345 with actual PID)
Stop-Process -Id 12345 -Force

# Or remove lock file and kill
Remove-Item $env:TEMP\shai-hulud-scanner.lock -Force
Get-Process | Where-Object {$_.CommandLine -like "*shai-hulud*"} | Stop-Process -Force
```

---

## Verifying Results

### Production Mode
After the scan completes, check:

1. **Google Sheets** - Results should appear in the "Scan Results" sheet
2. **Webhook logs** - Check Cloudflare Worker logs for successful submissions
3. **Scanner log file** - Review the local log for detailed scan information

### Local Testing Mode
Results are displayed directly in the console. No external verification needed.

---

## Configuration Options

You can modify these variables in the scanner files:

| Variable | Default | Description |
|----------|---------|-------------|
| `MAX_PROJECTS` | 200 | Maximum number of projects to scan |
| `DELAY_BETWEEN_PROJECTS` | 0.2 | Seconds to pause between projects |
| `SKIP_IF_ON_BATTERY` | false | Skip scan when on battery power |
| `SCAN_DIRS` | `/Users` (macOS) or `C:\Users` (Windows) | Directories to scan |

---

## Notes

- The scanner automatically backgrounds itself when run normally
- Results are sent to the webhook asynchronously (Production Mode only)
- The scanner uses reduced CPU priority to avoid impacting system performance
- Test-case directories are automatically excluded from scanning
- **The IOC list (`compromised-packages.txt`) is automatically downloaded from the public GitHub repo on each run - no manual download needed**
- Local Testing Mode doesn't require any secrets or webhook configuration
