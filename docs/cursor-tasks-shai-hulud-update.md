# Cursor Tasks: Shai-Hulud Scanner Update for November 2025 Coverage

## Context

Our scanner currently pulls from `https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/compromised-packages.txt` which **only covers September 2025 attacks** (~571 packages).

We need to add coverage for the **November 2025 "Shai-Hulud 2.0" attack** (~900 additional packages from Zapier, PostHog, Postman, ENS Domains, etc.).

**Solution:** Host our own merged IOC list in this repo and update scanners to use it.

---

## Task 1: Add Merged IOC List to Repository

### 1.1 Create directory structure

```bash
mkdir -p ioc
```

### 1.2 Create the compromised packages file

Create file: `ioc/compromised-packages.txt`

Download the merged list from this URL and save it:
```
https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/refs/heads/main/reports/shai-hulud-2-packages.csv
```

**Important:** The Wiz file is CSV format. Convert it to our format (package:version) and merge with existing Cobenian list.

Alternatively, use this pre-merged file I've created (copy the entire contents):

**File header should be:**
```
# Shai-Hulud NPM Supply Chain Attack - Comprehensive Compromised Packages List
#
# This file contains ALL confirmed compromised package versions from:
# - September 2025 attacks (Shai-Hulud v1, chalk/debug crypto theft)
# - November 2025 attacks (Shai-Hulud 2.0 "The Second Coming")
#
# Sources:
# - Cobenian/shai-hulud-detect (September 2025)
# - Wiz Security Research IOCs (November 2025)
# - Socket.dev, JFrog, ReversingLabs, Datadog Security Labs
#
# Format: package_name:version
# Last updated: December 2025
#
# Total compromised package:version pairs: 1509
#
```

---

## Task 2: Update macOS Scanner (v2.0.7)

### 2.1 Edit file: `scanners/macos/shai-hulud-scanner.sh`

**Change 1:** Update version number (around line 7)
```bash
# Find this line:
SCANNER_VERSION="2.0.6"

# Change to:
SCANNER_VERSION="2.0.7"
```

**Change 2:** Update packages URL (around line 25-30)
```bash
# Find this line:
PACKAGES_URL="https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/compromised-packages.txt"

# Change to (replace YOUR_ORG and YOUR_REPO with actual values):
PACKAGES_URL="https://raw.githubusercontent.com/YOUR_ORG/a6-shai-hulud-response/main/ioc/compromised-packages.txt"
```

**Change 3:** Remove the detector script download (we don't use it anymore in v2.0.6+)

If there's still a reference to `DETECTOR_URL`, remove it:
```bash
# Remove this line if present:
DETECTOR_URL="https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/shai-hulud-detector.sh"
```

---

## Task 3: Update Windows Scanner (v2.0.7)

### 3.1 Edit file: `scanners/windows/shai-hulud-scanner.ps1`

**Change 1:** Update version number (around line 7)
```powershell
# Find this line:
$SCANNER_VERSION = "2.0.3"

# Change to:
$SCANNER_VERSION = "2.0.7"
```

**Change 2:** Update packages URL (around line 25-30)
```powershell
# Find this line:
$PACKAGES_URL = "https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/compromised-packages.txt"

# Change to (replace YOUR_ORG and YOUR_REPO with actual values):
$PACKAGES_URL = "https://raw.githubusercontent.com/YOUR_ORG/a6-shai-hulud-response/main/ioc/compromised-packages.txt"
```

**Change 3:** Remove detector script reference if present
```powershell
# Remove this line if present:
$DETECTOR_URL = "https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/shai-hulud-detector.sh"
```

---

## Task 4: Update README.md

### 4.1 Edit file: `README.md`

Add a section about IOC coverage:

```markdown
## IOC Coverage

This scanner detects compromised packages from multiple attack waves:

| Attack Wave | Date | Packages | Source |
|-------------|------|----------|--------|
| Chalk/Debug Crypto Theft | September 8, 2025 | ~25 | Cobenian |
| Shai-Hulud v1 Worm | September 14-16, 2025 | ~550 | Cobenian |
| Shai-Hulud 2.0 | November 21-24, 2025 | ~900 | Wiz IOC |
| **Total** | | **~1,509** | Merged |

### High-Impact November 2025 Packages

The November 2025 attack compromised major vendor packages:
- `@zapier/*` - Official Zapier integration toolkit
- `@posthog/*` - Analytics platform (130M+ monthly downloads)
- `@postman/*` - API development tools
- `@ensdomains/*` - Ethereum .eth domain handling
- `@asyncapi/*` - API specification tools
- `@browserbasehq/*` - Browser automation

### Updating IOC List

To add new compromised packages:
1. Edit `ioc/compromised-packages.txt`
2. Add entries in format: `package-name:version`
3. Commit and push - scanners will pick up changes on next run
```

---

## Task 5: Update Version History in Docs

### 5.1 If you have a CHANGELOG.md or version history section, add:

```markdown
## v2.0.7 (December 2025)
- **CRITICAL:** Added November 2025 Shai-Hulud 2.0 coverage (~900 additional packages)
- Merged Cobenian + Wiz IOC lists for comprehensive detection
- Now detects @zapier/*, @posthog/*, @postman/*, @ensdomains/* compromised packages
- Total coverage: 1,509 compromised package:version pairs
- IOC list now hosted in this repo for faster updates
```

---

## Task 6: Commit and Push

### 6.1 Stage all changes
```bash
git add ioc/compromised-packages.txt
git add scanners/macos/shai-hulud-scanner.sh
git add scanners/windows/shai-hulud-scanner.ps1
git add README.md
```

### 6.2 Commit with descriptive message
```bash
git commit -m "feat: Add November 2025 Shai-Hulud 2.0 IOC coverage

- Add merged IOC list (1,509 packages) covering Sept + Nov 2025 attacks
- Update macOS scanner to v2.0.7, point to local IOC list
- Update Windows scanner to v2.0.7, point to local IOC list
- Now detects @zapier/*, @posthog/*, @postman/*, @ensdomains/* etc.

BREAKING: Scanners now pull IOC list from this repo instead of Cobenian"
```

### 6.3 Push to remote
```bash
git push origin main
```

---

## Task 7: Verify Raw URL Works

After pushing, verify the IOC file is accessible:

```bash
curl -sI "https://raw.githubusercontent.com/YOUR_ORG/a6-shai-hulud-response/main/ioc/compromised-packages.txt" | head -5
```

Should return `HTTP/2 200`.

---

## Post-Deployment: Update MDM

After the GitHub repo is updated, you need to:

1. **Kandji (macOS):** Update the Custom Script with new scanner v2.0.7
2. **Action1 (Windows):** Update the Script with new scanner v2.0.7

The scanners will automatically pull the new IOC list from your repo on next run.

---

## File Structure After Changes

```
a6-shai-hulud-response/
├── ioc/
│   └── compromised-packages.txt    # NEW: Merged IOC list (1,509 packages)
├── scanners/
│   ├── macos/
│   │   ├── shai-hulud-scanner.sh   # UPDATED: v2.0.7, new URL
│   │   └── README.md
│   └── windows/
│       └── shai-hulud-scanner.ps1  # UPDATED: v2.0.7, new URL
├── webhook/
│   └── src/index.js
├── README.md                        # UPDATED: IOC coverage docs
└── .gitignore
```

---

## Quick Reference: URLs to Update

| Scanner | Old URL | New URL |
|---------|---------|---------|
| macOS | `https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/compromised-packages.txt` | `https://raw.githubusercontent.com/YOUR_ORG/a6-shai-hulud-response/main/ioc/compromised-packages.txt` |
| Windows | Same as above | Same as above |

Replace `YOUR_ORG` with your actual GitHub organization/username.
