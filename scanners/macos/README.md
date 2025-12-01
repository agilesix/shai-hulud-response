# macOS Scanner

Deployed via Kandji MDM.

## Deployment

1. In Kandji: Library → Custom Scripts
2. Create new script or update existing
3. Paste contents of `shai-hulud-scanner.sh`
4. Set execution frequency (daily recommended)

## Configuration

Edit these values at the top of the script:

| Variable | Description |
|----------|-------------|
| `WEBHOOK_URL` | Cloudflare Worker endpoint |
| `SECRET` | Shared secret for authentication |
| `MAX_PROJECTS` | Safety limit for project scanning |

## How It Works

1. Kandji runs the script
2. Script copies itself and launches in background
3. Kandji connection closes (no timeout)
4. Background process downloads Cobenian detector
5. Scans all npm projects under /Users
6. Reports results to webhook → Google Sheets