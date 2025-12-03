# Cloudflare Worker Environment Variables Checklist

## Required Secrets

These must be set via `wrangler secret put` (not in `wrangler.toml`):

### 1. SHARED_SECRET
- **Purpose**: Authentication key for webhook requests
- **Set via**: `wrangler secret put SHARED_SECRET`
- **Used in**: `webhook/src/index.js` line 19
- **Check**: Should match the `SECRET` value in scanner scripts

### 2. GOOGLE_SERVICE_ACCOUNT_JSON
- **Purpose**: Google Service Account credentials (full JSON)
- **Set via**: `wrangler secret put GOOGLE_SERVICE_ACCOUNT_JSON`
- **Used in**: `webhook/src/index.js` line 163
- **Format**: Full JSON object with `client_email`, `private_key`, etc.

### 3. GOOGLE_SHEET_ID
- **Purpose**: Google Sheets spreadsheet ID
- **Set via**: `wrangler secret put GOOGLE_SHEET_ID`
- **Used in**: `webhook/src/index.js` lines 55, 129
- **Format**: Spreadsheet ID from Google Sheets URL

## Environment Variables (in wrangler.toml)

These are set in `wrangler.toml` under `[vars]`:

### SHEET_NAME
- **Current value**: `"Acknowledgements"`
- **Purpose**: Sheet tab name for acknowledgments
- **Used in**: `webhook/src/index.js` line 52
- **Note**: This is public and safe to keep in `wrangler.toml`

## How to Check/Set Secrets

### Check existing secrets:
```bash
cd webhook
wrangler secret list
```

### Set/Update a secret:
```bash
cd webhook

# Set SHARED_SECRET
wrangler secret put SHARED_SECRET
# (will prompt for value, or pipe it in)

# Set GOOGLE_SERVICE_ACCOUNT_JSON
wrangler secret put GOOGLE_SERVICE_ACCOUNT_JSON
# (paste the full JSON when prompted)

# Set GOOGLE_SHEET_ID
wrangler secret put GOOGLE_SHEET_ID
# (paste the spreadsheet ID when prompted)
```

### Verify secrets are set:
```bash
wrangler secret list
```

You should see:
- ✅ SHARED_SECRET
- ✅ GOOGLE_SERVICE_ACCOUNT_JSON
- ✅ GOOGLE_SHEET_ID

## Testing

After setting secrets, test the webhook:
```bash
# Test health check
curl https://kandji-ack-worker.anthony-arashiro.workers.dev/

# Test with a scan result (replace YOUR_SECRET with actual secret)
curl -X POST https://kandji-ack-worker.anthony-arashiro.workers.dev/scan \
  -H "Content-Type: application/json" \
  -d '{
    "secret": "YOUR_SECRET",
    "serial": "TEST123",
    "hostname": "test-host",
    "user": "test-user",
    "os": "macOS",
    "status": "clean",
    "high_risk_count": 0,
    "medium_risk_count": 0,
    "low_risk_count": 0,
    "high_risk_details": "",
    "medium_risk_details": "",
    "scan_duration_ms": 1000,
    "scanner_version": "2.0.8",
    "raw_output": "test",
    "malicious_files_found": 0
  }'
```

## Common Issues

### "Unauthorized" (401)
- **Cause**: `SHARED_SECRET` missing or doesn't match scanner
- **Fix**: Set `SHARED_SECRET` via `wrangler secret put SHARED_SECRET`

### "Token exchange failed"
- **Cause**: `GOOGLE_SERVICE_ACCOUNT_JSON` missing or invalid
- **Fix**: Set `GOOGLE_SERVICE_ACCOUNT_JSON` via `wrangler secret put GOOGLE_SERVICE_ACCOUNT_JSON`

### "Sheets API error" (404 or 403)
- **Cause**: `GOOGLE_SHEET_ID` missing or invalid, or service account doesn't have access
- **Fix**: 
  1. Set `GOOGLE_SHEET_ID` via `wrangler secret put GOOGLE_SHEET_ID`
  2. Ensure service account email has access to the spreadsheet

### Column O not updating
- **Cause**: `malicious_files_found` field missing from payload or not being parsed correctly
- **Fix**: Check webhook logs (see logging added in v2.0.8)

