export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // Health check
    if (request.method === 'GET') {
      return new Response('Worker is running!', { status: 200 });
    }

    if (request.method !== 'POST') {
      return new Response('Method not allowed', { status: 405 });
    }

    try {
      const body = await request.json();

      // Validate shared secret
      if (body.secret !== env.SHARED_SECRET) {
        return new Response('Unauthorized', { status: 401 });
      }

      // Route based on path
      if (path === '/scan' || path === '/scan/') {
        return await handleScanResult(body, env);
      } else {
        // Default to acknowledgment (maintains backward compatibility)
        return await handleAcknowledgment(body, env);
      }

    } catch (err) {
      console.error('[ERROR] Worker error:', {
        message: err.message,
        stack: err.stack,
        name: err.name
      });
      return new Response('Error: ' + err.message + '\nStack: ' + (err.stack || 'No stack trace'), { status: 500 });
    }
  }
};

// Handle acknowledgment submissions
async function handleAcknowledgment(body, env) {
  const accessToken = await getAccessToken(env);
  
  const now = new Date().toISOString();
  const row = [
    now,
    body.message_id || '',
    body.serial || '',
    body.hostname || '',
    body.user || '',
    body.timestamp_utc || '',
    JSON.stringify(body)
  ];

  const range = `${env.SHEET_NAME}!A:G`;
  
  const sheetsResponse = await fetch(
    `https://sheets.googleapis.com/v4/spreadsheets/${env.GOOGLE_SHEET_ID}/values/${range}:append?valueInputOption=USER_ENTERED`,
    {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ values: [row] })
    }
  );

  if (!sheetsResponse.ok) {
    const error = await sheetsResponse.text();
    return new Response('Sheets API error: ' + error, { status: 500 });
  }

  return new Response('OK', { status: 200 });
}

// Helper function to safely parse integers with default value
function parseIntSafe(value, defaultValue) {
  if (typeof value === 'number') return value;
  const parsed = parseInt(value);
  return isNaN(parsed) ? defaultValue : parsed;
}

// Helper function to truncate strings with max length
function truncate(str, maxLen) {
  if (!str) return '';
  if (typeof str !== 'string') str = String(str);
  return str.length > maxLen ? str.substring(0, maxLen) + '...[truncated]' : str;
}

// Handle scan result submissions
async function handleScanResult(body, env) {
  try {
    // Check required environment variables
    if (!env.GOOGLE_SHEET_ID) {
      console.error('[ERROR] GOOGLE_SHEET_ID is missing');
      return new Response('Configuration error: GOOGLE_SHEET_ID not set', { status: 500 });
    }
    
    if (!env.GOOGLE_SERVICE_ACCOUNT_JSON) {
      console.error('[ERROR] GOOGLE_SERVICE_ACCOUNT_JSON is missing');
      return new Response('Configuration error: GOOGLE_SERVICE_ACCOUNT_JSON not set', { status: 500 });
    }

    console.log('[DEBUG] Getting access token...');
    const accessToken = await getAccessToken(env);
    console.log('[DEBUG] Access token obtained');
    
    const now = new Date().toISOString();
    
    // Ensure malicious_files_found is always a number (default to 0 if missing or invalid)
    const maliciousFilesFound = (typeof body.malicious_files_found === 'number')
      ? body.malicious_files_found
      : (parseInt(body.malicious_files_found) || 0);
    
    // Parse new diagnostic fields with safe defaults
    const projectsFound = parseIntSafe(body.projects_found, 0);
    const projectsScanned = parseIntSafe(body.projects_scanned, 0);
    const iocCount = parseIntSafe(body.ioc_count, 0);
    
    // Truncate string fields to prevent overflow
    const warnings = truncate(body.warnings || '', 500);
    const scanLog = truncate(body.scan_log || '', 10000);
    const highRiskDetails = truncate(body.high_risk_details || '', 1000);
    const mediumRiskDetails = truncate(body.medium_risk_details || '', 1000);
    const rawOutput = truncate(body.raw_output || '', 5000);
    
    // Log the received payload for debugging
    console.log('[DEBUG] Received scan result:', {
      serial: body.serial,
      hostname: body.hostname,
      status: body.status,
      high_risk_count: body.high_risk_count,
      malicious_files_found: maliciousFilesFound,
      projects_found: projectsFound,
      projects_scanned: projectsScanned,
      ioc_count: iocCount
    });
    
    const row = [
      now,                              // A: Server Timestamp
      body.serial || '',                // B: Serial
      body.hostname || '',              // C: Hostname
      body.user || '',                  // D: User
      body.os || '',                    // E: OS (darwin/windows)
      body.status || '',                // F: Status (clean/affected/error)
      body.high_risk_count || 0,        // G: High Risk Count
      body.medium_risk_count || 0,      // H: Medium Risk Count
      body.low_risk_count || 0,         // I: Low Risk Count
      highRiskDetails,                  // J: High Risk Details
      mediumRiskDetails,                 // K: Medium Risk Details
      body.scan_duration_ms || '',       // L: Scan Duration (ms)
      body.scanner_version || '',        // M: Scanner Version
      rawOutput,                         // N: Raw Output
      maliciousFilesFound,               // O: Malicious Files Found
      projectsFound,                     // P: Projects Found (NEW)
      projectsScanned,                   // Q: Projects Scanned (NEW)
      iocCount,                          // R: IOC Count (NEW)
      body.scan_dirs || '',              // S: Scan Dirs (NEW)
      warnings,                          // T: Warnings (NEW)
      scanLog                            // U: Scan Log (NEW)
    ];

    const range = 'Scan Results!A:U';
    
    // Log the row being sent to Google Sheets
    console.log('[DEBUG] Row data being sent to Sheets:', {
      rowLength: row.length,
      columnO_value: row[14],
      columnO_type: typeof row[14],
      fullRow: row
    });
    
    console.log('[DEBUG] Sending to Google Sheets:', {
      sheetId: env.GOOGLE_SHEET_ID ? 'present' : 'missing',
      range: range,
      rowLength: row.length
    });
    
    const sheetsResponse = await fetch(
      `https://sheets.googleapis.com/v4/spreadsheets/${env.GOOGLE_SHEET_ID}/values/${range}:append?valueInputOption=USER_ENTERED`,
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ values: [row] })
      }
    );

    if (!sheetsResponse.ok) {
      const error = await sheetsResponse.text();
      console.error('[ERROR] Sheets API error:', {
        status: sheetsResponse.status,
        statusText: sheetsResponse.statusText,
        error
      });
      return new Response('Sheets API error: ' + error, { status: 500 });
    }

    const responseData = await sheetsResponse.json();
    console.log('[DEBUG] Successfully wrote to Sheets:', {
      updatedRange: responseData.updates?.updatedRange,
      updatedCells: responseData.updates?.updatedCells
    });

    return new Response('OK', { status: 200 });
  } catch (err) {
    console.error('[ERROR] handleScanResult error:', {
      message: err.message,
      stack: err.stack,
      name: err.name
    });
    return new Response('Internal error: ' + err.message, { status: 500 });
  }
}

// Google Service Account JWT auth
async function getAccessToken(env) {
  try {
    if (!env.GOOGLE_SERVICE_ACCOUNT_JSON) {
      throw new Error('GOOGLE_SERVICE_ACCOUNT_JSON is not set');
    }
    
    let serviceAccount;
    try {
      serviceAccount = JSON.parse(env.GOOGLE_SERVICE_ACCOUNT_JSON);
    } catch (parseErr) {
      console.error('[ERROR] Failed to parse GOOGLE_SERVICE_ACCOUNT_JSON:', parseErr.message);
      throw new Error('Invalid GOOGLE_SERVICE_ACCOUNT_JSON format: ' + parseErr.message);
    }

    const now = Math.floor(Date.now() / 1000);

    const header = { alg: 'RS256', typ: 'JWT' };
    const claim = {
      iss: serviceAccount.client_email,
      scope: 'https://www.googleapis.com/auth/spreadsheets',
      aud: 'https://oauth2.googleapis.com/token',
      iat: now,
      exp: now + 3600
    };

    const encodedHeader = base64url(JSON.stringify(header));
    const encodedClaim = base64url(JSON.stringify(claim));
    const signatureInput = `${encodedHeader}.${encodedClaim}`;

    const privateKey = await crypto.subtle.importKey(
      'pkcs8',
      pemToArrayBuffer(serviceAccount.private_key),
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['sign']
    );

    const signature = await crypto.subtle.sign(
      'RSASSA-PKCS1-v1_5',
      privateKey,
      new TextEncoder().encode(signatureInput)
    );

    const encodedSignature = base64url(new Uint8Array(signature));
    const jwt = `${encodedHeader}.${encodedClaim}.${encodedSignature}`;

    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
    });

    if (!tokenResponse.ok) {
      const error = await tokenResponse.text();
      throw new Error('Token exchange failed: ' + error);
    }

    const tokenData = await tokenResponse.json();
    return tokenData.access_token;
  } catch (err) {
    console.error('[ERROR] getAccessToken error:', {
      message: err.message,
      stack: err.stack,
      name: err.name
    });
    throw err;
  }
}

function base64url(input) {
  let bytes;
  if (typeof input === 'string') {
    bytes = new TextEncoder().encode(input);
  } else if (input instanceof Uint8Array) {
    bytes = input;
  } else if (input instanceof ArrayBuffer) {
    bytes = new Uint8Array(input);
  } else {
    bytes = new Uint8Array(input);
  }

  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = btoa(binary);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function pemToArrayBuffer(pem) {
  const b64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\n/g, '');
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}
