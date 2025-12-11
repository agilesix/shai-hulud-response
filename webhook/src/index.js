export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // Extract request metadata from Cloudflare
    const cf = request.cf || {};
    const requestMeta = {
      ip: request.headers.get('cf-connecting-ip') || request.headers.get('x-real-ip') || 'unknown',
      country: cf.country || request.headers.get('cf-ipcountry') || 'unknown',
      city: cf.city || 'unknown',
      region: cf.region || 'unknown',
      asn: cf.asn || 'unknown',
      asOrg: cf.asOrganization || 'unknown',
      userAgent: request.headers.get('user-agent') || 'unknown',
      rayId: request.headers.get('cf-ray') || 'unknown',
      timestamp: new Date().toISOString()
    };

    // Health check
    if (request.method === 'GET') {
      return new Response('Worker is running!', { status: 200 });
    }

    if (request.method !== 'POST') {
      return new Response('Method not allowed', { status: 405 });
    }

    try {
      const body = await request.json();

      // FORENSIC LOGGING - Log EVERY request before auth check
      console.log('[FORENSIC] Incoming request:', JSON.stringify({
        meta: requestMeta,
        payload: sanitizePayloadForLogging(body),
        path: path
      }));

      // GEO-FLAGGING - Flag or reject non-US requests
      const ALLOWED_COUNTRIES = ['US', 'PR', 'VI', 'GU', 'AS', 'MP'];
      const isAllowedCountry = ALLOWED_COUNTRIES.includes(requestMeta.country);
      
      if (!isAllowedCountry) {
        console.warn('[GEO-FLAG] Non-US request detected:', JSON.stringify({
          meta: requestMeta,
          payload: sanitizePayloadForLogging(body),
          action: env.GEO_BLOCK_MODE === 'reject' ? 'REJECTED' : 'FLAGGED'
        }));

        if (env.GEO_BLOCK_MODE === 'reject') {
          return new Response('Forbidden: Geographic restriction', { status: 403 });
        }
        
        body._geoFlagged = true;
        body._geoDetails = {
          country: requestMeta.country,
          city: requestMeta.city,
          asOrg: requestMeta.asOrg,
          ip: requestMeta.ip
        };
      }

      // Validate shared secret
      if (body.secret !== env.SHARED_SECRET) {
        console.error('[AUTH-FAIL] Invalid secret:', JSON.stringify({
          meta: requestMeta,
          providedSecretLength: body.secret ? body.secret.length : 0,
          hostname: body.hostname || 'unknown',
          serial: body.serial || 'unknown'
        }));
        return new Response('Unauthorized', { status: 401 });
      }

      // Route based on path
      if (path === '/scan' || path === '/scan/') {
        return await handleScanResult(body, env, requestMeta);
      } else {
        return await handleAcknowledgment(body, env, requestMeta);
      }

    } catch (err) {
      console.error('[ERROR] Worker error:', {
        message: err.message,
        stack: err.stack,
        name: err.name,
        meta: requestMeta
      });
      return new Response('Error: ' + err.message, { status: 500 });
    }
  }
};

function sanitizePayloadForLogging(body) {
  const sanitized = { ...body };
  if (sanitized.secret) sanitized.secret = '[REDACTED]';
  if (sanitized.raw_output && sanitized.raw_output.length > 500) {
    sanitized.raw_output = sanitized.raw_output.substring(0, 500) + '...[truncated]';
  }
  if (sanitized.scan_log && sanitized.scan_log.length > 500) {
    sanitized.scan_log = sanitized.scan_log.substring(0, 500) + '...[truncated]';
  }
  return sanitized;
}

async function handleAcknowledgment(body, env, requestMeta) {
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

function parseIntSafe(value, defaultValue) {
  if (typeof value === 'number') return value;
  const parsed = parseInt(value);
  return isNaN(parsed) ? defaultValue : parsed;
}

function truncate(str, maxLen) {
  if (!str) return '';
  if (typeof str !== 'string') str = String(str);
  return str.length > maxLen ? str.substring(0, maxLen) + '...[truncated]' : str;
}

async function handleScanResult(body, env, requestMeta) {
  try {
    if (!env.GOOGLE_SHEET_ID) {
      console.error('[ERROR] GOOGLE_SHEET_ID is missing');
      return new Response('Configuration error: GOOGLE_SHEET_ID not set', { status: 500 });
    }
    
    if (!env.GOOGLE_SERVICE_ACCOUNT_JSON) {
      console.error('[ERROR] GOOGLE_SERVICE_ACCOUNT_JSON is missing');
      return new Response('Configuration error: GOOGLE_SERVICE_ACCOUNT_JSON not set', { status: 500 });
    }

    const accessToken = await getAccessToken(env);
    const now = new Date().toISOString();
    
    const maliciousFilesFound = (typeof body.malicious_files_found === 'number')
      ? body.malicious_files_found
      : (parseInt(body.malicious_files_found) || 0);
    
    const projectsFound = parseIntSafe(body.projects_found, 0);
    const projectsScanned = parseIntSafe(body.projects_scanned, 0);
    const iocCount = parseIntSafe(body.ioc_count, 0);
    
    const warnings = truncate(body.warnings || '', 500);
    const scanLog = truncate(body.scan_log || '', 10000);
    const highRiskDetails = truncate(body.high_risk_details || '', 1000);
    const mediumRiskDetails = truncate(body.medium_risk_details || '', 1000);
    const rawOutput = truncate(body.raw_output || '', 5000);
    
    console.log('[SCAN-RESULT] Processing scan:', JSON.stringify({
      serial: body.serial,
      hostname: body.hostname,
      user: body.user,
      status: body.status,
      high_risk_count: body.high_risk_count,
      malicious_files_found: maliciousFilesFound,
      source_ip: requestMeta.ip,
      source_country: requestMeta.country,
      source_city: requestMeta.city,
      source_asOrg: requestMeta.asOrg,
      geo_flagged: body._geoFlagged || false
    }));
    
    // ROW WITH GEO DATA - Columns A-AA
    const row = [
      now,                              // A: Server Timestamp
      body.serial || '',                // B: Serial
      body.hostname || '',              // C: Hostname
      body.user || '',                  // D: User
      body.os || '',                    // E: OS
      body.status || '',                // F: Status
      body.high_risk_count || 0,        // G: High Risk Count
      body.medium_risk_count || 0,      // H: Medium Risk Count
      body.low_risk_count || 0,         // I: Low Risk Count
      highRiskDetails,                  // J: High Risk Details
      mediumRiskDetails,                // K: Medium Risk Details
      body.scan_duration_ms || '',      // L: Scan Duration (ms)
      body.scanner_version || '',       // M: Scanner Version
      rawOutput,                        // N: Raw Output
      maliciousFilesFound,              // O: Malicious Files Found
      projectsFound,                    // P: Projects Found
      projectsScanned,                  // Q: Projects Scanned
      iocCount,                         // R: IOC Count
      body.scan_dirs || '',             // S: Scan Dirs
      warnings,                         // T: Warnings
      scanLog,                          // U: Scan Log
      // NEW FORENSIC COLUMNS (V-AA)
      requestMeta.ip,                   // V: Source IP
      requestMeta.country,              // W: Source Country
      requestMeta.city,                 // X: Source City
      requestMeta.asOrg,                // Y: Source ASN Org
      body._geoFlagged ? 'YES' : '',    // Z: Geo Flagged
      requestMeta.userAgent             // AA: User Agent
    ];

    const range = 'Scan Results!A:AA';
    
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
      console.error('[ERROR] Sheets API error:', error);
      return new Response('Sheets API error: ' + error, { status: 500 });
    }

    return new Response('OK', { status: 200 });
  } catch (err) {
    console.error('[ERROR] handleScanResult error:', err.message);
    return new Response('Internal error: ' + err.message, { status: 500 });
  }
}

async function getAccessToken(env) {
  const serviceAccount = JSON.parse(env.GOOGLE_SERVICE_ACCOUNT_JSON);
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

  const jwt = `${encodedHeader}.${encodedClaim}.${base64url(new Uint8Array(signature))}`;

  const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
  });

  if (!tokenResponse.ok) {
    throw new Error('Token exchange failed: ' + await tokenResponse.text());
  }

  return (await tokenResponse.json()).access_token;
}

function base64url(input) {
  let bytes = typeof input === 'string' ? new TextEncoder().encode(input) : new Uint8Array(input);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function pemToArrayBuffer(pem) {
  const b64 = pem.replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\n/g, '');
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}