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
      return new Response('Error: ' + err.message, { status: 500 });
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

// Handle scan result submissions
async function handleScanResult(body, env) {
  const accessToken = await getAccessToken(env);
  
  const now = new Date().toISOString();
  const row = [
    now,                              // Server Timestamp
    body.serial || '',                // Serial
    body.hostname || '',              // Hostname
    body.user || '',                  // User
    body.os || '',                    // OS (darwin/windows)
    body.status || '',                // Status (clean/affected/error)
    body.high_risk_count || 0,        // High Risk Count
    body.medium_risk_count || 0,      // Medium Risk Count
    body.low_risk_count || 0,         // Low Risk Count
    body.high_risk_details || '',     // High Risk Details (comma-separated)
    body.medium_risk_details || '',   // Medium Risk Details
    body.scan_duration_ms || '',      // Scan Duration (ms)
    body.scanner_version || '',       // Scanner Version
    body.raw_output || ''             // Raw Output (truncated if needed)
  ];

  const range = 'Scan Results!A:N';
  
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

// Google Service Account JWT auth
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
