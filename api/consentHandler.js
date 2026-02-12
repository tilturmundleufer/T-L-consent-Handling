/**
 * Consent-Logging API für Vercel + Supabase
 *
 * Serverless Function: POST /api/consentHandler
 * Nimmt Consent-Events aus dem Browser entgegen, validiert sie,
 * prüft gegen Allowlist und schreibt in Supabase consent_events.
 *
 * Environment Variables (Vercel Dashboard / .env):
 *   SUPABASE_URL          - Supabase Projekt-URL
 *   SUPABASE_SERVICE_ROLE_KEY - Service Role Key (für Server-seitigen Zugriff)
 */

const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

// --- Konfiguration ---

const ALLOWLIST = [
  'turmundleufer.de',
  'unterkonstruktion.de',
  'www.state-of-mind.co',
  'philia-store.com',
];

/** Root-Domains für Subdomain-Matching (z.B. www.state-of-mind.co -> state-of-mind.co) */
const ALLOWLIST_ROOTS = ALLOWLIST.map((d) =>
  d.startsWith('www.') ? d.slice(4) : d
);

const VALID_ACTIONS = ['accept_all', 'reject_all', 'save_selection', 'unknown'];

const MAX_BODY_SIZE = 64 * 1024; // 64 KB (best effort)

// --- CORS ---

function setCorsHeaders(res, origin) {
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Max-Age', '86400');
}

// --- Domain-Allowlist ---

/**
 * Prüft, ob ein Hostname in der Allowlist ist oder Subdomain einer allowlisted Root.
 */
function isHostAllowed(hostname) {
  if (!hostname || typeof hostname !== 'string') return false;
  const host = hostname.toLowerCase().replace(/:\d+$/, ''); // Port entfernen

  if (ALLOWLIST.includes(host)) return true;
  return ALLOWLIST_ROOTS.some((root) => host === root || host.endsWith('.' + root));
}

/**
 * Ermittelt die erlaubte Origin aus Request-Headers.
 * Prüft Origin, dann Referer, dann Request-Host.
 * Gibt Origin zurück, wenn gültig; sonst null.
 */
function getAllowedOrigin(req) {
  const origin = req.headers.origin || req.headers.Origin;
  if (origin) {
    try {
      const url = new URL(origin);
      if (isHostAllowed(url.hostname)) return origin;
    } catch {
      return null;
    }
  }

  // Fallback: Referer prüfen (wenn Origin fehlt)
  const referer = req.headers.referer || req.headers.Referer;
  if (referer) {
    try {
      const url = new URL(referer);
      if (isHostAllowed(url.hostname)) return url.origin;
    } catch {
      /* ignore */
    }
  }

  // Fallback: Origin fehlt (z.B. keepalive/beacon) – prüfe Request-Host
  const host = req.headers.host || req.headers.Host;
  if (host) {
    const hostname = host.split(':')[0];
    if (isHostAllowed(hostname)) {
      const proto = req.headers['x-forwarded-proto'] || 'https';
      return `${proto}://${hostname}`;
    }
  }
  return null;
}

// --- Payload-Validierung ---

function ensureBoolean(val, fallback = false) {
  if (typeof val === 'boolean') return val;
  if (val === 'true' || val === 1) return true;
  if (val === 'false' || val === 0) return false;
  return fallback;
}

function validatePayload(raw, req) {
  if (!raw || typeof raw !== 'object') {
    return { error: 'Invalid payload: expected JSON object' };
  }

  const consent = raw.consent;
  if (!consent || typeof consent !== 'object') {
    return { error: 'Missing or invalid consent object' };
  }

  const action = raw.action;
  const validAction =
    typeof action === 'string' && VALID_ACTIONS.includes(action)
      ? action
      : 'unknown';

  return {
    ts: Number.isFinite(raw.ts) ? raw.ts : Date.now(),
    action: validAction,
    consent: {
      essential: ensureBoolean(consent.essential),
      analytics: ensureBoolean(consent.analytics),
      functional: ensureBoolean(consent.functional),
      marketing: ensureBoolean(consent.marketing),
    },
    version: typeof raw.version === 'string' ? raw.version : null,
    region: typeof raw.region === 'string' ? raw.region : null,
    language: typeof raw.language === 'string' ? raw.language : null,
    consent_uid: typeof raw.consent_uid === 'string' ? raw.consent_uid : null,
    gpc: ensureBoolean(raw.gpc),
    source: typeof raw.source === 'string' ? raw.source : null,
    domain: resolveDomain(raw, req),
  };
}

function resolveDomain(raw, req) {
  const payloadDomain = raw.domain;

  if (payloadDomain) {
    if (!isHostAllowed(payloadDomain)) {
      return { error: 'domain not in allowlist' };
    }
    return payloadDomain;
  }

  // Domain aus Origin oder Referer ableiten (Client-Domain, nicht API-Host)
  const origin = req.headers.origin || req.headers.Origin;
  if (origin) {
    try {
      const url = new URL(origin);
      if (isHostAllowed(url.hostname)) return url.hostname;
    } catch {
      /* ignore */
    }
  }
  const referer = req.headers.referer || req.headers.Referer;
  if (referer) {
    try {
      const url = new URL(referer);
      if (isHostAllowed(url.hostname)) return url.hostname;
    } catch {
      /* ignore */
    }
  }

  // Fallback: API auf gleicher Domain gehostet (req.host = Client-Domain)
  const reqHost = (req.headers.host || req.headers.Host || '').split(':')[0];
  if (reqHost && isHostAllowed(reqHost)) return reqHost;

  return { error: 'could not resolve allowed domain' };
}

// --- Payload-Hash (Deduplizierung) ---

function computePayloadHash(payload) {
  const tsBucket = Math.floor(payload.ts / 10000) * 10000; // 10 Sekunden runden
  const normalized = JSON.stringify({
    domain: payload.domain,
    action: payload.action,
    ts_bucket: tsBucket,
    consent: payload.consent,
    version: payload.version,
    consent_uid: payload.consent_uid,
  });
  return crypto.createHash('sha256').update(normalized).digest('hex');
}

// --- Supabase Insert ---

async function insertConsentEventWithHash(supabase, payload) {
  const row = {
    domain: payload.domain,
    action: payload.action,
    consent: payload.consent,
    version: payload.version,
    region: payload.region,
    language: payload.language,
    consent_uid: payload.consent_uid,
    gpc: payload.gpc,
    source: payload.source,
    payload_hash: computePayloadHash(payload),
  };

  const { error } = await supabase.from('consent_events').insert(row);
  if (error) throw error;
  return { success: true };
}

async function insertConsentEventWithoutHash(supabase, payload) {
  const row = {
    domain: payload.domain,
    action: payload.action,
    consent: payload.consent,
    version: payload.version,
    region: payload.region,
    language: payload.language,
    consent_uid: payload.consent_uid,
    gpc: payload.gpc,
    source: payload.source,
  };

  const { error } = await supabase.from('consent_events').insert(row);
  if (error) throw error;
  return { success: true };
}

// --- Hauptlogik ---

async function handlePost(req, res, origin) {
  const contentLength = parseInt(req.headers['content-length'] || '0', 10);
  if (contentLength > MAX_BODY_SIZE) {
    setCorsHeaders(res, origin);
    res.status(400).json({ error: 'Payload too large' });
    return;
  }

  let body = req.body;
  if (typeof body === 'string') {
    try {
      body = JSON.parse(body);
    } catch {
      setCorsHeaders(res, origin);
      res.status(400).json({ error: 'Invalid JSON' });
      return;
    }
  }
  if (!body || typeof body !== 'object') {
    setCorsHeaders(res, origin);
    res.status(400).json({ error: 'Invalid payload' });
    return;
  }

  const validated = validatePayload(body, req);
  if (validated.error) {
    setCorsHeaders(res, origin);
    res.status(400).json({ error: validated.error });
    return;
  }

  if (validated.domain && typeof validated.domain === 'object' && validated.domain.error) {
    setCorsHeaders(res, origin);
    res.status(403).json({ error: validated.domain.error });
    return;
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !supabaseKey) {
    setCorsHeaders(res, origin);
    res.status(500).json({ error: 'Server configuration error' });
    return;
  }

  const supabase = createClient(supabaseUrl, supabaseKey);

  try {
    await insertConsentEventWithHash(supabase, validated);
  } catch (err) {
    if (err.code === '42703' || err.message?.includes('payload_hash')) {
      await insertConsentEventWithoutHash(supabase, validated);
    } else {
      console.error('[consentHandler] DB error:', err.message);
      setCorsHeaders(res, origin);
      res.status(500).json({ error: 'Database error' });
      return;
    }
  }

  // Logging: nur minimal, keine sensiblen Daten
  console.log('[consentHandler] 204', validated.domain, validated.action);

  setCorsHeaders(res, origin);
  res.status(204).end();
}

// --- Export für Vercel ---

module.exports = (req, res) => {
  const origin = getAllowedOrigin(req);

  if (req.method === 'OPTIONS') {
    setCorsHeaders(res, origin);
    res.status(204).end();
    return;
  }

  if (req.method !== 'POST') {
    setCorsHeaders(res, origin);
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }

  if (!origin) {
    res.status(403).json({ error: 'Origin not allowed' });
    return;
  }

  handlePost(req, res, origin).catch((err) => {
    console.error('[consentHandler] Unhandled:', err.message);
    setCorsHeaders(res, origin);
    res.status(500).json({ error: 'Internal server error' });
  });
};

/*
 * Self-Test (curl):
 *
 * # 1. OPTIONS preflight
 * curl -X OPTIONS https://your-project.vercel.app/api/consentHandler \
 *   -H "Origin: https://turmundleufer.de" \
 *   -H "Access-Control-Request-Method: POST" \
 *   -H "Access-Control-Request-Headers: Content-Type" -v
 *
 * # 2. POST mit gültigem Payload
 * curl -X POST https://your-project.vercel.app/api/consentHandler \
 *   -H "Origin: https://turmundleufer.de" \
 *   -H "Content-Type: application/json" \
 *   -d '{"action":"accept_all","consent":{"essential":true,"analytics":true,"functional":false,"marketing":false}}'
 *
 * # Erwartung: 204 No Content
 *
 * # 3. Erwarteter 403 bei nicht erlaubter Origin
 * curl -X POST https://your-project.vercel.app/api/consentHandler \
 *   -H "Origin: https://evil.com" \
 *   -H "Content-Type: application/json" \
 *   -d '{"action":"accept_all","consent":{"essential":true,"analytics":true,"functional":false,"marketing":false}}'
 *
 * # Erwartung: 403 Forbidden
 */
