# Consent-Logging API (Vercel + Supabase)

Serverless Function für Consent-Events. Endpoint: `POST /api/consentHandler`

## Environment Variables

In Vercel Dashboard → Project → Settings → Environment Variables setzen:

| Variable | Beschreibung |
|----------|--------------|
| `SUPABASE_URL` | Supabase Projekt-URL (z.B. `https://xxx.supabase.co`) |
| `SUPABASE_SERVICE_ROLE_KEY` | Service Role Key für Server-seitigen DB-Zugriff |

## Supabase Tabelle

Tabelle `consent_events` mit Spalten:

- `created_at` (timestamp, default `now()`)
- `domain`, `action`, `consent` (jsonb), `version`, `region`, `language`, `consent_uid`, `gpc`, `source`
- optional: `payload_hash` (text) für Duplikaterkennung

## Deployment

```bash
npm install
vercel deploy
```

Siehe auch: curl-Beispiele am Ende von `api/consentHandler.js`
