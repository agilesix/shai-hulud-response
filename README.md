# a6-shai-hulud-response
Cobenian scanner to run on active A6 endpoints (both Mac and PC)

# Shai-Hulud 2.0 Response System

Internal tooling for detecting and responding to the Shai-Hulud npm supply chain attack.

## Components

| Component | Location | Description |
|-----------|----------|-------------|
| macOS Scanner | `scanners/macos/` | Kandji-deployed scanner for Mac endpoints |
| Windows Scanner | `scanners/windows/` | Action1-deployed scanner for Windows endpoints |
| Webhook Worker | `webhook/` | Cloudflare Worker that receives scan results |
| Documentation | `docs/` | SOPs and guides |

## Architecture
```
┌─────────────┐     ┌─────────────┐
│   Kandji    │     │   Action1   │
│   (macOS)   │     │  (Windows)  │
└──────┬──────┘     └──────┬──────┘
       │                   │
       ▼                   ▼
┌─────────────────────────────────┐
│     Endpoint Scanners           │
│  (downloads Cobenian detector)  │
└──────────────┬──────────────────┘
               │
               ▼
┌─────────────────────────────────┐
│   Cloudflare Worker (webhook)   │
│   kandji-ack-worker.workers.dev │
└──────────────┬──────────────────┘
               │
               ▼
┌─────────────────────────────────┐
│        Google Sheets            │
│   (Scan Results & Tracking)     │
└─────────────────────────────────┘
```

## Deployment

See [docs/deployment-guide.md](docs/deployment-guide.md)

## Scanner Versions

- **v2.0.3** - Current production (self-backgrounding, Cobenian integration, error capture)

## Dependencies

- [Cobenian/shai-hulud-detect](https://github.com/Cobenian/shai-hulud-detect) - Detection signatures (downloaded at runtime)

## Security Notes

- Secrets are managed via Cloudflare Workers secrets (not in repo)
- Google Sheets ID is referenced but not the service account key
- Scanner shared secret should be rotated periodically
EOF