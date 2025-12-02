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
│  (downloads IOC list from repo) │
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

- **v2.0.7** - Current production (November 2025 Shai-Hulud 2.0 coverage, merged IOC list)
- **v2.0.6** - Native lockfile parsing, removed Bash dependency
- **v2.0.3** - Self-backgrounding, Cobenian integration, error capture

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

## Dependencies

- IOC list hosted in this repository: `ioc/compromised-packages.txt`
- Merged from [Cobenian/shai-hulud-detect](https://github.com/Cobenian/shai-hulud-detect) and [Wiz Security Research IOCs](https://github.com/wiz-sec-public/wiz-research-iocs)

## Security Notes

- Secrets are managed via Cloudflare Workers secrets (not in repo)
- Google Sheets ID is referenced but not the service account key
- Scanner shared secret should be rotated periodically
EOF