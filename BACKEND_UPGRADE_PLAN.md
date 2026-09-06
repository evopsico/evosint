# Backend Upgrade Plan for Enhanced OSINT Tool

## Current State
- Node.js/Express backend with ~12 OSINT API endpoints
- Serving static HTML/JS frontend
- Running on port 3000/3002

## Planned Enhancements
1. Keep existing API endpoints (backward compatibility)
2. Add new API endpoints for additional OSINT tools (target: 18+ new = 30+ total)
3. Enhance existing endpoints with more features/data
4. Add WebSocket support for real-time updates (optional)
5. Add rate limiting and caching for performance
6. Improve error handling and logging

## New API Endpoints to Add
### Network & Infrastructure
- /api/subdomain/:domain - Subdomain enumeration
- /api/portscan/:ip - Basic port scanning (common ports)
- /api/technology/:url - Technology stack detection
- /api/asn/:asn - ASN information lookup
- /api/reverseip/:ip - Reverse IP lookup (hosted domains)
- /api/dnssec/:domain - DNSSEC validation
- /api/spf/:domain - SPF record check
- /api/dkim/:domain/:selector - DKIM record check
- /api/dmarc/:domain - DMARC record check
- /api/sslct/:domain - SSL Certificate Transparency logs
- /api/httpheaders/:url - HTTP header analysis
- /api/urlshort/:url - URL expander for shortened links

### Digital Footprint
- /api/metadata - File upload for EXIF/metadata extraction
- /api/reverseimage - Reverse image search (placeholder for API)
- /api/videometa - Video metadata extraction
- /api/pastebin/:query - Pastebin search
- /api/cryptoaddress/:address - Cryptocurrency address analysis
- /api/domainage/:domain - Domain registration age/check
- /api/geocode/:address - Geocoding (address to coordinates)
- /api/reversegeo/:lat,:lon - Reverse geocoding
- /api/breachmonitor/:domain - Breach monitoring for domain
- /api/threatfeed/:indicator - Threat intelligence feed check

### Utility & Analysis
- /api/timestamp - Timestamp conversion (Unix, ISO, human)
- /api/passwordcheck - Password strength analysis
- /api/breachalert - Set up breach alerts (simulated)
- /api/urlparams - URL parameter analysis
- /api/filehash - File upload for hash generation
- /api/networkutils - Network utilities (ping, traceroute simulation)
- /api/sslcipher/:domain - SSL cipher suite analysis
- /api/emailheader - Email header analysis
- /api/socialdeep/:username - Deep social media analysis
- /api/databroker/:info - Data broker information search
- /api/leaksearch/:query - Leaked database search (public sources)
- /api/blacklist/:ip - IP blacklist/reputation check
- /api/vulnscan/:url - Basic web vulnerability scan
- /api/threatactor/:name - Threat actor information

## Implementation Approach
1. Add new route files in backend/routes/ for each category
2. Update backend/server.js to include new routes
3. For tools requiring file uploads, add multer middleware
4. For tools requiring API keys, use environment variables
5. Add caching layer (node-cache or redis) for expensive operations
6. Add rate limiting (express-rate-limit) where appropriate
7. Implement proper error responses with status codes
8. Add input validation and sanitization for all endpoints