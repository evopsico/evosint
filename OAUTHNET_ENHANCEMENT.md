# OathNet Enhancement for OSINT Tool

## What is OathNet?
In the context of OSINT, "OathNet" likely refers to tools and techniques for analyzing OAuth/OpenID Connect implementations, which are common authentication protocols used by websites and applications. Analyzing these can reveal security misconfigurations, information disclosure, and potential attack vectors.

## OathNet-Related OSINT Tools to Add

### 1. OAuth Endpoint Discovery
- **/api/oauth/discover/:domain** - Discover OAuth/OIDC endpoints (authorization, token, userinfo, jwks)
- **/api/oauth/register/:domain** - Check for open OAuth registration
- **/api/oauth/jwks/:domain** - Fetch and analyze JWKS (JSON Web Key Set)

### 2. OAuth Security Analysis
- **/api/oauth/vulnerabilities/:domain** - Check for common OAuth vulnerabilities
- **/api/oauth/tokens/:token** - Analyze OAuth/JWT tokens (decode, validate, check for issues)
- **/api/oauth/scopes/:domain** - Analyze available OAuth scopes
- **/api/oauth/clients/:domain** - Discover OAuth client applications (if exposed)

### 3. OpenID Connect Analysis
- **/api/oidc/config/:domain** - Fetch OpenID Connect discovery document
- **/api/oidc/userinfo/:token** - Get user info from access token
- **/api/oidc/session/:domain** - Check session management

### 4. SAML Analysis (Related Federation Tech)
- **/api/saml/metadata/:domain** - Fetch and analyze SAML metadata
- **/api/saml/vulnerabilities/:domain** - Check for SAML vulnerabilities (XML external entities, signature wrapping, etc.)

### 5. API Key & Secret Detection
- **/api/apikeys/:domain** - Search for exposed API keys in JavaScript, HTML, etc.
- **/api/secretscan/:url** - Scan for secrets in public repositories (GitHub, GitLab, etc.)

## Implementation Notes
- These would be additional API endpoints in the backend
- Some would require making requests to target domains (with rate limiting)
- Others would be analysis tools (token decoding, etc.)
- Should include proper error handling and timeouts
- Consider caching results for discovery endpoints
- Add input validation to prevent SSRF where appropriate

## UI Integration
In the frontend, these would appear as:
- "OAuth Analysis" tool card
- "OpenID Connect Scanner" 
- "API Key Detector"
- "JWT Analyzer"
- "SAML Security Check"