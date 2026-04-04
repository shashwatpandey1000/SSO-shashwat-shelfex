# Shelfex SSO — Security Architecture

## Authentication Model

OAuth 2.0 Authorization Code Flow with PKCE, powering SSO across all Shelfex products.

---

## Security Measures

### OAuth & Token Security

| Measure | Implementation |
|---------|---------------|
| PKCE (S256) | `code_verifier` / `code_challenge` on every OAuth flow — prevents auth code interception |
| Nonce | OpenID Connect nonce in ID tokens — prevents replay attacks |
| OAuth State | Random UUID per flow, validated on callback — prevents CSRF on OAuth |
| Auth Code Hashing | SHA-256 hashed before DB storage — DB breach doesn't expose active codes |
| One-Time Auth Codes | Marked used after exchange, 10-minute expiry |
| Redirect URI Validation | Exact match against registered `allowed_redirect_uris` per client app |
| Client Secret (bcrypt) | Client secrets stored with bcrypt (12 rounds) — never plaintext in DB |

### Token Management

| Measure | Implementation |
|---------|---------------|
| httpOnly Cookies | All tokens (access, refresh, session) in httpOnly cookies — no JS access |
| sameSite: lax | All cookies — prevents cross-site request forgery |
| Secure Flag | `secure: true` in production — HTTPS only |
| Short-Lived Access Tokens | 1-hour JWT expiry, audience + issuer validated |
| Refresh Token Rotation | New token pair on every refresh, old token revoked |
| Reuse Detection | If revoked refresh token is used → all user sessions revoked |
| Separate ID Token | Distinct secret + audience (`shelfex-id-token`) — can't be confused with access tokens |
| No Tokens in Response Body | Login response contains user info only — tokens are in httpOnly cookies |

### Password Security

| Measure | Implementation |
|---------|---------------|
| bcrypt (12 rounds) | All passwords hashed with bcrypt |
| Strength Validation | Min 8 chars, uppercase, lowercase, number, special character |
| OTP Hashing | Email verification codes SHA-256 hashed before DB storage |
| Reset Token Hashing | Password reset tokens SHA-256 hashed before DB storage |
| Session Revocation on Reset | All refresh tokens revoked when password is changed |

### Rate Limiting (DB-Based)

| Endpoint | Limit |
|----------|-------|
| Login (per account) | 5 failed attempts / 15 min |
| Login (per IP) | 20 attempts / 15 min |
| Registration (per IP) | 5 / hour |
| Email sending (per email) | 3 / 15 min |
| OTP verification (per email) | 5 / 15 min |
| Token exchange (per IP) | 10 / 15 min |

### Infrastructure Security

| Measure | Implementation |
|---------|---------------|
| Helmet.js | HTTP security headers (CSP, X-Frame-Options, etc.) |
| CORS Whitelist | Only registered origins allowed; no-origin blocked in production |
| Trust Proxy | Express `trust proxy` enabled — accurate client IP behind ALB/nginx |
| req.ip | All IP extraction via `req.ip` (proxy-aware) — no spoofable `x-forwarded-for` |
| Input Limits | Request body capped at 16KB |
| Env Validation | All required env vars validated at startup via `envalid` |

### Audit & Monitoring

| Measure | Implementation |
|---------|---------------|
| Audit Logs | All auth actions logged (login, register, password reset, rate limit hits) |
| IP + User Agent | Captured on every audit event |
| Structured Logging | Winston logger with log levels |

### Anti-Enumeration

| Measure | Implementation |
|---------|---------------|
| Registration | Generic error: "An account with these details already exists" |
| Forgot Password | Always returns "If that email is registered, a reset link has been sent" |
| Resend Verification | Always returns "If that email is registered, a code has been sent" |

---

## Architecture

### Path 1: Login-Initiated Flow (Cross-Domain Safe)

```
Client App                    SSO
─────────                     ───
middleware.ts                 /oauth/authorize
  ├─ generate state              ├─ validate client_id + redirect_uri
  ├─ generate PKCE verifier      ├─ no accounts_session cookie
  ├─ compute S256 challenge      └─ redirect to SSO frontend /login
  ├─ generate nonce
  └─ redirect to SSO            /auth/login (POST, with OAuth params)
                                  ├─ validate credentials (bcrypt)
/auth/callback                    ├─ rate limit check (IP + identifier)
  ├─ validate state               ├─ validate client_id + redirect_uri
  ├─ read PKCE verifier           ├─ check email verification
  ├─ send to backend              ├─ generate auth code directly
  └─ set httpOnly cookies         ├─ store code_challenge + nonce
                                  └─ return callback URL with code
                                     (no cross-site cookie needed)

                              /oauth/token
                                ├─ verify client_secret (bcrypt)
                                ├─ verify code_verifier vs code_challenge
                                ├─ validate auth code (hash lookup)
                                ├─ issue access + refresh + id tokens
                                └─ nonce embedded in id_token
```

### Path 2: Session-Based Flow (Same-Domain Silent SSO)

```
Client App                    SSO
─────────                     ───
middleware.ts                 /oauth/authorize
  ├─ generate state              ├─ validate client_id + redirect_uri
  ├─ generate PKCE verifier      ├─ verify accounts_session cookie ✓
  ├─ compute S256 challenge      ├─ hash + store auth code
  ├─ generate nonce              ├─ store code_challenge + nonce
  └─ redirect to SSO             └─ redirect to client with code
                                     (no login prompt needed)
/auth/callback
  ├─ validate state           /oauth/token
  ├─ read PKCE verifier          ├─ verify client_secret (bcrypt)
  ├─ send to backend             ├─ verify code_verifier vs code_challenge
  └─ set httpOnly cookies        ├─ validate auth code (hash lookup)
                                 ├─ issue access + refresh + id tokens
                                 └─ nonce embedded in id_token
```

> Path 1 always works across any domain configuration.
> Path 2 requires SSO frontend and server to share a site (e.g., both under `*.shelfex.com`).

### Security Equivalence

Both paths provide identical security guarantees:

| Property | Path 1 (Login-Initiated) | Path 2 (Session-Based) |
|----------|------------------------|----------------------|
| User authentication | Password (bcrypt) | Session cookie (from prior password auth) |
| client_id validation | ✓ | ✓ |
| redirect_uri validation | ✓ | ✓ |
| PKCE code_challenge stored | ✓ | ✓ |
| Nonce stored | ✓ | ✓ |
| Auth code hashed in DB | ✓ | ✓ |
| Auth code single-use | ✓ | ✓ |
| Token exchange requires client_secret | ✓ | ✓ |
| Email verification enforced | ✓ | ✓ |
| Rate limiting | ✓ (login rate limits) | N/A (already authenticated) |
