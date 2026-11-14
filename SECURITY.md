# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | ✅ |
| pre-release builds | ❌ |

## Reporting a vulnerability

Open a private security advisory on this repository
(**Security → Report a vulnerability**) or open an issue if the report is not
sensitive. Please do not publish exploit details before a fix is available.

Include the affected version, Python and Flask versions, reproduction steps,
impact, and a suggested fix if you have one.

This is a personal educational project, so there is no paid bounty.

---

## Security model

### Intended use

The dashboard is a **teaching tool for an isolated lab**. Its data is synthetic
and its address space is RFC 1918. It is not a production SIEM and it has not
been assessed for multi-tenant or internet-facing deployment.

### What the application defends

| Threat | Control |
| --- | --- |
| Unauthenticated access to the dashboard | Session-based login on every route and every JSON endpoint |
| Password disclosure from the database | Werkzeug scrypt hashes; plaintext is never stored |
| Shipped default credentials | No password is committed. A random one is generated on first run, printed once, and stored only as a hash |
| Session cookie theft over the wire | `HttpOnly`, `SameSite=Lax`, and optional `Secure` (`SOC_COOKIE_SECURE=1`) |
| Cross-site request forgery | Per-session token required on every `POST`, compared in constant time |
| Open redirect after login | `?next=` accepts only site-relative paths; scheme, host, and `//` prefixes are rejected |
| Credential guessing | In-memory throttle: 10 failures per IP per 5 minutes |
| Session-fixation style replay | Flask signs the session; rotating the key invalidates all sessions |
| Secret committed to source control | Signing key comes from `SOC_SECRET_KEY` or a git-ignored `.secret_key` file with restrictive permissions |
| Information disclosure in errors | Exception text is logged server-side; the browser receives a generic message |
| SQL injection | Every query is parameterised |
| Debug console exposed | `debug` is off unless `SOC_DEBUG=1` is explicitly set |

### What it does **not** defend

| Threat | Why |
| --- | --- |
| A local administrator | Can read the database, the signing key, and process memory |
| Internet exposure | No TLS termination, no WAF, no account lockout persistence |
| Distributed password guessing | The throttle is per process, per IP, and resets on restart |
| Cross-site scripting from ingested logs | Log fields are rendered through a template, but treat untrusted log input as suspect and review before publishing |
| Denial of service | Upload size and request rate are not capped |

If you need any of these, put the application behind a reverse proxy with TLS,
size limits, and a persistent rate limiter — or use a real SIEM.

---

## Operator checklist

1. Set `SOC_SECRET_KEY` to a long random value before the first run, or let the
   application create `.secret_key` and make sure that file is not published.
2. Record the generated administrator password from the first-run console output.
3. Keep the database (`soc_dashboard.db`) out of version control. It is ignored
   by default.
4. Run behind localhost or a trusted lab network. Do not port-forward it.
5. Set `SOC_COOKIE_SECURE=1` once you terminate TLS in front of the app.

## Design notes

- **Password hashing** uses `werkzeug.security.generate_password_hash`, which
  selects scrypt with a per-password salt and sane parameters.
- **CSRF tokens** live in the signed session, are generated with
  `secrets.token_urlsafe(32)`, and are compared with `secrets.compare_digest`.
- **Detection queries** are constant strings with bound parameters; no user
  input is interpolated into SQL.
- **Uploads** are read as bytes and decoded with `errors="replace"`, so a
  malformed file cannot crash the ingestion loop.
