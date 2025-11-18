# Security Documentation

## Overview

This document outlines the security features, best practices, and considerations for the Aviation Intelligence Hub application. This version includes comprehensive security enhancements to protect against common web vulnerabilities.

## Security Features

### 1. Input Validation & Sanitization

**Location**: `security.py` - `InputValidator` class

All user inputs are validated and sanitized before processing:

- **URL Validation**: Strict validation with length limits (max 2048 chars)
- **String Sanitization**: Trimming, length limits, pattern matching
- **Integer Validation**: Range checking with configurable min/max values
- **Sentiment Filter Validation**: Whitelist-based validation

**Implementation**:
```python
# Example usage in app.py
url = InputValidator.validate_string(data.get("url"), max_length=2048)
page = InputValidator.validate_integer(request.args.get("page"), min_val=1, default=1)
```

### 2. SSRF (Server-Side Request Forgery) Protection

**Location**: `security.py` - `URLValidator` class

Prevents the application from being used to probe internal networks:

**Protected Against**:
- Private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Loopback addresses (127.0.0.0/8)
- Link-local addresses (169.254.0.0/16)
- Cloud metadata endpoints (169.254.169.254, metadata.google.internal)
- IPv6 private addresses

**Features**:
- Domain whitelist support (`ALLOWED_DOMAINS`)
- Domain blacklist with secure defaults (`BLOCKED_DOMAINS`)
- Scheme validation (only http:// and https://)
- Port validation (blocks dangerous ports: 22, 23, 3389, 5900, etc.)
- Hostname validation

**Configuration**:
```bash
# .env file
ALLOWED_DOMAINS=example.com,trusted-site.org  # Whitelist (optional)
BLOCKED_DOMAINS=internal.company.com,admin.local  # Additional blacklist
```

### 3. Rate Limiting

**Location**: `app.py` - Flask-Limiter integration

Prevents abuse through rate limiting on all API endpoints:

| Endpoint | Rate Limit |
|----------|------------|
| `/api/ingest` | 30 per minute |
| `/api/feeds/add` | 20 per minute |
| `/api/feeds/refresh` | 10 per minute |
| `/api/emails` | 60 per minute |
| `/api/ai/summarize` | 10 per minute |

**Configuration**:
```bash
# .env file
RATE_LIMIT_ENABLED=True
RATE_LIMIT_DEFAULT=60 per minute
```

**Disable for testing** (not recommended in production):
```bash
RATE_LIMIT_ENABLED=False
```

### 4. Security Headers

**Location**: `app.py` - Flask-Talisman integration

Implements security headers when not in debug mode:

- **Content Security Policy (CSP)**: Restricts resource loading
- **X-Frame-Options**: Prevents clickjacking
- **X-Content-Type-Options**: Prevents MIME sniffing
- **Strict-Transport-Security (HSTS)**: Forces HTTPS (in production)

**CSP Configuration**:
```python
csp = {
    'default-src': "'self'",
    'script-src': ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", ...],
    'style-src': ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
    'img-src': "'self' data: https:",
    'connect-src': "'self'",
}
```

**Note**: In debug mode, security headers are disabled for easier development. Enable in production.

### 5. Secure Configuration Management

**Location**: `config.py`

Centralized configuration with validation:

- **No Hardcoded Secrets**: All sensitive values from environment variables
- **Configuration Validation**: Startup validation prevents misconfigurations
- **Security Warnings**: Alerts for insecure defaults

**Example**:
```python
# config.py validates on startup
config.validate()  # Raises ValueError if invalid
```

### 6. Enhanced Logging

**Location**: `app.py`, `config.py`

Structured logging for security monitoring:

- Configurable log levels (`LOG_LEVEL=INFO|DEBUG|WARNING|ERROR`)
- Security event logging (failed validations, blocked requests)
- Request context logging (IP addresses via `get_client_ip()`)

### 7. Database Security

- **Parameterized Queries**: All SQL queries use parameterization to prevent SQL injection
- **Connection Timeouts**: Prevents connection exhaustion
- **Thread-safe Connections**: Separate connections for background threads
- **No Raw SQL**: Uses SQLite's parameter substitution

### 8. Secret Management

**Critical**: Never commit secrets to version control!

**Default Secrets to Change**:
1. `SECRET_KEY` - Flask secret key for sessions/CSRF
2. `CF_WORKER_TOKEN` - Cloudflare Worker authentication token

**Generate Secure Values**:
```bash
# Generate SECRET_KEY
python -c "import secrets; print(secrets.token_hex(32))"

# Generate CF_WORKER_TOKEN
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

## Vulnerability Mitigations

### SQL Injection
**Status**: ✅ Protected

All database queries use parameterized statements:
```python
# Safe - parameterized
cursor.execute("SELECT * FROM news_items WHERE id = ?", (item_id,))

# Unsafe - NEVER do this
cursor.execute(f"SELECT * FROM news_items WHERE id = {item_id}")  # ❌
```

### Cross-Site Scripting (XSS)
**Status**: ✅ Protected

- HTML output is escaped using `html.escape()`
- Flask's Jinja2 templates auto-escape by default
- CSP headers restrict inline scripts (in production)

### Server-Side Request Forgery (SSRF)
**Status**: ✅ Protected

- URL validation before all HTTP requests
- Private IP blocking
- Domain whitelisting/blacklisting
- Port restrictions

### Denial of Service (DoS)
**Status**: ⚠️ Partially Protected

- Rate limiting on all API endpoints
- Request timeouts configured
- Database connection timeouts
- **Recommendation**: Use a reverse proxy (nginx) with additional rate limiting

### Clickjacking
**Status**: ✅ Protected (in production)

- X-Frame-Options header via Flask-Talisman
- Only enabled when `FLASK_DEBUG=False`

### Sensitive Data Exposure
**Status**: ✅ Protected

- `.gitignore` prevents committing secrets
- Configuration summary masks sensitive values
- Database files excluded from version control

## Security Checklist for Deployment

### Before Deploying to Production

- [ ] Change `SECRET_KEY` to a secure random value
- [ ] Change `CF_WORKER_TOKEN` to a secure random value
- [ ] Set `FLASK_ENV=production` and `FLASK_DEBUG=False`
- [ ] Enable HTTPS with a reverse proxy (nginx, Caddy, etc.)
- [ ] Configure `ALLOWED_DOMAINS` if possible (whitelist)
- [ ] Review and update `BLOCKED_DOMAINS` as needed
- [ ] Set `RATE_LIMIT_ENABLED=True`
- [ ] Configure appropriate rate limits for your use case
- [ ] Review and test CSP headers
- [ ] Set up log monitoring and alerting
- [ ] Ensure `.env` file has restricted permissions: `chmod 600 .env`
- [ ] Verify database file permissions: `chmod 600 emails.db`
- [ ] Set up automated backups of `emails.db`
- [ ] Configure firewall rules (allow only ports 80/443)
- [ ] Run the application with a non-root user
- [ ] Keep dependencies updated: `pip install -U -r requirements.txt`

### Production Web Server Setup

**Recommended**: Use Gunicorn behind nginx/Caddy with HTTPS

```bash
# Install Gunicorn
pip install gunicorn

# Run with 4 workers
gunicorn -w 4 -b 127.0.0.1:5001 app:app

# Nginx reverse proxy configuration
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:5001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Monitoring & Incident Response

### Log Monitoring

Monitor logs for suspicious activity:

```bash
# Watch logs in real-time
tail -f /path/to/logs/app.log | grep -i "warning\|error\|security"

# Search for failed validations
grep "validation failed" /path/to/logs/app.log

# Search for rate limit hits
grep "rate limit exceeded" /path/to/logs/app.log
```

### Security Events to Monitor

- **Failed URL validations**: May indicate SSRF attempts
- **Rate limit exceeded**: May indicate DoS attack or abuse
- **Configuration validation failures**: May indicate misconfiguration
- **Database errors**: May indicate SQL injection attempts (though protected)
- **Unusual request patterns**: Spike in requests from single IP

### Incident Response

If you suspect a security incident:

1. **Isolate**: Temporarily disable affected endpoints or block suspicious IPs
2. **Investigate**: Review logs, database, and request patterns
3. **Patch**: Update configuration or code as needed
4. **Monitor**: Increase logging verbosity, watch for repeat attempts
5. **Document**: Record incident details for future reference

## Known Limitations

1. **No Authentication**: All endpoints are public. Consider adding authentication for production.
2. **In-Memory Rate Limiting**: Rate limits reset on app restart. Consider Redis for persistence.
3. **SQLite Database**: Not ideal for high-concurrency. Consider PostgreSQL for production.
4. **No CAPTCHA**: No bot protection beyond rate limiting.
5. **Session Management**: Minimal session security (no session fixation protection).

## Reporting Security Issues

If you discover a security vulnerability, please:

1. **Do not** open a public GitHub issue
2. Email security concerns to: [your-security-email]
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will respond within 48 hours and work with you to address the issue.

## Security Updates

Keep the application secure:

```bash
# Update Python packages
pip install -U -r requirements.txt

# Check for security vulnerabilities
pip install safety
safety check
```

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Flask Security Best Practices](https://flask.palletsprojects.com/en/latest/security/)
- [SQLite Security](https://www.sqlite.org/security.html)

## Version History

- **v2.0** (Current): Added comprehensive security features
  - Input validation and sanitization
  - SSRF protection
  - Rate limiting
  - Security headers
  - Centralized configuration
  - Enhanced logging

- **v1.0**: Initial version (security vulnerabilities present)
