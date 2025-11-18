# Aviation Intelligence Hub

A sophisticated Flask-based web application that aggregates, analyzes, and monitors aviation news from multiple RSS/Atom feeds and web sources. Features real-time sentiment analysis, AI-powered summarization, and intelligent feed management.

## Features

- **Multi-Source Aggregation**: Ingest news from RSS/Atom feeds and HTML pages
- **Sentiment Analysis**: Automatic sentiment scoring using TextBlob
- **AI Summarization**: Integration with Cloudflare Workers for AI-powered summaries
- **Real-time Updates**: Server-Sent Events (SSE) for live notifications
- **Auto-refresh**: Periodic background feed updates with parallel processing
- **Content Deduplication**: Hash-based duplicate detection
- **Smart Feed Discovery**: Automatic RSS/Atom feed detection
- **Search & Filter**: Full-text search and sentiment filtering
- **Data Export**: CSV export functionality
- **Responsive UI**: Dark/light theme support

## Security Features (NEW!)

This version includes comprehensive security enhancements:

- **Input Validation**: All user inputs are validated and sanitized
- **SSRF Protection**: URL validation prevents access to private networks
- **Rate Limiting**: API endpoints have rate limits to prevent abuse
- **Security Headers**: CSP, HSTS, and other security headers (via Flask-Talisman)
- **Centralized Configuration**: Environment-based configuration management
- **Enhanced Logging**: Structured logging with configurable levels
- **No Hardcoded Secrets**: All sensitive values use environment variables

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Setup

1. **Clone the repository**
   ```bash
   git clone <your-repo-url>
   cd AviationNews
   ```

2. **Create a virtual environment** (recommended)
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**
   ```bash
   cp .env.example .env
   ```

   Edit `.env` and set your configuration values:
   - **REQUIRED**: Change `CF_WORKER_TOKEN` to a secure random token
   - **REQUIRED**: Change `SECRET_KEY` to a secure random key
   - **RECOMMENDED**: Update `CF_WORKER_URL` if you have your own Cloudflare Worker
   - **OPTIONAL**: Configure domain restrictions, rate limits, etc.

   Generate secure tokens:
   ```bash
   # Generate a secret key
   python -c "import secrets; print(secrets.token_hex(32))"

   # Generate a worker token
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

5. **Initialize the database**
   ```bash
   python app.py
   ```
   The database will be automatically created on first run.

## Usage

### Starting the Application

```bash
python app.py
```

The application will start on `http://localhost:5001` by default.

### Adding Feeds

1. Navigate to the main dashboard
2. Enter a URL in the "Ingest New Content" field
3. Optionally check "Auto-add as feed" to save it for automatic updates
4. Click "Ingest"

### Managing Feeds

- View all feeds in the "Manage Feeds" section
- Refresh feeds manually or enable auto-refresh
- Remove feeds you no longer need

### AI Summarization

1. Navigate to the main feed view
2. Click "Generate AI Summaries"
3. Summaries will be processed in batches and appear in real-time

## Configuration

### Environment Variables

See `.env.example` for all available configuration options:

| Variable | Description | Default |
|----------|-------------|---------|
| `AIH_DB` | Database file path | `emails.db` |
| `PORT` | Server port | `5001` |
| `SECRET_KEY` | Flask secret key | Auto-generated |
| `CF_WORKER_URL` | Cloudflare Worker URL | (required for AI) |
| `CF_WORKER_TOKEN` | Worker authentication token | (required for AI) |
| `RATE_LIMIT_ENABLED` | Enable rate limiting | `True` |
| `ALLOWED_DOMAINS` | Domain whitelist (comma-separated) | (empty = all allowed) |
| `BLOCKED_DOMAINS` | Domain blacklist (comma-separated) | See `.env.example` |

### Security Configuration

**Domain Restrictions** (SSRF Protection):
- Set `ALLOWED_DOMAINS` to restrict which domains can be fetched
- `BLOCKED_DOMAINS` prevents access to private networks (pre-configured)
- Private IPs (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8) are always blocked

**Rate Limiting**:
- Default: 60 requests per minute per IP
- Customize with `RATE_LIMIT_DEFAULT` (e.g., "100 per minute", "5 per second")
- Disable with `RATE_LIMIT_ENABLED=False` (not recommended)

## API Endpoints

### News Management
- `GET /` - Main dashboard
- `POST /api/ingest` - Ingest a new URL
- `GET /api/emails` - Get news items (paginated, filterable)
- `GET /api/news/<id>` - Get single news item
- `GET /api/stats` - Get statistics

### Feed Management
- `GET /api/feeds` - List all feeds
- `POST /api/feeds/add` - Add a new feed
- `DELETE /api/feeds/<id>` - Remove a feed
- `POST /api/feeds/refresh` - Refresh feeds
- `POST /api/feeds/auto-refresh` - Toggle auto-refresh

### AI & Export
- `POST /api/ai/summarize` - Generate AI summaries
- `GET /api/ai/updates` - SSE stream for real-time updates
- `GET /api/export` - Export data as CSV

## Development

### Running in Debug Mode

Debug mode is enabled by default when running locally:
```bash
python app.py
```

### Running in Production

1. Set environment variables:
   ```bash
   export FLASK_ENV=production
   export FLASK_DEBUG=False
   ```

2. Use a production WSGI server (e.g., Gunicorn):
   ```bash
   pip install gunicorn
   gunicorn -w 4 -b 0.0.0.0:5001 app:app
   ```

3. **Important**: Configure a reverse proxy (nginx, Caddy) with HTTPS

### Project Structure

```
AviationNews/
├── app.py              # Main Flask application
├── config.py           # Configuration management
├── security.py         # Security utilities (validation, SSRF protection)
├── requirements.txt    # Python dependencies
├── .env                # Environment variables (DO NOT COMMIT!)
├── .env.example        # Example environment configuration
├── .gitignore          # Git ignore rules
├── templates/          # HTML templates
│   ├── base.html
│   ├── index.html
│   └── ...
└── emails.db           # SQLite database (auto-created)
```

## Troubleshooting

### Database Errors

If you encounter database errors, try:
```bash
rm emails.db
python app.py
```

### Configuration Errors

If the app fails to start with configuration errors:
1. Check your `.env` file syntax
2. Ensure all required variables are set
3. Validate numeric values are within acceptable ranges

### Rate Limiting Issues

If you're hitting rate limits during testing:
1. Set `RATE_LIMIT_ENABLED=False` in `.env`
2. Or increase limits: `RATE_LIMIT_DEFAULT=1000 per minute`

## Security Best Practices

1. **Never commit `.env` or `emails.db` to version control**
2. **Change default tokens** before deploying
3. **Use HTTPS** in production (configure reverse proxy)
4. **Restrict domains** with `ALLOWED_DOMAINS` if possible
5. **Keep dependencies updated**: `pip install -U -r requirements.txt`
6. **Monitor logs** for suspicious activity
7. **Enable rate limiting** in production

See [SECURITY.md](SECURITY.md) for detailed security information.

## License

[Your License Here]

## Contributing

Contributions are welcome! Please ensure:
- Code follows existing style
- Security best practices are maintained
- Tests are included (when available)
- Documentation is updated

## Support

For issues, questions, or contributions, please open an issue on GitHub.
