# Aviation Intelligence Hub - Quick Start

## 🚀 Run Locally in 3 Steps

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure (Optional)
```bash
# Copy environment template
cp .env.example .env

# Edit .env and set:
# - CF_WORKER_URL (your Cloudflare AI worker)
# - CF_WORKER_TOKEN (secure random token)
# Or leave defaults for basic RSS feed tracking
```

### 3. Run the App
```bash
python3 app.py
```

Open **http://localhost:5001** in your browser.

---

## ✅ What Works Out of the Box

- **RSS Feed Management** - Add, refresh, and track aviation news feeds
- **Sentiment Analysis** - Local TextBlob sentiment scoring (no API needed)
- **Search & Filter** - Filter by sentiment, search content
- **Export** - Download data as CSV/JSON
- **Security** - SSRF protection, rate limiting, input validation

## 🤖 AI Summaries (Optional)

To enable AI-powered summaries, you need a Cloudflare Worker:

1. Set `CF_WORKER_URL` and `CF_WORKER_TOKEN` in `.env`
2. Deploy the worker from `worker.js` (see SECURITY.md for details)
3. Click "Generate AI Summaries" in the UI

**Without AI Worker:** App still works for RSS feed tracking and basic sentiment analysis.

---

## 📊 Quick Test

```bash
# Start the app
python3 app.py

# In another terminal, test the API
curl http://localhost:5001/api/stats

# Add a test feed
curl -X POST http://localhost:5001/api/feeds \
  -H "Content-Type: application/json" \
  -d '{"url":"https://www.faa.gov/news/rss.xml","name":"FAA News"}'
```

---

## 🔧 Requirements

- **Python 3.8+**
- **pip** (Python package manager)
- **Internet connection** (for fetching RSS feeds)

That's it! No database setup needed - SQLite auto-creates on first run.

---

## 📝 Default Settings

| Setting | Default | Description |
|---------|---------|-------------|
| Port | 5001 | Web server port |
| Database | emails.db | SQLite database file |
| Rate Limit | 30/min | API requests per minute |
| Workers | 10 | Parallel feed fetchers |
| Debug Mode | On | Shows detailed errors |

---

## ⚠️ Security Note

**For local use only** - The default config uses HTTP and debug mode.

For production deployment:
- Set `FLASK_DEBUG=False`
- Use HTTPS reverse proxy (nginx, Cloudflare)
- Change `SECRET_KEY` and `CF_WORKER_TOKEN`
- Review SECURITY.md

---

## 🛠️ Troubleshooting

**Port already in use?**
```bash
# Kill existing process
pkill -f "python.*app.py"
# Or change port in .env
PORT=5002
```

**Import errors?**
```bash
# Reinstall dependencies
pip install --upgrade -r requirements.txt
```

**Database locked?**
```bash
# Close other instances
pkill -f "python.*app.py"
rm emails.db  # Start fresh (deletes all data!)
```

---

**Ready to go!** Just run `python3 app.py` and visit http://localhost:5001
