"""
Aviation Intelligence Hub - Flask Backend (SECURED VERSION)
Security enhancements applied:
1. Input validation and sanitization
2. SSRF protection with URL validation
3. Rate limiting on API endpoints
4. Security headers (CSP, HSTS, etc.)
5. Centralized configuration management
6. Enhanced error handling and logging
7. Removed hardcoded secrets (use environment variables)

Original fixes:
1. Fixed HTML escaping infinite loop
2. Fixed startswith() syntax
3. Improved thread-safe database handling
4. Better error handling in SSE
"""
import os
import re
import io
import csv
import json
import sqlite3
import logging
import time
import queue
import hashlib
import threading
from datetime import datetime, date, timezone, timedelta
from html import unescape, escape as html_escape
from email.utils import parsedate_to_datetime
from difflib import SequenceMatcher
from urllib.parse import urljoin, urlparse
from typing import Dict, Tuple, Optional, List, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from bs4 import BeautifulSoup, Comment
from textblob import TextBlob
from flask import Flask, render_template, request, jsonify, send_file, g, Response, stream_with_context
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_login import LoginManager, current_user
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
import atexit

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

# Import our security and configuration modules
from config import config
from security import URLValidator, InputValidator, SecurityError, get_client_ip

# Import auth modules
from models import init_user_tables, get_user_by_id
from auth import auth_bp
from email_service import email_service

# ---------------- Configuration ----------------
# Validate configuration on startup
try:
    config.validate()
    log_level = getattr(logging, config.LOG_LEVEL, logging.INFO)
    logging.basicConfig(level=log_level, format=config.LOG_FORMAT)
    log = logging.getLogger("aih")
    log.info("Configuration validated successfully")
    log.info(f"Configuration: {config.get_summary()}")
except ValueError as e:
    logging.basicConfig(level=logging.ERROR, format=config.LOG_FORMAT)
    log = logging.getLogger("aih")
    log.error(f"Configuration validation failed: {e}")
    raise

# Initialize URL validator with domain restrictions
url_validator = URLValidator(
    allowed_domains=config.ALLOWED_DOMAINS,
    blocked_domains=config.BLOCKED_DOMAINS
)

# Message queue for SSE
sse_message_queue = queue.Queue(maxsize=config.SSE_QUEUE_MAXSIZE)

# Thread safety lock
state_lock = threading.Lock()

# Initialize Flask app
app = Flask(__name__, template_folder="templates")
app.config['SECRET_KEY'] = config.SECRET_KEY

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'
login_manager.session_protection = 'strong'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'error'

# Initialize email service
email_service.init_app(app)

# Register auth blueprint
app.register_blueprint(auth_bp)

# Initialize rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[config.RATE_LIMIT_DEFAULT] if config.RATE_LIMIT_ENABLED else [],
    storage_uri="memory://",
)

# Initialize security headers (Talisman)
# For local development, we're lenient with CSP
# When deploying to production, tighten these policies
csp = {
    'default-src': ["'self'"],
    'script-src': [
        "'self'",
        "'unsafe-inline'",  # Required for inline scripts
        "https://cdn.jsdelivr.net",
        "https://cdnjs.cloudflare.com",
    ],
    'style-src': [
        "'self'",
        "'unsafe-inline'",  # Required for inline styles
        "https://cdnjs.cloudflare.com",
        "https://fonts.googleapis.com",  # Google Fonts
    ],
    'img-src': ["'self'", "data:", "https:"],
    'font-src': [
        "'self'",
        "https://cdnjs.cloudflare.com",
        "https://fonts.gstatic.com",  # Google Fonts
    ],
    'connect-src': ["'self'"],
}

# Only enable Talisman in production or if explicitly enabled
if not config.DEBUG or os.environ.get("FORCE_HTTPS") == "true":
    Talisman(
        app,
        force_https=False,  # Since we're behind a reverse proxy for local dev
        content_security_policy=csp,
        content_security_policy_nonce_in=['script-src']
    )
    log.info("Security headers (Talisman) enabled")
else:
    log.info("Running in debug mode - security headers disabled for development")

# Add security headers manually for development mode
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    # Only add if not already set by Talisman
    if 'X-Content-Type-Options' not in response.headers:
        response.headers['X-Content-Type-Options'] = 'nosniff'

    if 'X-Frame-Options' not in response.headers:
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'

    if 'X-XSS-Protection' not in response.headers:
        response.headers['X-XSS-Protection'] = '1; mode=block'

    # Add CSP if not present
    if 'Content-Security-Policy' not in response.headers:
        csp_parts = []
        for k, v in csp.items():
            if isinstance(v, list):
                csp_parts.append(f"{k} {' '.join(v)}")
            else:
                csp_parts.append(f"{k} {v}")
        csp_value = "; ".join(csp_parts)
        response.headers['Content-Security-Policy'] = csp_value

    # Note: HSTS only makes sense over HTTPS, skip in local dev
    if not config.DEBUG and 'Strict-Transport-Security' not in response.headers:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

    return response

auto_refresh_enabled = True
auto_refresh_timer = None

# --------------- DB Helpers -------------------
def get_db():
    """Get request-scoped database connection"""
    db = getattr(g, "_db", None)
    if db is None:
        db = sqlite3.connect(config.DATABASE, check_same_thread=False, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        g._db = db
    return db

@app.teardown_appcontext
def close_db(_):
    db = getattr(g, "_db", None)
    if db:
        db.close()

def get_thread_db():
    """Thread-safe database connection for background threads"""
    conn = sqlite3.connect(config.DATABASE, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database tables and indexes"""
    conn = sqlite3.connect(config.DATABASE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            recipient TEXT,
            subject TEXT,
            content TEXT,
            date TEXT,
            url TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS news_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email_id INTEGER,
            airline TEXT,
            content TEXT,
            sentiment REAL,
            sentiment_label TEXT,
            source TEXT,
            date TEXT,
            ai_summary TEXT DEFAULT NULL,
            content_hash TEXT UNIQUE,
            FOREIGN KEY (email_id) REFERENCES emails(id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS feeds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE,
            title TEXT,
            last_fetch TEXT,
            status TEXT,
            error TEXT,
            etag TEXT,
            last_modified TEXT
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_news_date ON news_items(date)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_news_airline ON news_items(airline)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_news_sentiment ON news_items(sentiment_label)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_content_hash ON news_items(content_hash)")
    conn.commit()
    conn.close()

def ensure_ai_summary_column():
    """Add ai_summary and content_hash columns if missing."""
    conn = sqlite3.connect(config.DATABASE)
    cur = conn.cursor()
    cur.execute("PRAGMA table_info(news_items)")
    cols = [r[1] for r in cur.fetchall()]
    if "ai_summary" not in cols:
        log.info("Adding ai_summary column to news_items")
        cur.execute("ALTER TABLE news_items ADD COLUMN ai_summary TEXT DEFAULT NULL")
        conn.commit()
    if "content_hash" not in cols:
        log.info("Adding content_hash column to news_items")
        cur.execute("ALTER TABLE news_items ADD COLUMN content_hash TEXT")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_content_hash ON news_items(content_hash)")
        conn.commit()
    conn.close()

# --------------- Flask-Login User Loader ---------------
@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login"""
    try:
        db = get_db()
        user = get_user_by_id(db, int(user_id))
        return user
    except Exception as e:
        log.error(f"Failed to load user {user_id}: {e}")
        return None

# --------------- User Cleanup Job ---------------
def cleanup_unverified_users():
    """
    Delete unverified users older than 12 hours.
    Runs periodically to prevent database bloat from bot signups.
    """
    try:
        conn = get_thread_db()
        cursor = conn.cursor()

        # Delete unverified users older than 12 hours
        twelve_hours_ago = datetime.now(timezone.utc) - timedelta(hours=12)
        cursor.execute("""
            DELETE FROM users
            WHERE is_verified = 0
            AND created_at < ?
        """, (twelve_hours_ago.isoformat(),))

        deleted_count = cursor.rowcount
        conn.commit()
        conn.close()

        if deleted_count > 0:
            log.info(f"Cleanup job: Deleted {deleted_count} unverified users older than 12 hours")
        else:
            log.debug("Cleanup job: No unverified users to delete")

    except Exception as e:
        log.error(f"Cleanup job failed: {e}")

# Initialize background scheduler for user cleanup
scheduler = BackgroundScheduler()
cleanup_interval = int(os.getenv('EMAIL_CLEANUP_INTERVAL', '3600'))  # Default: 1 hour
scheduler.add_job(
    func=cleanup_unverified_users,
    trigger=IntervalTrigger(seconds=cleanup_interval),
    id='cleanup_unverified_users',
    name='Cleanup unverified users older than 12 hours',
    replace_existing=True
)

# Ensure scheduler shuts down gracefully
atexit.register(lambda: scheduler.shutdown())

# --------------- Auto-Refresh System ---------------
def start_auto_refresh():
    """Start the automatic refresh timer"""
    global auto_refresh_timer, auto_refresh_enabled

    with state_lock:
        if auto_refresh_timer:
            auto_refresh_timer.cancel()

        if auto_refresh_enabled:
            auto_refresh_timer = threading.Timer(config.AUTO_REFRESH_INTERVAL, auto_refresh_feeds_parallel)
            auto_refresh_timer.daemon = True
            auto_refresh_timer.start()
            log.info(f"Auto-refresh scheduled for {config.AUTO_REFRESH_INTERVAL} seconds")

def auto_refresh_feeds_parallel():
    """Automatically refresh all feeds in parallel"""
    global auto_refresh_enabled

    if not auto_refresh_enabled:
        return

    log.info("Auto-refreshing feeds in parallel...")

    try:
        conn = get_thread_db()
        c = conn.cursor()
        c.execute("SELECT id, url, etag, last_modified FROM feeds")
        feeds = c.fetchall()
        conn.close()

        if not feeds:
            log.info("No feeds to auto-refresh")
            return

        results = []
        with ThreadPoolExecutor(max_workers=config.MAX_FEED_WORKERS) as executor:
            futures = [executor.submit(process_single_feed, feed) for feed in feeds]
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    log.exception(f"Feed processing failed: {e}")

        total_new = 0
        errors = 0
        for result in results:
            if result.get("error"):
                errors += 1
            else:
                total_new += result.get("new_items", 0)

        if total_new > 0:
            publish_sse_event("reload_page", json.dumps({"reason": "new_content"}))

        publish_sse_event("toast", json.dumps({"message": f"Auto-refresh complete: {total_new} new items, {errors} errors", "tone": "good"}))

    except Exception as e:
        log.exception(f"Auto-refresh system error: {e}")
    finally:
        start_auto_refresh()

def process_single_feed(feed):
    """Process a single feed for parallel execution"""
    f_id, url, etag, last_mod = feed
    try:
        result = extract_email_content(url, etag=etag, last_modified=last_mod)

        conn = get_thread_db()
        cur = conn.cursor()

        if "ERROR 304" in result.get("content", ""):
            cur.execute("UPDATE feeds SET last_fetch = ?, status = ?, error = NULL WHERE id = ?",
                        (now_iso(), "ok", f_id))
            conn.commit()
            conn.close()
            return {"feed_id": f_id, "new_items": 0}

        cur.execute("INSERT INTO emails (sender, recipient, subject, content, date, url) VALUES (?, ?, ?, ?, ?, ?)",
                    (result["sender"], result["recipient"], result["subject"], result["content"], now_iso(), url))
        email_id = cur.lastrowid

        count = ingest_news_items(cur, email_id, result["news_items"], url)

        cur.execute("UPDATE feeds SET last_fetch = ?, status = ?, error = NULL, etag = ?, last_modified = ? WHERE id = ?",
                    (now_iso(), "ok", result.get("etag"), result.get("last_modified"), f_id))
        conn.commit()
        conn.close()

        return {"feed_id": f_id, "email_id": email_id, "new_items": count, "url": url}

    except Exception as e:
        log.exception(f"Feed {url} failed: {e}")
        try:
            conn = get_thread_db()
            cur = conn.cursor()
            cur.execute("UPDATE feeds SET status = ?, error = ? WHERE id = ?",
                        ("error", str(e)[:500], f_id))
            conn.commit()
            conn.close()
        except Exception:
            pass
        return {"feed_id": f_id, "error": str(e)}

# --------------- Utilities ------------------
def now_iso():
    return datetime.now(timezone.utc).isoformat()

def safe_get(url: str, headers: Dict[str, str] = None, etag: str = None,
             last_modified: str = None) -> Tuple[Optional[requests.Response], Dict[str, str]]:
    """Enhanced safe_get with conditional request support."""
    parsed_url = urlparse(url)
    if parsed_url.query:
        url += f"&_t={int(time.time())}"
    else:
        url += f"?_t={int(time.time())}"

    request_headers = {
        "User-Agent": "Aviation-Intell/2.0",
    }
    if headers:
        request_headers.update(headers)
    if etag:
        request_headers["If-None-Match"] = etag
    if last_modified:
        request_headers["If-Modified-Since"] = last_modified
    try:
        response = requests.get(url, headers=request_headers, timeout=config.REQUEST_TIMEOUT)
        # Fix character encoding issues (â, etc.)
        if response.encoding == 'ISO-8859-1':
            response.encoding = response.apparent_encoding or 'utf-8'
        response_headers = {}
        if "ETag" in response.headers:
            response_headers["etag"] = response.headers["ETag"]
        if "Last-Modified" in response.headers:
            response_headers["last_modified"] = response.headers["Last-Modified"]
        return response, response_headers
    except Exception as e:
        log.warning("safe_get failed for %s: %s", url, e)
        return None, {}

def analyze_sentiment(text: str) -> Tuple[float, str]:
    try:
        p = float(TextBlob(text).sentiment.polarity)
    except Exception:
        p = 0.0
    label = "positive" if p > 0.12 else ("negative" if p < -0.12 else "neutral")
    return p, label

def _strip_html_text(html_fragment: str) -> str:
    """Enhanced HTML stripping."""
    if not html_fragment:
        return ""
    t = unescape(html_fragment)
    soup = BeautifulSoup(t, "html.parser")
    for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
        comment.extract()
    for s in soup(["script", "style", "iframe", "noscript", "head", "meta", "link"]):
        s.decompose()
    for pre in soup.find_all("pre"):
        pre.replace_with(soup.new_string(pre.get_text("\n", strip=True)))
    text = soup.get_text(" ", strip=True)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def _try_parse_pubdate(s: Optional[str]) -> Optional[str]:
    if not s:
        return None
    fmts = [
        lambda s: parsedate_to_datetime(s),
        lambda s: datetime.fromisoformat(s),
        lambda s: datetime.strptime(s, "%Y-%m-%dT%H:%M:%S%z"),
        lambda s: datetime.strptime(s, "%Y-%m-%d %H:%M:%S"),
        lambda s: datetime.strptime(s, "%d %b %Y %H:%M:%S %z"),
        lambda s: datetime.strptime(s, "%a, %d %b %Y %H:%M:%S %z"),
        lambda s: datetime.strptime(s, "%Y-%m-%d"),
    ]
    for f in fmts:
        try:
            dt = f(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except Exception:
            pass
    m = re.search(r'(\d{4})-?(\d{1,2})-?(\d{1,2})', s or "")
    if m:
        y, mo, d = map(int, m.groups())
        return datetime(y, mo, d, tzinfo=timezone.utc).isoformat()
    return None

def _is_likely_ad(title: str, content: str) -> bool:
    ad_markers = [
        "sponsored", "advertisement", "promoted", "partner content",
        "special offer", "discount", "save now", "limited time",
        "sponsored post", "sponsored content", "paid content",
        "affiliate", "promotion", "promo code"
    ]
    combined = (title + " " + content).lower()
    if any(m in combined for m in ad_markers):
        return True
    if re.search(r"\$\d+(\.\d+)?", combined) and re.search(r"discount|offer|save|deal", combined):
        return True
    if len(content) < 150 and re.search(r"click|subscribe|sign up|join|buy now|order now", combined):
        return True
    if content.count('!') > 3:
        return True
    return False

def _deduplicate_items(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    def similarity(a, b): return SequenceMatcher(None, a, b).ratio()
    unique_items, sigs = [], []
    for item in items:
        content = item.get("content", "")
        airline = item.get("airline", "")
        sig = (airline + " " + content[:200]).lower()
        is_dup = False
        for i, ex in enumerate(sigs):
            if similarity(sig, ex) > 0.7:
                is_dup = True
                if len(content) > len(unique_items[i].get("content", "")):
                    sigs[i] = sig
                    unique_items[i] = item
                break
        if not is_dup:
            sigs.append(sig)
            unique_items.append(item)
    return unique_items

def discover_feed_url(html_content: str, base_url: str) -> Optional[str]:
    soup = BeautifulSoup(html_content, "html.parser")
    for link in soup.find_all("link"):
        rel = (link.get("rel") or [""])[0].lower()
        if rel in ["alternate", "feed"] and link.get("type") in [
            "application/rss+xml", "application/atom+xml", "application/xml", "text/xml"
        ]:
            href = link.get("href", "")
            if href:
                # FIXED: Correct syntax for checking multiple prefixes
                if not (href.startswith("http://") or href.startswith("https://")):
                    href = urljoin(base_url, href)
                return href
    for path in ["/feed", "/rss", "/atom", "/feed/", "/rss/", "/atom/", "/rss.xml", "/atom.xml"]:
        feed_url = urljoin(base_url, path)
        resp, _ = safe_get(feed_url)
        if resp and resp.status_code == 200:
            ctype = resp.headers.get("content-type", "").lower()
            if "xml" in ctype or resp.text.strip().startswith("<?xml"):
                return feed_url
    return None

def ingest_news_items(cursor, email_id, news_items, source_url):
    """Helper to ingest news items to DB"""
    count = 0
    for item in news_items:
        content_text = (item.get("content") or "")[:32000]

        content_hash = hashlib.md5((item.get("airline", "") + content_text).encode()).hexdigest()

        cursor.execute("SELECT id FROM news_items WHERE content_hash = ?", (content_hash,))
        if cursor.fetchone():
            continue

        p, label = analyze_sentiment(content_text)
        item_date = (item.get("date") or "") or now_iso()
        cursor.execute("""INSERT INTO news_items
                          (email_id, airline, content, sentiment, sentiment_label, source, date, content_hash)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                       (email_id,
                        (item.get("airline") or "News")[:200],
                        content_text,
                        p,
                        label,
                        (item.get("source") or source_url)[:500],
                        item_date,
                        content_hash))
        count += 1
    return count

# --------------- HTML & RSS extraction -----------
def extract_news_items_from_html(html: str, source_hint: Optional[str] = None) -> List[Dict[str, Any]]:
    soup = BeautifulSoup(html, "html.parser")
    items: List[Dict[str, Any]] = []

    for element in soup.select("footer, .footer, .advertisement, .ad, .sidebar, .comments, .nav, .menu, .social"):
        element.decompose()

    for t in soup.find_all("table"):
        tx = t.get_text(" ", strip=True)
        if len(tx) < 50:
            continue
        strong = t.find(["strong", "b"])
        if strong:
            airline = strong.get_text().strip()
            content = tx.replace(airline, "", 1).strip()
            if len(content) > 20:
                items.append({"airline": airline, "content": content, "source": source_hint})
        else:
            for tr in t.find_all("tr"):
                txt = tr.get_text(" ", strip=True)
                if len(txt) > 40:
                    parts = re.split(r"[:\-–—]{1,2}", txt, maxsplit=1)
                    if len(parts) == 2:
                        items.append({"airline": parts[0].strip(), "content": parts[1].strip(), "source": source_hint})

    for article in soup.find_all("article"):
        title_tag = article.find(["h1", "h2", "h3", "header"])
        content_tag = article.find(["p", "div.content", ".entry-content", ".post-content"])
        if title_tag and content_tag:
            title = title_tag.get_text(" ", strip=True)
            content = content_tag.get_text(" ", strip=True)
            if len(title) > 8 and len(content) > 30:
                items.append({"airline": title, "content": content, "source": source_hint})

    for h in soup.find_all(["h1", "h2", "h3", "h4"]):
        title = h.get_text(" ", strip=True)
        if len(title) < 8:
            continue
        content_parts = []
        nxt = h.find_next_sibling()
        while nxt and nxt.name not in ["h1", "h2", "h3", "h4"]:
            if nxt.name in ["p", "div", "section"]:
                text = nxt.get_text(" ", strip=True)
                if len(text) > 20:
                    content_parts.append(text)
            nxt = nxt.find_next_sibling()
        if content_parts:
            content = " ".join(content_parts)
            if len(content) > 30:
                items.append({"airline": title, "content": content, "source": source_hint})

    for ul in soup.find_all(["ul", "ol"]):
        for li in ul.find_all("li"):
            txt = li.get_text(" ", strip=True)
            if len(txt) > 30:
                parts = re.split(r"[:\-–—]{1,2}", txt, maxsplit=1)
                if len(parts) == 2:
                    items.append({"airline": parts[0].strip(), "content": parts[1].strip(), "source": source_hint})
                else:
                    items.append({"airline": "News", "content": txt, "source": source_hint})

    if not items:
        text = soup.get_text("\n", strip=True)
        for line in text.splitlines():
            line = line.strip()
            if len(line) < 40:
                continue
            m = re.match(r"^(.{2,70}?)\s*[—\-:]{1,2}\s*(.+)$", line)
            if m:
                items.append({"airline": m.group(1).strip(), "content": m.group(2).strip(), "source": source_hint})
            else:
                items.append({"airline": "News", "content": line, "source": source_hint})

    seen = set()
    out = []
    for it in items:
        airline = (it.get("airline") or "Unknown").strip()[:160]
        content = (it.get("content") or "").strip()
        if not content:
            continue
        if _is_likely_ad(airline, content):
            continue
        key = (airline[:80], content[:200])
        if key in seen:
            continue
        seen.add(key)
        out.append({"airline": airline, "content": content, "source": it.get("source") or source_hint or "unknown"})
    return out

def extract_feed_items(xml_text: str, source_hint: Optional[str] = None) -> List[Dict[str, Any]]:
    soup = BeautifulSoup(xml_text, "xml")
    items: List[Dict[str, Any]] = []
    feed_items = soup.find_all("item") or soup.find_all("entry")

    for it in feed_items:
        title_tag = it.find("title")
        link_tag = it.find("link")
        link_href = None
        if link_tag:
            link_href = link_tag.get("href") or link_tag.get_text()

        desc_tag = it.find("description") or it.find("summary")
        content_tag = it.find("content")
        content_enc = it.find("content:encoded")
        pub = it.find("pubDate") or it.find("published") or it.find("updated") or it.find("dc:date")

        airline = _strip_html_text(title_tag.get_text() if title_tag else "") or "News"
        raw_content = content_enc.get_text() if content_enc else (content_tag.get_text() if content_tag else (desc_tag.get_text() if desc_tag else ""))
        content = _strip_html_text(raw_content)

        if len(content) < 40 or _is_likely_ad(airline, content):
            continue

        date_iso = _try_parse_pubdate(pub.get_text() if pub else None)
        source = link_href or source_hint or "feed"

        items.append({
            "airline": airline,
            "content": content,
            "source": source,
            "date": date_iso or now_iso()
        })
    return _deduplicate_items(items)

def extract_email_content(url: str, etag: Optional[str] = None, last_modified: Optional[str] = None) -> Dict[str, Any]:
    """
    Unified fetcher for RSS/Atom and HTML with feed discovery, conditional requests.
    """
    resp, resp_headers = safe_get(url, etag=etag, last_modified=last_modified)
    if not resp:
        return {"sender": "Unknown", "recipient": "Unknown", "subject": "(fetch error: network failed)",
                "content": f"ERROR {url}", "news_items": [], "url": url, "etag": None, "last_modified": None}
    if resp.status_code == 304:
        return {"sender": "feed", "recipient": "feed", "subject": "Not Modified",
                "content": "ERROR 304", "news_items": [], "url": url,
                "etag": resp_headers.get("etag"), "last_modified": resp_headers.get("last_modified")}

    html = resp.text
    ctype = (resp.headers.get("content-type") or "").lower()
    is_feed_xml = html.lstrip().startswith("<?xml") or "<rss" in html[:4000].lower() or "<feed" in html[:4000].lower()
    is_feeD_ct = any(x in ctype for x in ["application/rss+xml", "application/atom+xml", "application/xml", "text/xml"])

    if is_feed_xml or is_feeD_ct or "/feed" in url or "/rss" in url:
        try:
            feed_items = extract_feed_items(html, source_hint=url)
            feed_soup = BeautifulSoup(html, "xml")
            feed_title_tag = feed_soup.find("title") or (feed_soup.find("channel").find("title") if feed_soup.find("channel") else None)
            feed_title = feed_title_tag.get_text() if feed_title_tag else "Feed"
            feed_desc_tag = feed_soup.find("description") or feed_soup.find("subtitle")
            feed_desc = f": {feed_desc_tag.get_text()}" if feed_desc_tag else ""
            return {
                "sender": feed_title,
                "recipient": "feed",
                "subject": f"{feed_title}{feed_desc}",
                "content": html,
                "news_items": feed_items,
                "url": url,
                "etag": resp_headers.get("etag"),
                "last_modified": resp_headers.get("last_modified")
            }
        except Exception as e:
            log.warning("feed parsing failed, falling back to HTML for %s: %s", url, e)

    soup = BeautifulSoup(html, "html.parser")
    sender, recipient, subject = "Unknown", "Unknown", None

    feed_url = discover_feed_url(html, url)
    if feed_url and feed_url != url:
        resp2, resp2_headers = safe_get(feed_url)
        if resp2 and resp2.status_code == 200:
            items = extract_feed_items(resp2.text, source_hint=feed_url)
            soup2 = BeautifulSoup(resp2.text, "xml")
            feed_title_tag = soup2.find("title") or (soup2.find("channel").find("title") if soup2.find("channel") else None)
            feed_title = feed_title_tag.get_text() if feed_title_tag else "Feed"
            feed_desc_tag = soup2.find("description") or soup2.find("subtitle")
            feed_desc = f": {feed_desc_tag.get_text()}" if feed_desc_tag else ""
            return {
                "sender": feed_title,
                "recipient": "feed",
                "subject": f"{feed_title}{feed_desc}",
                "content": resp2.text,
                "news_items": items,
                "url": feed_url,
                "etag": resp2_headers.get("etag"),
                "last_modified": resp2_headers.get("last_modified")
            }

    title_tag = soup.find("title")
    if title_tag and not subject:
        subject = title_tag.get_text(" ", strip=True)
    h = soup.find(["h1", "h2"])
    if h and not subject:
        subject = h.get_text(" ", strip=True)

    text = soup.get_text("\n", strip=True)
    for line in text.splitlines():
        low = line.lower()
        if low.startswith("from:") and sender == "Unknown":
            sender = line.split(":", 1)[1].strip()
        if low.startswith("to:") and recipient == "Unknown":
            recipient = line.split(":", 1)[1].strip()
        if low.startswith("subject:") and not subject:
            subject = line.split(":", 1)[1].strip()

    if sender == "Unknown":
        domain = urlparse(url).netloc
        if domain:
            sender = domain.replace("www.", "")

    news_items = extract_news_items_from_html(html, source_hint=url)
    return {
        "sender": sender,
        "recipient": recipient,
        "subject": subject or "No subject",
        "content": html,
        "news_items": news_items,
        "url": url,
        "etag": resp_headers.get("etag"),
        "last_modified": resp_headers.get("last_modified")
    }

# --------------- SSE Helper Functions -----------
def _format_sse(event_type: str, data: str) -> str:
    return f"event: {event_type}\ndata: {data}\n\n"

def publish_sse_event(event_type: str, data: Any):
    """Queue JSON or HTML payload for SSE."""
    try:
        if sse_message_queue.full():
            try:
                sse_message_queue.get_nowait()
            except Exception:
                pass
        sse_message_queue.put_nowait({"event_type": event_type, "data": data})
    except Exception as e:
        log.error(f"Failed to publish SSE event: {e}")

def _escape_html(s: Optional[str]) -> str:
    """FIXED: Use html.escape() instead of manual replacement to avoid infinite loop"""
    if not s:
        return ""
    return html_escape(str(s))

def make_toast_html(message: str, tone: str = "info", onclick: Optional[str] = None) -> str:
    """Build HTMX OOB toast HTML."""
    cls_click = " clickable" if onclick else ""
    onclick_attr = f' onclick="{onclick}"' if onclick else ""
    return (
        '<div id="toasts" hx-swap-oob="beforeend">'
        f'  <div class="toast {tone}{cls_click}"{onclick_attr}>' 
        '    <div class="icon"><i class="fa-solid fa-bell"></i></div>'
        f'    <div style="flex:1">{_escape_html(message)}</div>'
        '  </div>'
        '</div>'
    )

def _parse_ai_summary(ai_json_str: str) -> Dict[str, Any]:
    try:
        obj = json.loads(ai_json_str)
        if isinstance(obj, dict):
            return obj
        if isinstance(obj, list) and obj:
            return {"summary": str(obj[0]), "key_points": [str(x) for x in obj]}
    except Exception:
        pass
    return {"summary": str(ai_json_str)}

def _build_summary_html(nid: int, ai: Dict[str, Any]) -> str:
    headline = _escape_html((ai.get("headline") or "")[:160])
    summary  = _escape_html((ai.get("summary") or "")[:4000])
    kps      = ai.get("key_points") if isinstance(ai.get("key_points"), list) else []
    ents     = ai.get("entities") if isinstance(ai.get("entities"), dict) else {}

    def chips(name):
        arr = ents.get(name) if isinstance(ents.get(name), list) else []
        items = [f'<span class="chip">{_escape_html(str(v)[:80])}</span>' for v in arr[:12]]
        return "".join(items)

    kp_html = ""
    if kps:
        lis = "".join(f"<li>{_escape_html(str(x)[:400])}</li>" for x in kps[:10])
        kp_html = f"<ul class='ai-kp'>{lis}</ul>"

    chips_html = "".join([
        f"<div class='chips-row'><label>Airlines</label>{chips('airlines')}</div>",
        f"<div class='chips-row'><label>Aircraft</label>{chips('aircraft')}</div>",
        f"<div class='chips-row'><label>Locations</label>{chips('locations')}</div>",
    ])
    ents_html = f"<div class='ai-entities'>{chips_html}</div>" if chips_html else ""

    title_html = f"<div class='ai-headline'>{headline}</div>" if headline else ""
    body_html  = f"<div class='ai-summary-text'>{summary}</div>" if summary else ""
    block = (
        f"<div id='ai-summary-{nid}' hx-swap-oob='innerHTML' class='ai-summary'>"
        f"{title_html}{body_html}{kp_html}{ents_html}"
        f"</div>"
    )
    return block

# ================= Routes ====================
@app.route("/")
def index():
    return render_template("index.html")

def _truthy(v) -> bool:
    if v is None:
        return False
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    return s in ("1", "true", "yes", "on", "y")

@app.route("/api/ingest", methods=["POST"])
@limiter.limit("30 per minute")  # Rate limit to prevent abuse
def api_ingest():
    """
    Ingest URL, optionally add discovered feed.
    Validates URL for security before processing.
    """
    try:
        data = request.get_json(silent=True) or {}

        # Strict validation: enforce type checking and length limits
        try:
            url = InputValidator.validate_string(
                data.get("url"),
                max_length=2048,
                strict=True
            )
        except ValueError as e:
            log.warning(f"Input validation failed: {e}")
            return jsonify({"error": f"Invalid input: {str(e)}"}), 400

        auto_add = _truthy(data.get("auto_add_feed") or request.args.get("auto_add_feed"))

        if not url:
            return jsonify({"error": "URL is required"}), 400

        # Validate URL for security (SSRF protection)
        try:
            url = url_validator.validate_url(url)
        except SecurityError as e:
            log.warning(f"URL validation failed for {url}: {e}")
            return jsonify({"error": f"Invalid URL: {str(e)}"}), 400
    except Exception as e:
        log.error(f"Error parsing ingest request: {e}")
        return jsonify({"error": "Invalid request"}), 400

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT id, etag, last_modified FROM feeds WHERE url = ?", (url,))
    feed_row = cur.fetchone()
    etag = feed_row["etag"] if feed_row else None
    last_modified = feed_row["last_modified"] if feed_row else None

    result = extract_email_content(url, etag=etag, last_modified=last_modified)

    if result.get("content") == "ERROR 304":
        if feed_row:
            cur.execute("UPDATE feeds SET last_fetch=?, status=?, error=NULL WHERE id=?",
                        (now_iso(), "ok", feed_row["id"]))
            conn.commit()
        return jsonify({"id": feed_row["id"] if feed_row else None, "status": "not_modified", "news_items_count": 0})

    cur.execute(
        "INSERT INTO emails (sender, recipient, subject, content, date, url) VALUES (?, ?, ?, ?, ?, ?)",
        (result["sender"], result["recipient"], result["subject"], result["content"], now_iso(), result["url"])
    )
    email_id = cur.lastrowid

    feed_id = None
    if auto_add:
        cur.execute("SELECT id FROM feeds WHERE url = ?", (result["url"],))
        row = cur.fetchone()
        if row:
            feed_id = row["id"]
            cur.execute(
                "UPDATE feeds SET title=?, last_fetch=?, status=?, error=NULL, etag=?, last_modified=? WHERE id=?",
                (result["subject"], now_iso(), "ok", result.get("etag"), result.get("last_modified"), feed_id)
            )
        else:
            cur.execute(
                "INSERT INTO feeds (url, title, last_fetch, status, error, etag, last_modified) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (result["url"], result["subject"], now_iso(), "ok", None, result.get("etag"), result.get("last_modified"))
            )
            feed_id = cur.lastrowid
        publish_sse_event("toast", json.dumps({"message": f"Feed added: {result['url']}", "tone": "good"}))

    count = ingest_news_items(cur, email_id, result["news_items"], result["url"])

    conn.commit()

    if count > 0:
        publish_sse_event("reload_page", json.dumps({"reason": "new_content"}))

    publish_sse_event("ingest_complete", {
        "type": "ingest_complete",
        "email_id": email_id,
        "news_items_count": count,
        "url": result["url"],
        "feed_id": feed_id,
        "auto_added": bool(auto_add)
    })

    return jsonify({"id": email_id, "status": "ok", "news_items_count": count, "feed_id": feed_id, "auto_added": bool(auto_add)})

@app.route("/api/feeds", methods=["GET"])
def api_feeds():
    db = get_db()
    c = db.cursor()
    c.execute("SELECT id, url, title, last_fetch, status, error FROM feeds ORDER BY title")
    feeds = [dict(r) for r in c.fetchall()]
    return jsonify({"feeds": feeds})

@app.route("/api/feeds/auto-refresh", methods=["POST"])
def api_feeds_auto_refresh():
    global auto_refresh_enabled

    data = request.get_json(silent=True) or {}
    enabled = _truthy(data.get("enabled", True))

    with state_lock:
        auto_refresh_enabled = enabled

        if enabled:
            start_auto_refresh()
            publish_sse_event("toast", json.dumps({"message": "Auto-refresh enabled", "tone": "good"}))
        else:
            if auto_refresh_timer:
                auto_refresh_timer.cancel()
            publish_sse_event("toast", json.dumps({"message": "Auto-refresh disabled", "tone": "info"}))

    return jsonify({"status": "ok", "auto_refresh_enabled": auto_refresh_enabled})

@app.route("/api/feeds/add", methods=["POST"])
@limiter.limit("20 per minute")
def api_feeds_add():
    """Add a new feed with URL validation"""
    try:
        data = request.get_json(silent=True) or {}
        url = InputValidator.validate_string(data.get("url"), max_length=2048)

        if not url:
            return jsonify({"error": "URL is required"}), 400

        # Validate URL for security
        try:
            url = url_validator.validate_url(url)
        except SecurityError as e:
            log.warning(f"URL validation failed: {e}")
            return jsonify({"error": f"Invalid URL: {str(e)}"}), 400
    except Exception as e:
        log.error(f"Error parsing feed add request: {e}")
        return jsonify({"error": "Invalid request"}), 400

    res = extract_email_content(url)
    if not res or not res.get("url"):
        return jsonify({"error": "fetch failed"}), 502

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM feeds WHERE url = ?", (res["url"],))
    row = cur.fetchone()
    if row:
        fid = row["id"]
        cur.execute(
            "UPDATE feeds SET title=?, last_fetch=?, status=?, error=NULL, etag=?, last_modified=? WHERE id=?",
            (res["subject"], now_iso(), "ok", res.get("etag"), res.get("last_modified"), fid)
        )
    else:
        cur.execute(
            "INSERT INTO feeds (url, title, last_fetch, status, error, etag, last_modified) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (res["url"], res["subject"], now_iso(), "ok", None, res.get("etag"), res.get("last_modified"))
        )
        fid = cur.lastrowid

    conn.commit()
    publish_sse_event("toast", json.dumps({"message": "Feed added", "tone": "good"}))
    return jsonify({"status": "ok", "feed_id": fid, "url": res["url"], "title": res["subject"]})

@app.route("/api/feeds/<int:feed_id>", methods=["DELETE"])
def api_delete_feed(feed_id: int):
    db = get_db()
    c = db.cursor()
    c.execute("DELETE FROM feeds WHERE id = ?", (feed_id,))
    db.commit()
    publish_sse_event("toast", json.dumps({"message": f"Feed removed: #{feed_id}", "tone": "info"}))
    return jsonify({"status": "ok"})

@app.route("/api/feeds/refresh", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def api_refresh_feeds():
    feed_id = request.args.get("id")
    url_param = request.args.get("url")

    db = get_db()
    c = db.cursor()

    if feed_id:
        c.execute("SELECT id, url, etag, last_modified FROM feeds WHERE id = ?", (feed_id,))
    elif url_param:
        c.execute("SELECT id, url, etag, last_modified FROM feeds WHERE url = ?", (url_param,))
    else:
        c.execute("SELECT id, url, etag, last_modified FROM feeds")
    feeds = c.fetchall()

    if not feeds:
        return jsonify({"error": "no feeds found"}), 404

    def refresh_feeds_parallel_thread():
        results = []
        with ThreadPoolExecutor(max_workers=config.MAX_FEED_WORKERS) as executor:
            futures = [executor.submit(process_single_feed, feed) for feed in feeds]
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                    if result.get("new_items", 0) > 0:
                        publish_sse_event("toast", json.dumps({"message": f"New items from {result.get('url', 'feed')}", "tone": "good"}))
                        publish_sse_event("feed_refreshed", {
                            "type": "feed_refreshed",
                            "feed_id": result["feed_id"],
                            "email_id": result.get("email_id"),
                            "count": result["new_items"],
                            "url": result.get("url")
                        })
                except Exception as e:
                    log.exception(f"Feed processing exception: {e}")

        total_new = sum(r.get("new_items", 0) for r in results)
        errors = len([r for r in results if r.get("error")])
        if total_new > 0:
            publish_sse_event("reload_page", json.dumps({"reason": "new_content"}))
        publish_sse_event("toast", json.dumps({"message": f"Refresh complete: {total_new} new items, {errors} errors", "tone": "good"}))
        publish_sse_event("reload_page", json.dumps({"reason": "feed_refresh_complete"}))

    threading.Thread(target=refresh_feeds_parallel_thread, daemon=True).start()

    return jsonify({
        "status": "refreshing",
        "feeds_count": len(feeds),
        "message": "Feeds refresh started in background."
    })

@app.route("/api/emails")
@limiter.limit("60 per minute")
def api_emails():
    """Get news items with pagination and filtering"""
    # Validate and sanitize inputs
    filt = InputValidator.validate_sentiment_filter(request.args.get("filter", "all"))
    search = InputValidator.validate_string(request.args.get("search"), max_length=200)
    page = InputValidator.validate_integer(request.args.get("page"), min_val=1, default=1)
    per_page = InputValidator.validate_integer(request.args.get("per_page"), min_val=1, max_val=500, default=50)
    off = (page - 1) * per_page

    db = get_db()
    c = db.cursor()
    where, params = [], []
    if search:
        where.append("(n.airline LIKE ? OR n.content LIKE ? OR e.subject LIKE ?)")
        s = f"%{search}%"
        params += [s, s, s]
    if filt != "all":
        where.append("n.sentiment_label = ?")
        params.append(filt)
    wc = (" WHERE " + " AND ".join(where)) if where else ""
    c.execute(f"SELECT COUNT(*) FROM news_items n LEFT JOIN emails e ON n.email_id=e.id {wc}", params)
    total = c.fetchone()[0] or 0

    c.execute(f"""SELECT n.id, n.email_id, n.airline, n.content, n.sentiment, n.sentiment_label, n.source, n.date, n.ai_summary,
                         e.subject as email_subject
                  FROM news_items n LEFT JOIN emails e ON n.email_id=e.id
                  {wc} ORDER BY n.date DESC LIMIT ? OFFSET ?""", params + [per_page, off])
    rows = [dict(r) for r in c.fetchall()]
    return jsonify({"news_items": rows, "page": page, "per_page": per_page, "total_count": total, "total_pages": (total + per_page - 1) // per_page})

@app.route("/api/news/<int:nid>")
def api_news(nid: int):
    db = get_db()
    c = db.cursor()
    c.execute("SELECT id, email_id, airline, content, sentiment, sentiment_label, source, date, ai_summary FROM news_items WHERE id=?", (nid,))
    r = c.fetchone()
    if not r:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(r))

@app.route("/api/stats")
def api_stats():
    db = get_db()
    c = db.cursor()
    c.execute("SELECT COUNT(*) FROM news_items")
    total = c.fetchone()[0] or 0
    c.execute("SELECT sentiment_label, COUNT(*) FROM news_items GROUP BY sentiment_label")
    counts = {"positive": 0, "neutral": 0, "negative": 0}
    for lab, cnt in c.fetchall():
        counts[lab] = cnt

    now = datetime.now(timezone.utc)
    week_ago = (now - timedelta(days=7)).isoformat()
    two_weeks_ago = (now - timedelta(days=14)).isoformat()

    c.execute("SELECT sentiment_label, COUNT(*) FROM news_items WHERE date >= ? GROUP BY sentiment_label", (week_ago,))
    recent = {"positive": 0, "neutral": 0, "negative": 0}
    for lab, cnt in c.fetchall():
        recent[lab] = cnt

    c.execute("SELECT sentiment_label, COUNT(*) FROM news_items WHERE date >= ? AND date < ? GROUP BY sentiment_label", (two_weeks_ago, week_ago))
    prev = {"positive": 0, "neutral": 0, "negative": 0}
    for lab, cnt in c.fetchall():
        prev[lab] = cnt

    return jsonify({
        "total": total,
        "positive": counts["positive"],
        "neutral": counts["neutral"],
        "negative": counts["negative"],
        "recent": recent,
        "previous": prev
    })

@app.route("/api/export")
def api_export():
    fmt = request.args.get("format", "csv")
    filt = request.args.get("filter", "all")
    single = request.args.get("single")
    include_summary = request.args.get("include_summary", "1") == "1"

    db = get_db()
    c = db.cursor()
    if single:
        c.execute("SELECT airline, content, ai_summary, sentiment_label, date FROM news_items WHERE id=?", (single,))
    else:
        if filt == "all":
            c.execute("SELECT airline, content, ai_summary, sentiment_label, date FROM news_items ORDER BY date DESC")
        else:
            c.execute("SELECT airline, content, ai_summary, sentiment_label, date FROM news_items WHERE sentiment_label=? ORDER BY date DESC", (filt,))
    rows = c.fetchall()

    out = io.StringIO()
    w = csv.writer(out)

    if include_summary:
        w.writerow(["Airline", "Content", "AI Summary", "Sentiment", "Date"])
        for r in rows:
            ai_summary = r[2]
            summary_text = ""
            if ai_summary:
                try:
                    summary_json = json.loads(ai_summary)
                    summary_text = summary_json.get("summary", "") if isinstance(summary_json, dict) else str(summary_json)
                except Exception:
                    summary_text = ai_summary
            w.writerow([r[0], r[1], summary_text, r[3], r[4]])
    else:
        w.writerow(["Airline", "Content", "Sentiment", "Date"])
        for r in rows:
            w.writerow([r[0], r[1], r[3], r[4]])

    out.seek(0)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return send_file(
        io.BytesIO(out.getvalue().encode("utf-8")),
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"aviation_news_export_{timestamp}.csv"
    )

def _normalize_item(it: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": str(it.get("id")),
        "airline": (it.get("airline") or "")[:160],
        "content": (it.get("content") or "")[:config.MAX_CONTENT_CHARS_TO_WORKER],
        "source": (it.get("source") or "")[:300],
        "date": (it.get("date") or "") or ""
    }

# Create a requests session for connection pooling (reuse connections)
worker_session = requests.Session()
worker_session.headers.update({
    "Authorization": f"Bearer {config.CF_WORKER_TOKEN}",
    "Content-Type": "application/json",
})

def _call_worker(items: List[Dict[str, Any]], batch_num: int = 0) -> Dict[str, Any]:
    """Call worker with a batch of items. Uses session for connection pooling."""
    body = {"items": items}
    try:
        log.info(f"Sending batch {batch_num} with {len(items)} items to worker")
        r = worker_session.post(config.CF_WORKER_URL, json=body, timeout=config.WORKER_TIMEOUT)
        log.info(f"Batch {batch_num} completed in {r.elapsed.total_seconds():.2f}s")
    except Exception as e:
        log.exception(f"Worker request exception for batch {batch_num}")
        return {"error": f"worker request failed: {str(e)}", "batch": batch_num}

    try:
        data = r.json()
    except Exception:
        data = {"error": f"invalid JSON from worker (status {r.status_code})", "raw": r.text[:1000], "batch": batch_num}

    if r.status_code != 200 and "error" not in data:
        data["error"] = f"worker status {r.status_code}"
        data["batch"] = batch_num
    return data

@app.route("/api/ai/summarize", methods=["POST"])
@limiter.limit("10 per minute")
def api_ai_summarize():
    """Generate AI summaries for news items"""
    if not config.CF_WORKER_URL or not config.CF_WORKER_TOKEN:
        return jsonify({"error": "Cloudflare worker not configured"}), 500

    db = get_db()
    cur = db.cursor()
    payload = request.get_json(silent=True) or {}

    items: List[Dict[str, Any]] = []
    if isinstance(payload.get("items"), list) and payload["items"]:
        items = payload["items"]
    elif isinstance(payload.get("ids"), list) and payload["ids"]:
        ids = [int(x) for x in payload["ids"]][:500]
        q = f"SELECT id, airline, content, source, date, ai_summary FROM news_items WHERE id IN ({','.join(['?']*len(ids))})"
        cur.execute(q, ids)
        rows = [dict(r) for r in cur.fetchall()]
        items = rows
    else:
        limit = max(1, min(200, int(request.args.get("limit", "50"))))
        page = max(1, int(request.args.get("page", "1")))
        offset = (page - 1) * limit
        cur.execute("""
            SELECT id, airline, content, source, date, ai_summary
              FROM news_items
          ORDER BY date DESC
             LIMIT ? OFFSET ?
        """, (limit, offset))
        items = [dict(r) for r in cur.fetchall()]

    if not items:
        return jsonify({"ok": True, "updated": 0, "summaries": {}, "overall_summary": "", "sentiment": {"label": "neutral", "score": 0}})

    items_for_worker = []
    id_map_original = {}
    for it in items:
        norm = _normalize_item(it)
        id_map_original[norm["id"]] = it
        items_for_worker.append(norm)

    def _emit_summary_events(nid: int, ai_json_str: str, snippet: str):
        publish_sse_event("summary_updated", json.dumps({
            "type": "summary_updated",
            "id": nid,
            "ai_summary": ai_json_str,
            "snippet": snippet
        }))
        try:
            parsed = _parse_ai_summary(ai_json_str)
        except Exception:
            parsed = {"summary": snippet}
        html_block = _build_summary_html(nid, parsed)
        publish_sse_event("summary_oob", html_block)

    def process_summaries():
        batches = [items_for_worker[i:i + config.WORKER_BATCH_SIZE] for i in range(0, len(items_for_worker), config.WORKER_BATCH_SIZE)]
        all_summaries: Dict[str, Any] = {}
        overall_parts: List[str] = []
        coarse_sent = {"label": "neutral", "score": 0.0}
        worker_errors: List[str] = []

        log.info(f"Processing {len(batches)} batches ({len(items_for_worker)} items total) in parallel (max {config.WORKER_PARALLEL_BATCHES} concurrent)")

        # Process batches in parallel using ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=config.WORKER_PARALLEL_BATCHES) as executor:
            # Submit all batches to the executor
            future_to_batch = {executor.submit(_call_worker, batch, i): i for i, batch in enumerate(batches)}

            # Process results as they complete (not in order, but faster!)
            for future in as_completed(future_to_batch):
                batch_num = future_to_batch[future]
                try:
                    resp = future.result()
                    if not isinstance(resp, dict):
                        worker_errors.append(f"Batch {batch_num}: invalid worker response")
                        continue
                    if resp.get("error"):
                        worker_errors.append(f"Batch {batch_num}: {str(resp.get('error'))}")
                        continue

                    # Process successful response
                    summaries = resp.get("summaries") or {}
                    if isinstance(summaries, dict):
                        all_summaries.update({str(k): v for k, v in summaries.items()})
                    if resp.get("overall_summary"):
                        overall_parts.append(str(resp["overall_summary"]))
                    s = resp.get("sentiment")
                    if isinstance(s, dict):
                        try:
                            coarse_sent["label"] = s.get("label", coarse_sent["label"]) or coarse_sent["label"]
                            coarse_sent["score"] = (coarse_sent.get("score", 0.0) + float(s.get("score", 0.0))) / 2.0
                        except Exception:
                            pass

                    log.info(f"Batch {batch_num} processed successfully: {len(summaries)} summaries")
                except Exception as e:
                    log.exception(f"Batch {batch_num} failed with exception: {e}")
                    worker_errors.append(f"Batch {batch_num}: {str(e)}")

        updated = 0
        conn = get_thread_db()
        conn_cur = conn.cursor()

        toast_count = 0

        for sid, summ in all_summaries.items():
            try:
                nid = int(sid)
            except Exception:
                continue

            orig_row = id_map_original.get(str(nid), {})
            existing_ai = orig_row.get("ai_summary")

            try:
                if isinstance(summ, (dict, list)):
                    ai_json_str = json.dumps(summ, ensure_ascii=False)
                else:
                    ai_json_str = json.dumps({"summary": str(summ)}, ensure_ascii=False)
            except Exception:
                ai_json_str = json.dumps({"summary": str(summ)}, ensure_ascii=False)

            short_snip = ""
            try:
                parsed = json.loads(ai_json_str)
                if isinstance(parsed, dict):
                    short_snip = parsed.get("summary") or parsed.get("headline") or parsed.get("takeaway") or ""
                elif isinstance(parsed, list) and parsed:
                    short_snip = str(parsed[0])
                if short_snip:
                    short_snip = short_snip.strip()
                    if len(short_snip) > 400:
                        short_snip = short_snip[:400].rsplit(".", 1)[0] + "…"
            except Exception:
                short_snip = str(summ)[:400]

            try:
                do_update = True
                if existing_ai:
                    try:
                        if json.loads(existing_ai) == json.loads(ai_json_str):
                            do_update = False
                    except Exception:
                        if existing_ai == ai_json_str:
                            do_update = False

                if short_snip.strip().lower() == (orig_row.get("airline") or "").strip().lower():
                    do_update = False

                if do_update:
                    conn_cur.execute("UPDATE news_items SET ai_summary = ? WHERE id = ?", (ai_json_str, nid))
                else:
                    if not existing_ai:
                        conn_cur.execute("UPDATE news_items SET ai_summary = ? WHERE id = ?", (ai_json_str, nid))

                updated += 1

                _emit_summary_events(nid, ai_json_str, short_snip)

                if toast_count < config.MAX_ITEM_TOASTS:
                    msg = f"AI summary ready for item #{nid}"
                    publish_sse_event("toast", json.dumps({"message": msg, "tone": "info"}))
                    toast_count += 1

            except Exception as e:
                log.exception("db update failed for id %s: %s", nid, e)
                worker_errors.append(f"db update failed for id {nid}: {str(e)}")

        conn.commit()
        conn.close()

        publish_sse_event("toast", json.dumps({"message": f"Batch complete: {updated} items updated", "tone": "good"}))
        publish_sse_event("summary_batch_complete", json.dumps({
            "type": "summary_batch_complete",
            "updated": updated,
            "total_processed": len(all_summaries),
            "overall": " | ".join(overall_parts)[:2000],
            "sentiment": coarse_sent
        }))
        if updated > 0:
            publish_sse_event("reload_page", json.dumps({"reason": "ai_summary_updated"}))

        if worker_errors:
            publish_sse_event("toast", json.dumps({"message": f"Worker issues: {worker_errors[0]}", "tone": "bad"}))

    threading.Thread(target=process_summaries, daemon=True).start()

    return jsonify({
        "ok": True,
        "status": "processing",
        "message": "Processing items in background. Updates will be sent via SSE."
    })

@app.route("/api/ai/updates")
def api_ai_updates():
    def generate():
        yield "retry: 10000\n\n"
        yield _format_sse("connected", json.dumps({"status": "connected"}))
        while True:
            try:
                message = sse_message_queue.get(timeout=30)
                data = message["data"]
                if isinstance(data, (dict, list)):
                    payload = json.dumps(data)
                else:
                    payload = str(data)
                yield _format_sse(message["event_type"], payload)
            except queue.Empty:
                yield _format_sse("heartbeat", json.dumps({"timestamp": now_iso()}))
            except Exception as e:
                log.error(f"SSE error: {e}")
                yield _format_sse("error", json.dumps({"error": str(e)}))
                time.sleep(1)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )

if __name__ == "__main__":
    init_db()
    ensure_ai_summary_column()

    # Initialize user authentication tables
    with app.app_context():
        db = get_db()
        init_user_tables(db)
        log.info("User authentication tables initialized")

    # Start background jobs
    start_auto_refresh()
    scheduler.start()
    log.info(f"Background cleanup job started (runs every {cleanup_interval} seconds)")

    log.info(f"Starting Aviation Intelligence Hub on {config.HOST}:{config.PORT}")
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG, threaded=True)