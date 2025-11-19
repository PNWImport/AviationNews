# Aviation Intelligence Hub - File Structure

Complete reference for all project files and their purposes.

## 🐍 Core Python Application

| File | Purpose |
|------|---------|
| `app.py` | Main Flask application - web server, API endpoints, business logic |
| `config.py` | Configuration management - reads from environment variables |
| `security.py` | Security module - input validation, SSRF protection, URL validation |

## 🌐 Frontend

| File/Directory | Purpose |
|---------------|---------|
| `templates/index.html` | Single-page application UI - HTML, CSS, and JavaScript |

## ☁️ Cloudflare Worker (AI Processing)

| File | Purpose |
|------|---------|
| `worker.js` | Cloudflare Worker for AI-powered summaries using Workers AI |
| `wrangler.toml` | Cloudflare Workers deployment configuration |
| `WORKER_DEPLOY.md` | Complete deployment guide for the Cloudflare Worker |

## 📖 Documentation

| File | Purpose |
|------|---------|
| `README.md` | Project overview, features, and basic setup instructions |
| `QUICKSTART.md` | Quick 3-step guide to run locally |
| `SECURITY.md` | Security features, best practices, vulnerability mitigations |
| `FILES.md` | This file - complete file structure reference |
| `WORKER_DEPLOY.md` | Cloudflare Worker deployment guide |

## 🔧 Configuration

| File | Purpose |
|------|---------|
| `.env.example` | Environment variables template - copy to `.env` and customize |
| `.gitignore` | Git ignore rules - prevents committing secrets and build files |
| `requirements.txt` | Python dependencies for pip install |

## 🧪 Testing & Security

| File | Purpose |
|------|---------|
| `triage_agent_v2.py` | Comprehensive penetration testing tool |
| `test_validation.py` | Standalone input validation test suite |

## 📦 Generated/Runtime Files (Not in Git)

| File/Directory | Purpose |
|---------------|---------|
| `.env` | Your local configuration (NEVER commit!) |
| `emails.db` | SQLite database (auto-created on first run) |
| `__pycache__/` | Python bytecode cache |
| `.wrangler/` | Wrangler CLI cache and build files |
| `node_modules/` | Node.js dependencies (if using Wrangler locally) |

---

## 🗂️ Directory Structure

```
AviationNews/
├── app.py                    # Main Flask application
├── config.py                 # Configuration
├── security.py               # Security utilities
├── worker.js                 # Cloudflare AI Worker
├── wrangler.toml             # Worker deployment config
├── requirements.txt          # Python dependencies
├── .env.example              # Config template
├── .gitignore                # Git ignore rules
│
├── templates/
│   └── index.html            # Single-page frontend
│
├── README.md                 # Project overview
├── QUICKSTART.md             # Quick start guide
├── SECURITY.md               # Security documentation
├── WORKER_DEPLOY.md          # Worker deployment guide
├── FILES.md                  # This file
│
├── triage_agent_v2.py        # Security testing tool
├── test_validation.py        # Validation tests
│
└── (generated at runtime)
    ├── .env                  # Your config (git-ignored)
    ├── emails.db             # SQLite database (git-ignored)
    └── __pycache__/          # Python cache (git-ignored)
```

---

## 🚀 Quick Reference

### Essential Files to Edit

**For local deployment:**
- Copy `.env.example` → `.env`
- Edit `.env` with your settings

**For Cloudflare Worker:**
- Edit `worker.js` if customizing AI behavior
- Edit `wrangler.toml` for worker name/settings
- Follow `WORKER_DEPLOY.md` for deployment

### Files You Should Never Edit

- `requirements.txt` - Only edit if adding new Python dependencies
- `.gitignore` - Already configured for security
- `emails.db` - Database file, don't edit manually

### Files to Review for Security

- `SECURITY.md` - Security features and best practices
- `triage_agent_v2.py` - Run to test security posture
- `security.py` - Core security implementation

---

## 📝 Notes

- All `.md` files are documentation - safe to read, edit, or delete
- Python files (`.py`) contain the application logic
- The worker files (`worker.js`, `wrangler.toml`) are optional - only needed for AI summaries
- SQLite database (`emails.db`) is automatically created on first run

---

**Looking for something?**
- **Quick setup**: See `QUICKSTART.md`
- **Worker deployment**: See `WORKER_DEPLOY.md`
- **Security info**: See `SECURITY.md`
- **Project overview**: See `README.md`
