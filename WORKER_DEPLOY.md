# Cloudflare Worker Deployment Guide

This guide explains how to deploy the AI worker for Aviation Intelligence Hub to Cloudflare Workers.

## 📋 Prerequisites

- **Cloudflare account** (free tier works!)
- **Node.js 16+** and npm installed
- **Wrangler CLI** - Cloudflare's deployment tool

## 🚀 Quick Deploy (3 Steps)

### 1. Install Wrangler

```bash
npm install -g wrangler
```

### 2. Login to Cloudflare

```bash
wrangler login
```

This will open a browser window to authenticate with your Cloudflare account.

### 3. Deploy the Worker

```bash
# Set your authentication token (required!)
wrangler secret put CF_WORKER_TOKEN
# When prompted, enter a secure random token:
# Example: python -c "import secrets; print(secrets.token_urlsafe(32))"

# Deploy to Cloudflare
wrangler deploy
```

**Done!** Wrangler will output your worker URL:
```
Published aviation-intelligence-hub-ai (X.XX sec)
  https://aviation-intelligence-hub-ai.your-username.workers.dev
```

---

## 🔧 Configure Your App

After deployment, update your `.env` file:

```bash
# Copy the worker URL from the deploy output
CF_WORKER_URL=https://aviation-intelligence-hub-ai.your-username.workers.dev

# Use the same token you set with wrangler secret put
CF_WORKER_TOKEN=your-secure-token-here
```

Restart your Flask app:
```bash
python3 app.py
```

---

## ✅ Test the Worker

### Test directly with curl:

```bash
# Set your values
WORKER_URL="https://your-worker.workers.dev"
WORKER_TOKEN="your-token"

# Test the worker
curl -X POST "$WORKER_URL" \
  -H "Authorization: Bearer $WORKER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "items": [
      {
        "id": 1,
        "airline": "FAA",
        "content": "The Federal Aviation Administration issued new safety guidelines for aircraft maintenance procedures.",
        "source": "faa.gov",
        "date": "2024-01-15"
      }
    ]
  }'
```

**Expected Response:**
```json
{
  "summaries": {
    "1": {
      "summary": "FAA has issued new safety guidelines...",
      "source": "FAA",
      "analyzed_at": "2024-01-15T12:00:00Z"
    }
  },
  "overall_summary": "Processed 1 aviation news items...",
  "sentiment": {
    "label": "neutral",
    "score": 0.0
  }
}
```

### Test from the UI:

1. Open your app: http://localhost:5001
2. Add some RSS feeds (or use existing news)
3. Click **"Generate AI Summaries"** button
4. Watch the summaries appear in real-time!

---

## 🤖 About Cloudflare AI

This worker uses **Cloudflare Workers AI** for text generation:

- **Model**: Llama 3.1 8B Instruct
- **Cost**: First 10,000 neurons/day are FREE
- **Speed**: ~1-2 seconds per summary
- **Fallback**: Basic extraction if AI is unavailable

### Enable Workers AI (Required for AI Summaries)

1. Go to https://dash.cloudflare.com/
2. Navigate to **Workers & Pages** → **AI**
3. Enable **Workers AI** (free tier available)
4. Re-deploy: `wrangler deploy`

**Without Workers AI**: The worker will still work but use basic text extraction instead of AI.

---

## 🔒 Security Notes

### Authentication

The worker requires a Bearer token for all requests:

```javascript
Authorization: Bearer YOUR_CF_WORKER_TOKEN
```

**IMPORTANT**:
- Never commit `CF_WORKER_TOKEN` to git
- Use `wrangler secret put` to set tokens securely
- Rotate tokens if compromised

### CORS

The worker allows cross-origin requests from any domain (`Access-Control-Allow-Origin: *`).

**For production**: Restrict to your domain only:

```javascript
// In worker.js, change:
'Access-Control-Allow-Origin': '*',
// To:
'Access-Control-Allow-Origin': 'https://your-domain.com',
```

---

## 📊 Monitoring & Logs

### View Logs:

```bash
wrangler tail
```

This streams real-time logs from your worker.

### View Analytics:

1. Go to https://dash.cloudflare.com/
2. **Workers & Pages** → Select your worker
3. View metrics: requests, errors, CPU time

---

## 🛠️ Development & Testing

### Run worker locally:

```bash
wrangler dev
```

This starts a local server at http://localhost:8787

### Test against local worker:

Update `.env` temporarily:
```bash
CF_WORKER_URL=http://localhost:8787
```

---

## 🔄 Update Deployment

Made changes to `worker.js`? Re-deploy:

```bash
wrangler deploy
```

Changes are live instantly - no restart needed!

---

## 💰 Costs

**Free Tier includes:**
- 100,000 requests/day
- 10,000 AI neurons/day (approx. 1,000-5,000 summaries)
- 10ms CPU time per request

**Paid Plans:**
- $5/month for 10M requests
- Additional AI usage billed separately

For this app's typical usage (local deployment, small feed set), free tier is plenty!

---

## 🐛 Troubleshooting

### "Authentication failed"

- Check `CF_WORKER_TOKEN` matches in both:
  - Cloudflare (set via `wrangler secret put`)
  - Your `.env` file
- Tokens are case-sensitive!

### "AI model unavailable"

- Verify Workers AI is enabled in Cloudflare dashboard
- Check account limits (free tier: 10k neurons/day)
- Worker will fall back to basic extraction

### "Worker not found"

- Verify `CF_WORKER_URL` in `.env` matches deployment output
- Check worker is published: `wrangler deployments list`

### "CORS error"

- Worker includes CORS headers by default
- If still blocked, check browser console for details
- Verify worker is publicly accessible

---

## 📚 Additional Resources

- [Cloudflare Workers Docs](https://developers.cloudflare.com/workers/)
- [Workers AI Documentation](https://developers.cloudflare.com/workers-ai/)
- [Wrangler CLI Reference](https://developers.cloudflare.com/workers/wrangler/)
- [Pricing Calculator](https://workers.cloudflare.com/pricing)

---

**Need help?** Check the [SECURITY.md](SECURITY.md) file for additional configuration options.
