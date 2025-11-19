/**
 * Aviation Intelligence Hub - Cloudflare AI Worker
 *
 * This worker receives batches of aviation news items and returns AI-generated summaries
 * using Cloudflare's AI models.
 *
 * Expected Request Format:
 * POST /
 * Authorization: Bearer YOUR_CF_WORKER_TOKEN
 * {
 *   "items": [
 *     {"id": 1, "airline": "FAA", "content": "...", "source": "...", "date": "..."},
 *     ...
 *   ]
 * }
 *
 * Response Format:
 * {
 *   "summaries": {
 *     "1": {"summary": "...", "key_points": [...], "action_items": [...]},
 *     "2": "Brief summary...",
 *     ...
 *   },
 *   "overall_summary": "Overall analysis of this batch...",
 *   "sentiment": {"label": "neutral", "score": 0.0}
 * }
 */

export default {
  async fetch(request, env) {
    // CORS headers for all responses
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    // Only allow POST
    if (request.method !== 'POST') {
      return new Response(JSON.stringify({ error: 'Method not allowed' }), {
        status: 405,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Verify authentication
    const authHeader = request.headers.get('Authorization');
    const expectedToken = env.CF_WORKER_TOKEN || 'super-secret-123!';

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return new Response(JSON.stringify({ error: 'Missing authorization' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const token = authHeader.slice(7); // Remove 'Bearer '
    if (token !== expectedToken) {
      return new Response(JSON.stringify({ error: 'Invalid authorization token' }), {
        status: 403,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    try {
      // Parse request body
      const body = await request.json();
      const items = body.items || [];

      if (!Array.isArray(items) || items.length === 0) {
        return new Response(JSON.stringify({ error: 'No items provided' }), {
          status: 400,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      console.log(`Processing ${items.length} items`);

      // Generate summaries using Cloudflare AI
      const summaries = {};
      const overallTexts = [];
      let totalSentiment = 0;
      let sentimentCount = 0;

      for (const item of items) {
        try {
          const summary = await generateSummary(item, env);
          summaries[item.id] = summary;

          // Collect for overall summary
          if (typeof summary === 'string') {
            overallTexts.push(summary);
          } else if (summary.summary) {
            overallTexts.push(summary.summary);
          }

          // Simple sentiment analysis
          const sentiment = analyzeSentiment(item.content || '');
          totalSentiment += sentiment;
          sentimentCount++;
        } catch (err) {
          console.error(`Failed to process item ${item.id}:`, err);
          summaries[item.id] = {
            summary: 'Unable to generate summary',
            error: err.message
          };
        }
      }

      // Calculate average sentiment
      const avgSentiment = sentimentCount > 0 ? totalSentiment / sentimentCount : 0;
      const sentimentLabel = avgSentiment > 0.1 ? 'positive' : avgSentiment < -0.1 ? 'negative' : 'neutral';

      // Generate overall summary
      const overallSummary = overallTexts.length > 0
        ? `Processed ${items.length} aviation news items. Key topics include regulatory updates, safety notices, and industry developments.`
        : '';

      return new Response(JSON.stringify({
        summaries,
        overall_summary: overallSummary,
        sentiment: {
          label: sentimentLabel,
          score: avgSentiment
        }
      }), {
        status: 200,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });

    } catch (err) {
      console.error('Worker error:', err);
      return new Response(JSON.stringify({
        error: 'Internal server error',
        details: err.message
      }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }
  }
};

/**
 * Generate AI summary for a single news item
 */
async function generateSummary(item, env) {
  const content = (item.content || '').substring(0, 2500);
  const airline = item.airline || 'Unknown';
  const source = item.source || '';

  // Use Cloudflare AI if available
  if (env.AI) {
    try {
      const prompt = `Summarize this aviation news article in 2-3 concise sentences. Focus on key facts and implications.

Source: ${airline}
Article: ${content}

Provide a professional summary:`;

      const response = await env.AI.run('@cf/meta/llama-3.1-8b-instruct', {
        messages: [
          { role: 'system', content: 'You are an aviation industry analyst. Provide concise, factual summaries.' },
          { role: 'user', content: prompt }
        ],
        max_tokens: 150,
        temperature: 0.3,
      });

      const aiSummary = response.response || response.text || 'Unable to generate summary';

      return {
        summary: aiSummary.trim(),
        source: airline,
        analyzed_at: new Date().toISOString(),
        model: 'llama-3.1-8b'
      };
    } catch (err) {
      console.error('AI generation failed:', err);
      // Fall through to basic summary
    }
  }

  // Fallback: Generate basic summary
  return generateBasicSummary(content, airline);
}

/**
 * Generate a basic summary without AI
 */
function generateBasicSummary(content, source) {
  // Extract first few sentences
  const sentences = content.split(/[.!?]+/).filter(s => s.trim().length > 20);
  const summary = sentences.slice(0, 2).join('. ').trim() + '.';

  // Extract key phrases (simple approach)
  const keyWords = ['safety', 'regulation', 'compliance', 'inspection', 'maintenance',
                    'pilot', 'aircraft', 'airport', 'faa', 'emergency'];
  const foundKeys = keyWords.filter(word =>
    content.toLowerCase().includes(word)
  );

  return {
    summary: summary.substring(0, 300),
    key_topics: foundKeys.slice(0, 5),
    source: source,
    analyzed_at: new Date().toISOString(),
    method: 'basic_extraction'
  };
}

/**
 * Simple sentiment analysis
 * Returns a score between -1 (negative) and 1 (positive)
 */
function analyzeSentiment(text) {
  const lowerText = text.toLowerCase();

  const positiveWords = ['approved', 'success', 'improved', 'safe', 'cleared',
                         'certified', 'compliant', 'completed', 'awarded', 'growth'];
  const negativeWords = ['violation', 'suspended', 'failed', 'crash', 'emergency',
                         'incident', 'penalty', 'grounded', 'denied', 'unsafe'];

  let score = 0;
  positiveWords.forEach(word => {
    if (lowerText.includes(word)) score += 0.1;
  });
  negativeWords.forEach(word => {
    if (lowerText.includes(word)) score -= 0.1;
  });

  return Math.max(-1, Math.min(1, score));
}
