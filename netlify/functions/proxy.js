// Full session-aware proxy with CAPTCHA support
const https = require('https');
const http = require('http');
const { URL } = require('url');

// Cookie jar for session persistence (per-request on serverless, but helps with redirects)
const cookieJar = new Map();

exports.handler = async (event, context) => {
  // Disable response streaming timeout for long CAPTCHA pages
  context.callbackWaitsForEmptyEventLoop = false;
  
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD',
    'Access-Control-Allow-Headers': '*',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Expose-Headers': '*',
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers: corsHeaders, body: '' };
  }

  try {
    // Get target URL
    let targetUrl = event.queryStringParameters?.url || 
                    event.queryStringParameters?.proxied ||
                    event.headers['x-target-url'];

    if (!targetUrl) {
      return {
        statusCode: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({ error: 'No target URL. Use ?url=https://example.com' })
      };
    }

    // Ensure protocol
    if (!targetUrl.startsWith('http')) {
      targetUrl = 'https://' + targetUrl;
    }

    const parsedUrl = new URL(targetUrl);
    
    // Build headers - forward everything important for auth/CAPTCHA
    const forwardHeaders = {
      'Accept': event.headers['accept'] || 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
      'Accept-Language': event.headers['accept-language'] || 'en-US,en;q=0.9',
      'Accept-Encoding': event.headers['accept-encoding'] || 'gzip, deflate, br',
      'Cache-Control': event.headers['cache-control'] || 'no-cache',
      'User-Agent': event.headers['user-agent'] || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Referer': event.headers['referer'] || parsedUrl.origin,
      'Origin': event.headers['origin'] || parsedUrl.origin,
    };

    // Forward auth headers
    if (event.headers['authorization']) {
      forwardHeaders['Authorization'] = event.headers['authorization'];
    }
    
    // Forward cookies (critical for CAPTCHA session persistence)
    if (event.headers['x-forwarded-cookie'] || event.headers['cookie']) {
      forwardHeaders['Cookie'] = event.headers['x-forwarded-cookie'] || event.headers['cookie'];
    }

    // Forward content-type for POSTs
    if (event.headers['content-type']) {
      forwardHeaders['Content-Type'] = event.headers['content-type'];
    }

    // Prepare body
    let body = null;
    if (event.body && !['GET', 'HEAD'].includes(event.httpMethod)) {
      body = event.isBase64Encoded ? Buffer.from(event.body, 'base64') : event.body;
    }

    // Make request using native https (faster than fetch for CAPTCHA pages)
    const response = await makeRequest(parsedUrl, event.httpMethod, forwardHeaders, body);
    
    // Process response
    const responseHeaders = { ...corsHeaders };
    Object.entries(response.headers).forEach(([key, value]) => {
      const lower = key.toLowerCase();
      if (!['content-encoding', 'transfer-encoding', 'connection', 'content
