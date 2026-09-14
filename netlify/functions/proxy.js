// Ultra-fast edge-ready proxy with CAPTCHA support
exports.handler = async (event, context) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD',
    'Access-Control-Allow-Headers': '*',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Max-Age': '86400',
  };

  // Handle preflight
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers, body: '' };
  }

  try {
    // Get target URL from query param or path
    const url = event.queryStringParameters?.url || 
                event.queryStringParameters?.proxied ||
                event.queryStringParameters?.target ||
                decodeURIComponent(event.path.replace('/api/proxy/', '').replace('/proxy/', ''));

    if (!url) {
      return {
        statusCode: 400,
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({ error: 'No target URL provided. Use ?url=https://example.com' })
      };
    }

    // Validate URL
    let targetUrl;
    try {
      targetUrl = new URL(url.startsWith('http') ? url : `https://${url}`);
    } catch {
      return {
        statusCode: 400,
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({ error: 'Invalid URL format' })
      };
    }

    // CAPTCHA verification (optional - check for token)
    const captchaToken = event.queryStringParameters?.captcha || event.headers['x-captcha-token'];
    if (process.env.CAPTCHA_SECRET) {
      const verified = await verifyCaptcha(captchaToken, event.headers['x-forwarded-for'] || event.headers['client-ip']);
      if (!verified) {
        return {
          statusCode: 403,
          headers: { ...headers, 'Content-Type': 'application/json' },
          body: JSON.stringify({ error: 'CAPTCHA verification failed' })
        };
      }
    }

    // Build target headers (forward important ones)
    const forwardHeaders = {};
    const forwardable = ['accept', 'accept-language', 'accept-encoding', 'cache-control', 
                        'content-type', 'user-agent', 'referer', 'authorization', 'cookie'];
    
    Object.entries(event.headers).forEach(([key, value]) => {
      const lowerKey = key.toLowerCase();
      if (forwardable.includes(lowerKey) && !lowerKey.startsWith('x-') && !lowerKey.startsWith('host')) {
        forwardHeaders[key] = value;
      }
    });

    // Handle request body
    let body = event.body;
    if (event.isBase64Encoded && body) {
      body = Buffer.from(body, 'base64');
    }

    // Make the request with timeout
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 25000); // 25s timeout

    const response = await fetch(targetUrl.toString(), {
      method: event.httpMethod,
      headers: forwardHeaders,
      body: ['GET', 'HEAD'].includes(event.httpMethod) ? undefined : body,
      redirect: 'follow',
      signal: controller.signal
    });

    clearTimeout(timeout);

    // Process response headers
    const responseHeaders = { ...headers };
    response.headers.forEach((value, key) => {
      const lowerKey = key.toLowerCase();
      // Skip problematic headers but keep most
      if (!['content-encoding', 'transfer-encoding', 'connection'].includes(lowerKey)) {
        responseHeaders[key] = value;
      }
    });

    // Ensure content-type is set
    if (!responseHeaders['content-type']) {
      responseHeaders['content-type'] = 'text/html; charset=utf-8';
    }

    // Get response body
    const responseBuffer = await response.arrayBuffer();
    
    // Inject CORS headers into HTML responses for iframe compatibility
    let finalBody = Buffer.from(responseBuffer);
    const contentType = responseHeaders['content-type'] || '';
    
    if (contentType.includes('text/html')) {
      let html = finalBody.toString('utf-8');
      // Inject meta referrer and CORS support
      const injection = `<meta name="referrer" content="no-referrer"><base target="_top">`;
      html = html.replace(/<head[^>]*>/i, match => match + injection);
      finalBody = Buffer.from(html);
      responseHeaders['content-length'] = finalBody.length.toString();
    }

    return {
      statusCode: response.status,
      headers: responseHeaders,
      body: finalBody.toString('base64'),
      isBase64Encoded: true
    };

  } catch (error) {
    if (error.name === 'AbortError') {
      return {
        statusCode: 504,
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({ error: 'Gateway timeout - target took too long' })
      };
    }
    
    return {
      statusCode: 502,
      headers: { ...headers, 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'Proxy error', message: error.message })
    };
  }
};

// CAPTCHA verification helper
async function verifyCaptcha(token, remoteip) {
  if (!token) return false;
  
  // hCaptcha verification
  if (process.env.HCAPTCHA_SECRET) {
    const res = await fetch('https://hcaptcha.com/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        secret: process.env.HCAPTCHA_SECRET,
        response: token,
        remoteip: remoteip
      })
    });
    const data = await res.json();
    return data.success;
  }
  
  // reCAPTCHA verification
  if (process.env.RECAPTCHA_SECRET) {
    const res = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        secret: process.env.RECAPTCHA_SECRET,
        response: token
      })
    });
    const data = await res.json();
    return data.success;
  }
  
  // Simple token bypass for testing
  return token === process.env.CAPTCHA_BYPASS_TOKEN;
}
