exports.handler = async (event, context) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD',
    'Access-Control-Allow-Headers': '*',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Max-Age': '86400',
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers, body: '' };
  }

  try {
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

    const forwardHeaders = {};
    const forwardable = ['accept', 'accept-language', 'accept-encoding', 'cache-control', 
                        'content-type', 'user-agent', 'referer', 'authorization', 'cookie'];
    
    Object.entries(event.headers).forEach(([key, value]) => {
      const lowerKey = key.toLowerCase();
      if (forwardable.includes(lowerKey) && !lowerKey.startsWith('x-') && !lowerKey.startsWith('host')) {
        forwardHeaders[key] = value;
      }
    });

    let body = event.body;
    if (event.isBase64Encoded && body) {
      body = Buffer.from(body, 'base64');
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 25000);

    const response = await fetch(targetUrl.toString(), {
      method: event.httpMethod,
      headers: forwardHeaders,
      body: ['GET', 'HEAD'].includes(event.httpMethod) ? undefined : body,
      redirect: 'follow',
      signal: controller.signal
    });

    clearTimeout(timeout);

    const responseHeaders = { ...headers };
    response.headers.forEach((value, key) => {
      const lowerKey = key.toLowerCase();
      if (!['content-encoding', 'transfer-encoding', 'connection'].includes(lowerKey)) {
        responseHeaders[key] = value;
      }
    });

    if (!responseHeaders['content-type']) {
      responseHeaders['content-type'] = 'text/html; charset=utf-8';
    }

    const responseBuffer = await response.arrayBuffer();
    let finalBody = Buffer.from(responseBuffer);
    const contentType = responseHeaders['content-type'] || '';
    
    if (contentType.includes('text/html')) {
      let html = finalBody.toString('utf-8');
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

async function verifyCaptcha(token, remoteip) {
  if (!token) return false;
  
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
  
  return token === process.env.CAPTCHA_BYPASS_TOKEN;
}
