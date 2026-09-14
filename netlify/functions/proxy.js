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
      if (!['content-encoding', 'transfer-encoding', 'connection', 'content-length'].includes(lower)) {
        responseHeaders[key] = value;
      }
    });

    // Handle Set-Cookie - expose them to client
    if (response.headers['set-cookie']) {
      responseHeaders['X-Set-Cookie'] = Array.isArray(response.headers['set-cookie']) 
        ? response.headers['set-cookie'].join(', ') 
        : response.headers['set-cookie'];
    }

    // Get body as buffer
    const bodyBuffer = Buffer.concat(response.chunks);
    
    // Detect CAPTCHA pages and inject helper
    let finalBody = bodyBuffer;
    const contentType = (responseHeaders['content-type'] || '').toLowerCase();
    
    if (contentType.includes('text/html')) {
      let html = finalBody.toString('utf-8');
      
      // Check for common CAPTCHA indicators
      const hasCaptcha = /(g-recaptcha|h-captcha|data-sitekey|cf-challenge|turnstile|__cf_bm)/i.test(html);
      
      if (hasCaptcha) {
        // Inject CAPTCHA helper script
        const captchaHelper = `
<script>
// CAPTCHA Proxy Helper - forwards tokens back through proxy
(function() {
  // Store original grecaptcha if present
  const originalRender = window.grecaptcha?.render;
  
  // Intercept form submissions with CAPTCHA
  document.querySelectorAll('form').forEach(form => {
    form.addEventListener('submit', function(e) {
      // Collect all CAPTCHA tokens
      const tokens = {};
      if (window.grecaptcha) {
        document.querySelectorAll('[name="g-recaptcha-response"]').forEach(el => {
          tokens['g-recaptcha-response'] = el.value;
        });
      }
      if (window.hcaptcha) {
        document.querySelectorAll('[name="h-captcha-response"]').forEach(el => {
          tokens['h-captcha-response'] = el.value;
        });
      }
      
      // Store tokens for parent frame
      window.parent.postMessage({type: 'captcha-solved', tokens: tokens, url: location.href}, '*');
    });
  });
  
  // Auto-detect CAPTCHA completion
  const observer = new MutationObserver((mutations) => {
    const recaptchaResponse = document.querySelector('[name="g-recaptcha-response"]');
    const hcaptchaResponse = document.querySelector('[name="h-captcha-response"]');
    
    if ((recaptchaResponse && recaptchaResponse.value) || 
        (hcaptchaResponse && hcaptchaResponse.value)) {
      window.parent.postMessage({type: 'captcha-detected', url: location.href}, '*');
    }
  });
  
  observer.observe(document.body, { childList: true, subtree: true });
})();
</script>`;
        html = html.replace(/<\/body>/i, captchaHelper + '</body>');
        finalBody = Buffer.from(html);
      }
      
      // Inject proxy helper for links/forms
      const proxyScript = `
<base href="${targetUrl}">
<script>
// Proxy Helper - rewrite all navigation to stay in proxy
(function() {
  const proxyBase = '${event.headers.host || ''}';
  const targetOrigin = '${parsedUrl.origin}';
  
  // Rewrite links
  document.querySelectorAll('a[href]').forEach(a => {
    if (a.href.startsWith('http') && !a.href.includes(proxyBase)) {
      const encoded = encodeURIComponent(a.href);
      a.href = '/api/proxy?url=' + encoded;
      a.target = '_top';
    }
  });
  
  // Rewrite forms
  document.querySelectorAll('form').forEach(f => {
    if (f.action && f.action.startsWith('http') && !f.action.includes(proxyBase)) {
      f.action = '/api/proxy?url=' + encodeURIComponent(f.action);
    }
    // Add hidden field for cookie persistence
    if (!f.querySelector('input[name="__proxy_cookie"]')) {
      const input = document.createElement('input');
      input.type = 'hidden';
      input.name = '__proxy_cookie';
      input.value = document.cookie;
      f.appendChild(input);
    }
  });
})();
</script>`;
      html = html.replace(/<\/head>/i, proxyScript + '</head>');
      finalBody = Buffer.from(html);
    }

    // Compress if needed
    responseHeaders['content-length'] = finalBody.length;

    return {
      statusCode: response.statusCode,
      headers: responseHeaders,
      body: finalBody.toString('base64'),
      isBase64Encoded: true
    };

  } catch (error) {
    return {
      statusCode: 502,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        error: 'Proxy error', 
        message: error.message,
        tip: 'For sites with heavy protection, use ?url= with a fresh session'
      })
    };
  }
};

// Native HTTP request with full control
function makeRequest(urlObj, method, headers, body) {
  return new Promise((resolve, reject) => {
    const client = urlObj.protocol === 'https:' ? https : http;
    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
      path: urlObj.pathname + urlObj.search,
      method: method,
      headers: {
        ...headers,
        'Host': urlObj.hostname,
      },
      timeout: 30000,
      rejectUnauthorized: false // Handle self-signed certs
    };

    const chunks = [];
    const req = client.request(options, (res) => {
      // Handle redirects manually to preserve cookies
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
        const redirectUrl = new URL(res.headers.location, urlObj);
        makeRequest(redirectUrl, method === 'POST' && res.statusCode !== 307 ? 'GET' : method, headers, body)
          .then(resolve)
          .catch(reject);
        return;
      }

      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          chunks: chunks
        });
      });
    });

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });

    if (body) {
      req.write(body);
    }
    req.end();
  });
}
