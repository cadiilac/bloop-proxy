// Returns a CAPTCHA challenge page
exports.handler = async (event) => {
  const headers = {
    'Content-Type': 'text/html',
    'Access-Control-Allow-Origin': '*',
    'Cache-Control': 'no-store'
  };

  const targetUrl = event.queryStringParameters?.url || '';
  
  const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Check</title>
  <script src="https://js.hcaptcha.com/1/api.js" async defer></script>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #fff;
    }
    .container {
      text-align: center;
      padding: 2rem;
      max-width: 400px;
    }
    h1 { font-size: 1.5rem; margin-bottom: 1rem; color: #eee; }
    .target { color: #4fc3f7; word-break: break-all; font-size: 0.9rem; margin-bottom: 2rem; }
    .h-captcha { display: inline-block; }
    .info { margin-top: 2rem; font-size: 0.85rem; color: #888; }
    .loading { display: none; margin-top: 1rem; }
    .spinner {
      width: 40px; height: 40px;
      border: 3px solid rgba(255,255,255,0.1);
      border-top-color: #4fc3f7;
      border-radius: 50%;
      animation: spin 1s linear infinite;
      margin: 0 auto;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
  </style>
</head>
<body>
  <div class="container">
    <h1>🔒 Security Verification</h1>
    <div class="target">${escapeHtml(targetUrl)}</div>
    
    <div class="h-captcha" 
         data-sitekey="${process.env.HCAPTCHA_SITE_KEY || '10000000-ffff-ffff-ffff-000000000001'}" 
         data-callback="onCaptchaSuccess"
         data-theme="dark"></div>
    
    <div class="loading" id="loading">
      <div class="spinner"></div>
      <p>Verifying...</p>
    </div>
    
    <div class="info">Complete the CAPTCHA to continue to your destination</div>
  </div>

  <script>
    function onCaptchaSuccess(token) {
      document.getElementById('loading').style.display = 'block';
      const url = new URL(window.location.href);
      const target = url.searchParams.get('url');
      window.location.href = '/api/proxy?url=' + encodeURIComponent(target) + '&captcha=' + token;
    }
    
    function escapeHtml(text) {
      const div = document.createElement('div');
      div.textContent = text;
      return div.innerHTML;
    }
  </script>
</body>
</html>`;

  return { statusCode: 200, headers, body: html };
};

function escapeHtml(text) {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
