const http = require('http');
const https = require('https');
const crypto = require('crypto');

// Configuration
const PORT = process.env.PORT || 3000;
const ENCRYPTION_KEY = 'fVwH6G9bLm2NPtXvR8sC3jK5dE9nZqYr'; // Must match local proxy
const IV_LENGTH = 16;

// Decryption function
function decrypt(text) {
  const parts = text.split(':');
  const iv = Buffer.from(parts.shift(), 'hex');
  const encryptedText = Buffer.from(parts.join(':'), 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return JSON.parse(decrypted.toString());
}

// Encryption function
function encrypt(text) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
  let encrypted = cipher.update(JSON.stringify(text));
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

// Parse URL to get protocol, host, path
function parseUrl(url) {
  const match = url.match(/^(https?:\/\/)?([^\/]+)(\/.*)?$/);
  if (!match) throw new Error('Invalid URL');
  
  const protocol = match[1] || 'http://';
  const host = match[2];
  const path = match[3] || '/';
  
  return { protocol, host, path };
}

// Reverse proxy server
const server = http.createServer((req, res) => {
  if (req.method !== 'POST') {
    res.writeHead(200);
    res.end('Encrypted Reverse Proxy Running');
    return;
  }

  let body = [];
  req.on('data', chunk => body.push(chunk));

  req.on('end', async () => {
    try {
      body = Buffer.concat(body).toString();

      // Decrypt the request
      const decryptedRequest = decrypt(body);
      console.log(`[REVERSE] Forwarding: ${decryptedRequest.method} ${decryptedRequest.url}`);

      // Parse the URL
      const { protocol, host, path } = parseUrl(decryptedRequest.url);
      const isHttps = protocol.startsWith('https');

      // Prepare options for the actual request
      const options = {
        hostname: host.split(':')[0],
        port: host.split(':')[1] || (isHttps ? 443 : 80),
        path: path,
        method: decryptedRequest.method,
        headers: {
          ...decryptedRequest.headers,
          host: host
        }
      };

      // Remove proxy-specific headers
      delete options.headers['proxy-connection'];
      delete options.headers['proxy-authorization'];

      // Make the actual request
      const client = isHttps ? https : http;
      const proxyReq = client.request(options, (proxyRes) => {
        let responseBody = [];

        proxyRes.on('data', chunk => responseBody.push(chunk));
        
        proxyRes.on('end', () => {
          // Package the response
          const responseData = {
            statusCode: proxyRes.statusCode,
            headers: proxyRes.headers,
            body: Buffer.concat(responseBody).toString('base64')
          };

          // Encrypt and send back
          const encryptedResponse = encrypt(responseData);
          res.writeHead(200, { 'Content-Type': 'text/plain' });
          res.end(encryptedResponse);
        });
      });

      proxyReq.on('error', (error) => {
        console.error('[REVERSE] Request error:', error.message);
        const errorResponse = {
          statusCode: 502,
          headers: {},
          body: Buffer.from('Bad Gateway: ' + error.message).toString('base64')
        };
        const encryptedResponse = encrypt(errorResponse);
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(encryptedResponse);
      });

      // Send request body if exists
      if (decryptedRequest.body) {
        proxyReq.write(decryptedRequest.body);
      }
      
      proxyReq.end();

    } catch (error) {
      console.error('[REVERSE] Error:', error.message);
      res.writeHead(500);
      res.end('Decryption Error: ' + error.message);
    }
  });
});

server.listen(PORT, () => {
  console.log(`[REVERSE] Encrypted reverse proxy running on port ${PORT}`);
});