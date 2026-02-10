const http = require('http');
const https = require('https');
const net = require('net');
const crypto = require('crypto');

// Configuration
const PORT = process.env.PORT || 3000;
const ENCRYPTION_KEY = 'fVwH6G9bLm2NPtXvR8sC3jK5dE9nZqYr';
const IV_LENGTH = 16;

// Decryption function
function decrypt(text) {
  try {
    const parts = text.split(':');
    const iv = Buffer.from(parts.shift(), 'hex');
    const encryptedText = Buffer.from(parts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return JSON.parse(decrypted.toString());
  } catch (e) {
    console.error('[REVERSE] Decryption error:', e.message);
    return null;
  }
}

// Encryption function
function encrypt(text) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
  let encrypted = cipher.update(JSON.stringify(text));
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

// Parse URL
function parseUrl(url) {
  const match = url.match(/^(https?:\/\/)?([^\/]+)(\/.*)?$/);
  if (!match) throw new Error('Invalid URL');
  
  const protocol = match[1] || 'http://';
  const host = match[2];
  const path = match[3] || '/';
  
  return { protocol, host, path };
}

// Server
const server = http.createServer((req, res) => {
  // Health check
  if (req.method === 'GET' && req.url === '/') {
    res.writeHead(200);
    res.end('Encrypted Reverse Proxy (HTTP + HTTPS CONNECT)');
    return;
  }

  // Handle HTTP proxy
  if (req.method === 'POST' && req.url === '/proxy') {
    handleHttpProxy(req, res);
    return;
  }

  res.writeHead(404);
  res.end('Not Found');
});

// Handle CONNECT method
server.on('connect', (req, clientSocket, head) => {
  const targetUrl = req.url;
  console.log(`[REVERSE] CONNECT request for ${targetUrl}`);

  // Try to decrypt target from header
  const encryptedTarget = req.headers['x-target'];
  let targetHost = targetUrl;
  let targetPort = 443;

  if (encryptedTarget) {
    const decrypted = decrypt(encryptedTarget);
    if (decrypted) {
      targetHost = decrypted.host;
      targetPort = parseInt(decrypted.port) || 443;
      console.log(`[REVERSE] Decrypted target: ${targetHost}:${targetPort}`);
    }
  } else {
    // Parse from URL
    [targetHost, targetPort = 443] = targetUrl.split(':');
  }

  console.log(`[REVERSE] Connecting to ${targetHost}:${targetPort}`);

  // Connect to target
  const targetSocket = net.connect(targetPort, targetHost, () => {
    console.log(`[REVERSE] ✓ Connected to ${targetHost}:${targetPort}`);
    
    // Send success to client
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

    // Write any buffered data
    if (head && head.length > 0) {
      targetSocket.write(head);
    }

    // Pipe bidirectionally
    targetSocket.pipe(clientSocket);
    clientSocket.pipe(targetSocket);
  });

  targetSocket.on('error', (err) => {
    console.error(`[REVERSE] ✗ Target error for ${targetHost}:`, err.message);
    clientSocket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n');
    clientSocket.end();
  });

  clientSocket.on('error', (err) => {
    console.error(`[REVERSE] ✗ Client error:`, err.message);
    targetSocket.destroy();
  });
});

// Handle HTTP proxy requests
function handleHttpProxy(req, res) {
  let body = [];
  req.on('data', chunk => body.push(chunk));

  req.on('end', async () => {
    try {
      body = Buffer.concat(body).toString();

      const decryptedRequest = decrypt(body);
      if (!decryptedRequest) {
        res.writeHead(400);
        res.end('Bad Request');
        return;
      }

      console.log(`[REVERSE] ${decryptedRequest.method} ${decryptedRequest.url}`);

      const { protocol, host, path } = parseUrl(decryptedRequest.url);
      const isHttps = protocol.startsWith('https');

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

      delete options.headers['proxy-connection'];
      delete options.headers['proxy-authorization'];

      const client = isHttps ? https : http;
      const proxyReq = client.request(options, (proxyRes) => {
        let responseBody = [];

        proxyRes.on('data', chunk => responseBody.push(chunk));
        
        proxyRes.on('end', () => {
          const responseData = {
            statusCode: proxyRes.statusCode,
            headers: proxyRes.headers,
            body: Buffer.concat(responseBody).toString('base64')
          };

          const encryptedResponse = encrypt(responseData);
          res.writeHead(200, { 'Content-Type': 'text/plain' });
          res.end(encryptedResponse);
          console.log(`[REVERSE] ✓ ${proxyRes.statusCode}`);
        });
      });

      proxyReq.on('error', (error) => {
        console.error('[REVERSE] Request error:', error.message);
        const errorResponse = {
          statusCode: 502,
          headers: {},
          body: Buffer.from('Bad Gateway').toString('base64')
        };
        const encryptedResponse = encrypt(errorResponse);
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(encryptedResponse);
      });

      if (decryptedRequest.body) {
        proxyReq.write(decryptedRequest.body);
      }
      
      proxyReq.end();

    } catch (error) {
      console.error('[REVERSE] Error:', error.message);
      res.writeHead(500);
      res.end('Server Error');
    }
  });
}

server.listen(PORT, () => {
  console.log(`[REVERSE] Running on port ${PORT}`);
  console.log(`[REVERSE] HTTP proxy + HTTPS CONNECT support`);
});
