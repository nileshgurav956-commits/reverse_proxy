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
  // Health check
  if (req.method === 'GET' && req.url === '/') {
    res.writeHead(200);
    res.end('Encrypted Reverse Proxy Running (HTTP + HTTPS CONNECT Support)');
    return;
  }

  // Handle HTTPS CONNECT tunneling
  if (req.method === 'POST' && req.url === '/connect') {
    handleConnectTunnel(req, res);
    return;
  }

  // Handle regular HTTP proxying
  if (req.method === 'POST' && req.url === '/http') {
    handleHttpProxy(req, res);
    return;
  }

  res.writeHead(404);
  res.end('Not Found');
});

// Handle HTTPS CONNECT tunnel requests
function handleConnectTunnel(req, res) {
  let body = [];
  req.on('data', chunk => body.push(chunk));

  req.on('end', async () => {
    try {
      body = Buffer.concat(body).toString();
      
      // Decrypt the CONNECT request
      const decryptedData = decrypt(body);
      const targetHost = decryptedData.host;
      
      console.log(`[REVERSE] Creating HTTPS tunnel to ${targetHost}`);
      
      // Parse host and port
      const [hostname, port = 443] = targetHost.split(':');
      
      // Create connection to target server
      const targetSocket = net.connect(port, hostname, () => {
        console.log(`[REVERSE] ✓ Connected to ${targetHost}`);
        
        // Send success response
        res.writeHead(200, {
          'Content-Type': 'text/plain',
          'Connection': 'keep-alive'
        });
        
        // Upgrade the connection to raw TCP
        res.socket.pipe(targetSocket);
        targetSocket.pipe(res.socket);
      });

      targetSocket.on('error', (err) => {
        console.error(`[REVERSE] ✗ Target connection error for ${targetHost}:`, err.message);
        if (!res.headersSent) {
          res.writeHead(502);
          res.end('Bad Gateway');
        }
      });

    } catch (error) {
      console.error('[REVERSE] CONNECT Error:', error.message);
      res.writeHead(500);
      res.end('Tunnel Error: ' + error.message);
    }
  });
}

// Handle regular HTTP proxy requests
function handleHttpProxy(req, res) {
  let body = [];
  req.on('data', chunk => body.push(chunk));

  req.on('end', async () => {
    try {
      body = Buffer.concat(body).toString();

      // Decrypt the request
      const decryptedRequest = decrypt(body);
      console.log(`[REVERSE] HTTP Forwarding: ${decryptedRequest.method} ${decryptedRequest.url}`);

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
      console.error('[REVERSE] HTTP Error:', error.message);
      res.writeHead(500);
      res.end('Decryption Error: ' + error.message);
    }
  });
}

server.listen(PORT, () => {
  console.log(`[REVERSE] Encrypted reverse proxy running on port ${PORT}`);
  console.log(`[REVERSE] Supports HTTP and HTTPS CONNECT tunneling`);
});
