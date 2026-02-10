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
    res.end('Encrypted Reverse Proxy Running (v2 - HTTP + HTTPS)');
    return;
  }

  // Handle proxy requests
  if (req.method === 'POST') {
    handleProxyRequest(req, res);
    return;
  }

  res.writeHead(404);
  res.end('Not Found');
});

// Handle CONNECT method for HTTPS tunneling
server.on('connect', (req, clientSocket, head) => {
  const targetUrl = req.url;
  
  console.log(`[REVERSE] CONNECT tunnel request for ${targetUrl}`);
  
  try {
    // Decrypt authorization header if present
    const auth = req.headers['proxy-authorization'];
    if (auth) {
      const decrypted = decrypt(auth);
      console.log(`[REVERSE] Decrypted target: ${decrypted.target}`);
    }
    
    // Parse target host and port
    const [hostname, port = 443] = targetUrl.split(':');
    
    // Connect to target server
    const targetSocket = net.connect(port, hostname, () => {
      console.log(`[REVERSE] ✓ Connected to ${targetUrl}`);
      
      // Tell client we're ready
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      
      // Pipe data bidirectionally
      targetSocket.pipe(clientSocket);
      clientSocket.pipe(targetSocket);
      
      // Write any buffered data
      if (head.length) {
        targetSocket.write(head);
      }
    });

    targetSocket.on('error', (err) => {
      console.error(`[REVERSE] ✗ Target error for ${targetUrl}:`, err.message);
      clientSocket.end();
    });

    clientSocket.on('error', (err) => {
      console.error(`[REVERSE] ✗ Client error:`, err.message);
      targetSocket.destroy();
    });

  } catch (error) {
    console.error('[REVERSE] CONNECT Error:', error.message);
    clientSocket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n');
  }
});

// Handle regular proxy requests
function handleProxyRequest(req, res) {
  let body = [];
  req.on('data', chunk => body.push(chunk));

  req.on('end', async () => {
    try {
      body = Buffer.concat(body).toString();

      // Decrypt the request
      const decryptedRequest = decrypt(body);
      console.log(`[REVERSE] ${decryptedRequest.method} ${decryptedRequest.url}`);

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
        proxyReq.write(Buffer.from(decryptedRequest.body, 'base64'));
      }
      
      proxyReq.end();

    } catch (error) {
      console.error('[REVERSE] Error:', error.message);
      res.writeHead(500);
      res.end('Decryption Error: ' + error.message);
    }
  });
}

server.listen(PORT, () => {
  console.log(`[REVERSE] Encrypted reverse proxy running on port ${PORT}`);
  console.log(`[REVERSE] Supports HTTP POST and CONNECT methods`);
});
