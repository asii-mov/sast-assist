const http = require('http');
const { URL } = require('url');

const orders = require('./routes/orders');
const files = require('./routes/files');
const admin = require('./routes/admin');
const safe = require('./routes/safe');

const server = http.createServer((req, res) => {
  const p = new URL(req.url, 'http://localhost').pathname;
  if (p === '/healthz') { res.setHeader('content-type', 'text/plain'); return res.end('ok'); }
  if (p === '/orders') return orders.findByStatus(req, res);
  if (p === '/files') return files.read(req, res);
  if (p === '/admin/ping') return admin.ping(req, res);
  if (p === '/orders/safe') return safe.findByStatusSafe(req, res);
  res.statusCode = 404;
  res.end('no route');
});

const port = Number(process.env.PORT || 0);
server.listen(port, '127.0.0.1', () => {
  console.log(`listening ${JSON.stringify(server.address())}`);
});

module.exports = { server };
