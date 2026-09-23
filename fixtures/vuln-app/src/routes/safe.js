const url = require('url');
const { query } = require('../db');

const ALLOWED = ['open', 'shipped', 'cancelled'];

function findByStatusSafe(req, res) {
  const status = url.parse(req.url, true).query.status;
  if (!ALLOWED.includes(status)) { res.statusCode = 400; return res.end('bad status'); }
  res.setHeader('content-type', 'application/json');
  res.end(JSON.stringify(query('SELECT id, total FROM orders WHERE status = ?', [status])));
}

module.exports = { findByStatusSafe };
