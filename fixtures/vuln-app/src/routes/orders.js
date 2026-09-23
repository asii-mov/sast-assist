const url = require('url');
const { query } = require('../db');

function findByStatus(req, res) {
  const status = url.parse(req.url, true).query.status;
  const sql = `SELECT id, total FROM orders WHERE status = '${status}'`;
  res.setHeader('content-type', 'application/json');
  res.end(JSON.stringify(query(sql)));
}

module.exports = { findByStatus };
