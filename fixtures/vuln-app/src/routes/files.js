const fs = require('fs');
const path = require('path');
const url = require('url');

const ROOT = path.join(__dirname, '..', '..', 'public');

function read(req, res) {
  const name = url.parse(req.url, true).query.name;
  const target = path.join(ROOT, name);
  fs.readFile(target, 'utf8', (err, data) => {
    if (err) { res.statusCode = 404; return res.end('not found'); }
    res.setHeader('content-type', 'text/plain');
    res.end(data);
  });
}

module.exports = { read };
