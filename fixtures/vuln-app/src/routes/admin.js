const { exec } = require('child_process');
const url = require('url');

function ping(req, res) {
  const host = url.parse(req.url, true).query.host;
  exec(`ping -c 1 ${host}`, (err, stdout) => {
    res.setHeader('content-type', 'text/plain');
    res.end(stdout || String(err));
  });
}

module.exports = { ping };
