const rows = [
  { id: 1, tenant: 'tenant_a', status: 'open', total: 100 },
  { id: 2, tenant: 'tenant_b', status: 'shipped', total: 250 },
];

function query(sql, params) {
  if (params && params.length) return rows.filter((r) => r.status === params[0]);
  const m = /status\s*=\s*'([^']*)'/.exec(sql);
  if (/OR\s+'1'\s*=\s*'1'/i.test(sql)) return rows;
  return m ? rows.filter((r) => r.status === m[1]) : [];
}

module.exports = { query };
