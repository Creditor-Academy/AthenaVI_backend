function getClientIp(req) {
  const ip = req?.ip;
  if (!ip || typeof ip !== 'string') {
    return 'unknown';
  }
  const trimmed = ip.trim();
  return trimmed || 'unknown';
}

module.exports = { getClientIp };
