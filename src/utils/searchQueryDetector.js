const URL_PROTOCOLS = new Set(['http:', 'https:']);

const MD5_REGEX = /^[a-fA-F0-9]{32}$/;
const SHA256_REGEX = /^[a-fA-F0-9]{64}$/;
const IPV4_REGEX = /^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$/;
const DOMAIN_REGEX = /^(?!:\/\/)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$/;

function detectSearchQueryType(rawQuery) {
  const query = `${rawQuery ?? ''}`.trim();

  if (!query) return { type: 'unknown', normalized: query };
  if (SHA256_REGEX.test(query) || MD5_REGEX.test(query)) {
    return { type: 'hash', normalized: query.toLowerCase() };
  }

  if (isUrl(query)) {
    const normalizedUrl = normalizeUrl(query);
    return { type: 'url', normalized: normalizedUrl };
  }

  if (IPV4_REGEX.test(query)) {
    return { type: 'ip', normalized: query };
  }

  if (DOMAIN_REGEX.test(query)) {
    return { type: 'domain', normalized: query.toLowerCase() };
  }

  return { type: 'unknown', normalized: query };
}

function isUrl(value) {
  try {
    const url = new URL(normalizeUrl(value));
    return URL_PROTOCOLS.has(url.protocol);
  } catch {
    return false;
  }
}

function normalizeUrl(value) {
  if (/^https?:\/\//i.test(value)) return value;
  return `https://${value}`;
}

module.exports = { detectSearchQueryType };
