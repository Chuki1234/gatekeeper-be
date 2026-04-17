const axios = require('axios');
const FormData = require('form-data');

const VT_BASE = 'https://www.virustotal.com/api/v3';

function headers() {
  return { 'x-apikey': process.env.VT_API_KEY };
}

// ─── File operations ──────────────────────────────────────

async function getFileReport(hash) {
  const res = await axios.get(`${VT_BASE}/files/${hash}`, { headers: headers() });
  return res.data;
}

async function uploadFile(buffer, fileName) {
  const form = new FormData();
  form.append('file', buffer, { filename: fileName });

  const res = await axios.post(`${VT_BASE}/files`, form, {
    headers: { ...headers(), ...form.getHeaders() },
    maxContentLength: Infinity,
    maxBodyLength: Infinity,
  });
  return res.data;
}

/**
 * For files > 32 MB VirusTotal requires a special upload URL.
 */
async function getUploadUrl() {
  const res = await axios.get(`${VT_BASE}/files/upload_url`, { headers: headers() });
  return res.data.data;
}

async function uploadLargeFile(buffer, fileName, uploadUrl) {
  const form = new FormData();
  form.append('file', buffer, { filename: fileName });

  const res = await axios.post(uploadUrl, form, {
    headers: { ...headers(), ...form.getHeaders() },
    maxContentLength: Infinity,
    maxBodyLength: Infinity,
  });
  return res.data;
}

// ─── Analysis polling ─────────────────────────────────────

async function getAnalysis(analysisId) {
  const res = await axios.get(`${VT_BASE}/analyses/${analysisId}`, { headers: headers() });
  return res.data;
}

/**
 * Poll the analysis endpoint until `status` is "completed" or we exceed
 * the maximum number of attempts.  Returns the final analysis JSON.
 */
async function pollAnalysis(analysisId, { interval = 15000, maxAttempts = 20 } = {}) {
  for (let i = 0; i < maxAttempts; i++) {
    const data = await getAnalysis(analysisId);
    if (data.data?.attributes?.status === 'completed') return data;
    await new Promise((r) => setTimeout(r, interval));
  }
  throw new Error('Analysis polling timed out — try fetching the result later.');
}

// ─── URL operations ───────────────────────────────────────

async function getUrlReport(urlId) {
  const res = await axios.get(`${VT_BASE}/urls/${urlId}`, { headers: headers() });
  return res.data;
}

async function getDomainReport(domain) {
  const res = await axios.get(`${VT_BASE}/domains/${domain}`, { headers: headers() });
  return res.data;
}

async function getIpAddressReport(ipAddress) {
  const res = await axios.get(`${VT_BASE}/ip_addresses/${ipAddress}`, { headers: headers() });
  return res.data;
}

async function getObjectComments(objectType, objectId, limit = 5) {
  const safeObjectType = encodeURIComponent(objectType);
  const safeObjectId = encodeURIComponent(objectId);
  const res = await axios.get(`${VT_BASE}/${safeObjectType}/${safeObjectId}/comments?limit=${limit}`, {
    headers: headers(),
  });
  return res.data;
}

async function submitUrl(url) {
  const res = await axios.post(`${VT_BASE}/urls`, new URLSearchParams({ url }), {
    headers: { ...headers(), 'Content-Type': 'application/x-www-form-urlencoded' },
  });
  return res.data;
}

module.exports = {
  getFileReport,
  uploadFile,
  getUploadUrl,
  uploadLargeFile,
  getAnalysis,
  pollAnalysis,
  getUrlReport,
  getDomainReport,
  getIpAddressReport,
  getObjectComments,
  submitUrl,
};
