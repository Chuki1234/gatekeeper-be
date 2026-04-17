const vtService = require('../services/vtService');
const supabase = require('../services/supabaseService');
const { hashBuffer } = require('../utils/hasher');
const base64url = require('../utils/base64url');
const { formatFileReport, formatUrlReport, formatAnalysis } = require('../utils/formatter');

// ─── POST /api/scan/file ──────────────────────────────────

async function scanFile(req, res, next) {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const { buffer, originalname } = req.file;

    // Phase 1 — hash check
    const sha256 = hashBuffer(buffer);
    let report;

    try {
      const existing = await vtService.getFileReport(sha256);
      report = formatFileReport(existing, originalname);
      report.source = 'cache';
    } catch (err) {
      if (err.response?.status !== 404) throw err;

      // Phase 2 — upload to VirusTotal
      const LARGE_FILE_THRESHOLD = 32 * 1024 * 1024;
      let uploadResult;

      if (buffer.length > LARGE_FILE_THRESHOLD) {
        const uploadUrl = await vtService.getUploadUrl();
        uploadResult = await vtService.uploadLargeFile(buffer, originalname, uploadUrl);
      } else {
        uploadResult = await vtService.uploadFile(buffer, originalname);
      }

      const analysisId = uploadResult.data?.id;
      if (!analysisId) {
        return res.status(202).json({
          status: 'analyzing',
          analysis_id: null,
          message: 'File submitted but no analysis ID returned.',
        });
      }

      const analysisData = await vtService.pollAnalysis(analysisId);

      const fileHash = analysisData.data?.meta?.file_info?.sha256 ?? sha256;
      const fullReport = await vtService.getFileReport(fileHash);
      report = formatFileReport(fullReport, originalname);
      report.source = 'new_scan';
    }

    const verdict = mapVerdict(report.stats);

    supabase.saveScan({
      user_id: req.user?.id ?? null,
      target_type: 'file',
      target_name: report.file_name,
      target_hash: report.file_hash,
      stats: report.stats,
      verdict,
      analysis_id: report.scan_id,
    }).catch((e) => console.error('[Supabase] save failed:', e.message));

    return res.json(report);
  } catch (err) {
    next(err);
  }
}

// ─── POST /api/scan/url ───────────────────────────────────

async function scanUrl(req, res, next) {
  try {
    const { url } = req.body;

    if (!url) {
      return res.status(400).json({ error: 'Missing "url" in request body' });
    }

    const urlId = base64url.encode(url);
    let report;

    try {
      const existing = await vtService.getUrlReport(urlId);
      report = formatUrlReport(existing, url);
      report.source = 'cache';
    } catch (err) {
      if (err.response?.status !== 404) throw err;

      const submission = await vtService.submitUrl(url);
      const analysisId = submission.data?.id;

      if (!analysisId) {
        return res.status(202).json({
          status: 'analyzing',
          analysis_id: null,
          message: 'URL submitted but no analysis ID returned.',
        });
      }

      await vtService.pollAnalysis(analysisId);

      const fullReport = await vtService.getUrlReport(urlId);
      report = formatUrlReport(fullReport, url);
      report.source = 'new_scan';
    }

    const verdict = mapVerdict(report.stats);

    supabase.saveScan({
      user_id: req.user?.id ?? null,
      target_type: 'url',
      target_name: url,
      target_hash: urlId,
      stats: report.stats,
      verdict,
      analysis_id: report.scan_id,
    }).catch((e) => console.error('[Supabase] save failed:', e.message));

    return res.json(report);
  } catch (err) {
    next(err);
  }
}

// ─── GET /api/scan/analysis/:id ───────────────────────────

async function getAnalysis(req, res, next) {
  try {
    const { id } = req.params;
    const data = await vtService.getAnalysis(id);
    return res.json(formatAnalysis(data));
  } catch (err) {
    next(err);
  }
}

// ─── GET /api/scan/report/:id ─────────────────────────────

async function getReport(req, res, next) {
  try {
    const { id } = req.params;
    const record = await supabase.getScanById(id, req.user?.id);

    if (!record) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    return res.json(record);
  } catch (err) {
    next(err);
  }
}

// ─── GET /api/scan/history ────────────────────────────────

async function getHistory(_req, res, next) {
  try {
    const scans = await supabase.getRecentScans(20, req.user?.id);
    return res.json(scans);
  } catch (err) {
    next(err);
  }
}

// ─── Helpers ──────────────────────────────────────────────

function mapVerdict(stats) {
  if (!stats) return 'clean';
  const { malicious = 0, suspicious = 0 } = stats;
  if (malicious > 3) return 'malicious';
  if (malicious > 0 || suspicious > 0) return 'suspicious';
  return 'clean';
}

module.exports = { scanFile, scanUrl, getAnalysis, getReport, getHistory };
