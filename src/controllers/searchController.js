const vtService = require('../services/vtService');
const supabase = require('../services/supabaseService');
const base64url = require('../utils/base64url');
const { detectSearchQueryType } = require('../utils/searchQueryDetector');
const { formatIntelligenceReport } = require('../utils/formatter');

async function searchIntelligence(req, res, next) {
  try {
    const rawQuery = `${req.query.q ?? ''}`.trim();
    if (!rawQuery) {
      return res.status(400).json({ error: 'Missing query parameter "q"' });
    }

    const detected = detectSearchQueryType(rawQuery);
    if (detected.type === 'unknown') {
      return res.status(400).json({
        error: 'Unsupported query format. Use SHA-256/MD5 hash, IP, domain, or URL.',
      });
    }

    const { data, objectType, objectIdForComments } = await fetchIntelligenceReport(detected);

    const communityComments = await fetchCommunityComments(objectType, objectIdForComments);
    const report = formatIntelligenceReport(data, {
      query: rawQuery,
      objectType,
      communityComments,
    });

    supabase.saveScan({
      user_id: req.user?.id ?? null,
      target_type: 'search_query',
      target_name: rawQuery,
      target_hash: report.object_id ?? detected.normalized,
      stats: report.last_analysis_stats,
      verdict: mapVerdict(report.last_analysis_stats),
      analysis_id: report.object_id ?? null,
    }).catch((e) => console.error('[Supabase] search save failed:', e.message));

    return res.json(report);
  } catch (err) {
    if (err.response?.status === 404) {
      return res.status(404).json({ error: 'No intelligence report found for this query.' });
    }
    return next(err);
  }
}

async function fetchIntelligenceReport(detected) {
  switch (detected.type) {
    case 'hash':
      return {
        data: await vtService.getFileReport(detected.normalized),
        objectType: 'files',
        objectIdForComments: detected.normalized,
      };
    case 'domain':
      return {
        data: await vtService.getDomainReport(detected.normalized),
        objectType: 'domains',
        objectIdForComments: detected.normalized,
      };
    case 'ip':
      return {
        data: await vtService.getIpAddressReport(detected.normalized),
        objectType: 'ip_addresses',
        objectIdForComments: detected.normalized,
      };
    case 'url': {
      const urlId = base64url.encode(detected.normalized);
      return {
        data: await vtService.getUrlReport(urlId),
        objectType: 'urls',
        objectIdForComments: urlId,
      };
    }
    default:
      throw new Error(`Unsupported search query type: ${detected.type}`);
  }
}

async function fetchCommunityComments(objectType, objectId) {
  try {
    const commentsPayload = await vtService.getObjectComments(objectType, objectId, 5);
    return (commentsPayload.data ?? []).map((item) => ({
      id: item.id ?? null,
      text: item.attributes?.text ?? '',
      date: item.attributes?.date
        ? new Date(item.attributes.date * 1000).toISOString()
        : null,
    }));
  } catch {
    // Comment collection can be unavailable for some objects/accounts.
    return [];
  }
}

function mapVerdict(stats) {
  if (!stats) return 'clean';
  const { malicious = 0, suspicious = 0 } = stats;
  if (malicious > 3) return 'malicious';
  if (malicious > 0 || suspicious > 0) return 'suspicious';
  return 'clean';
}

module.exports = { searchIntelligence };
