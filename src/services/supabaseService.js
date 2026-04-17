const { createClient } = require('@supabase/supabase-js');

let supabase;

function getClient() {
  if (!supabase) {
    supabase = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_SERVICE_KEY,
    );
  }
  return supabase;
}

/**
 * Persist a scan result into the `scans` table.
 * Standalone mode — no user_id required.
 */
async function saveScan({
  user_id,
  target_type,
  target_name,
  target_hash,
  stats,
  verdict,
  analysis_id,
}) {
  const { data, error } = await getClient()
    .from('scans')
    .insert({
      user_id: user_id ?? null,
      target_type,
      target_name,
      target_hash: target_hash ?? null,
      stats,
      verdict,
      analysis_id: analysis_id ?? null,
    })
    .select()
    .single();

  if (error) throw error;
  return data;
}

async function getScanById(scanId, userId) {
  let query = getClient()
    .from('scans')
    .select('*')
    .eq('id', scanId);

  if (userId) query = query.eq('user_id', userId);

  const { data, error } = await query.single();

  if (error && error.code !== 'PGRST116') throw error;
  return data;
}

async function getRecentScans(limit = 20, userId) {
  let query = getClient()
    .from('scans')
    .select('*')
    .order('created_at', { ascending: false });

  if (userId) query = query.eq('user_id', userId);

  const { data, error } = await query.limit(limit);

  if (error) throw error;
  return data;
}

module.exports = { saveScan, getScanById, getRecentScans };
