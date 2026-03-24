// featureExtractor.js
// Node.js module — DNS stateless feature extraction
// Called by the Express.js /api/analyse route handler.
// Computes 12 behavioural features per DNS query record.
 
'use strict';
 
/**
 * Compute Shannon entropy of a string.
 * Formula: H = -Σ p_i * log2(p_i)
 *
 * @param  {string} str  - Input string (subdomain portion of FQDN)
 * @returns {number}     - Entropy value (0 = uniform, ~4 = highly random)
 */
function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  const len = str.length;
  return -Object.values(freq)
    .map(f => { const p = f / len; return p * Math.log2(p); })
    .reduce((a, b) => a + b, 0);
}
 
/**
 * Extract all 12 stateless features from a single DNS query row.
 *
 * @param  {Object} row  - CSV row object from csv-parser
 *                         Expected field: query_name  (or FQDN / domain)
 * @returns {Object}     - Feature vector (keys match scaler.json and model)
 */
function extractFeatures(row) {
  const fqdn      = String(row.query_name || row.FQDN || row.domain || '');
  const parts     = fqdn.split('.').filter(Boolean);
  // Subdomain = everything except the last two labels (SLD + TLD)
  const subdomain = parts.slice(0, Math.max(0, parts.length - 2)).join('.');
 
  const upper   = (subdomain.match(/[A-Z]/g)       || []).length;
  const lower   = (subdomain.match(/[a-z]/g)       || []).length;
  const numeric = (subdomain.match(/[0-9]/g)       || []).length;
  const special = (subdomain.match(/[^a-zA-Z0-9.]/g) || []).length;
 
  const labelsAvg = parts.length > 0
    ? parts.reduce((s, p) => s + p.length, 0) / parts.length
    : 0;
  const longestWord = subdomain.length > 0
    ? Math.max(...subdomain.split(/[^a-zA-Z]+/).map(w => w.length))
    : 0;
 
  return {
    FQDN_count      : parts.length,
    subdomain_length: subdomain.length,
    upper,
    lower,
    numeric,
    entropy         : parseFloat(shannonEntropy(subdomain).toFixed(6)),
    special,
    labels          : parts.length,
    labels_max      : parts.length > 0 ? Math.max(...parts.map(p => p.length)) : 0,
    labels_average  : parseFloat(labelsAvg.toFixed(4)),
    longest_word    : longestWord,
    len             : fqdn.length,
  };
}
 
module.exports = { extractFeatures, shannonEntropy };
