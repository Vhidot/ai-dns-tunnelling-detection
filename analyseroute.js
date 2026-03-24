// analyseRoute.js
// Express.js route — POST /api/analyse
// Handles file upload, orchestrates feature extraction and inference,
// returns JSON classification results to the React frontend.
 
'use strict';
 
const express  = require('express');
const multer   = require('multer');
const csv      = require('csv-parser');
const fs       = require('fs');
const path     = require('path');
 
const { extractFeatures }           = require('./featureExtractor');
const { classifyBatch }             = require('./modelInference');
 
const router  = express.Router();
 
// ── Multer config: memory storage, accept only .csv and .pcap ───────────
const upload = multer({
  storage: multer.memoryStorage(),
  limits:  { fileSize: 50 * 1024 * 1024 },   // 50 MB hard limit
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (['.csv', '.pcap'].includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Unsupported file type. Please upload a .csv or .pcap file.'));
    }
  },
});
 
// ── Helper: parse CSV buffer → array of feature vectors ─────────────────
function parseCsvBuffer(buffer) {
  return new Promise((resolve, reject) => {
    const rows = [];
    const { Readable } = require('stream');
    const stream = Readable.from(buffer.toString('utf8'));
    stream
      .pipe(csv())
      .on('data',  row  => rows.push(extractFeatures(row)))
      .on('end',   ()   => resolve(rows))
      .on('error', err  => reject(err));
  });
}
 
// ── Helper: compute summary statistics ──────────────────────────────────
function calculateSummary(results) {
  const total      = results.length;
  const suspicious = results.filter(r => r.label === 'Suspicious').length;
  const benign     = total - suspicious;
  const avgConf    = results.length > 0
    ? (results.reduce((s, r) => s + parseFloat(r.confidence), 0) / total).toFixed(2)
    : '0.00';
  return { total, benign, suspicious, avgConf };
}
 
// ── POST /api/analyse ────────────────────────────────────────────────────
router.post('/', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded.' });
    }
 
    const ext = path.extname(req.file.originalname).toLowerCase();
    let featureVectors = [];
 
    if (ext === '.csv') {
      featureVectors = await parseCsvBuffer(req.file.buffer);
    } else {
      // .pcap: placeholder — in production, pipe through tshark
      return res.status(422).json({
        error: 'Direct .pcap processing requires tshark on the server. '
             + 'Please convert to .csv first using the provided script.',
      });
    }
 
    if (featureVectors.length === 0) {
      return res.status(422).json({ error: 'No DNS records found in uploaded file.' });
    }
 
    // Classify all records
    const results = await classifyBatch(featureVectors);
    const summary = calculateSummary(results);
 
    return res.status(200).json({
      summary,
      results: results.map((r, i) => ({
        id         : i + 1,
        query      : r.rawFeatures._query || '',
        entropy    : r.rawFeatures.entropy,
        subdomain_length: r.rawFeatures.subdomain_length,
        label      : r.label,
        confidence : r.confidence,
      })),
    });
 
  } catch (err) {
    console.error('[/api/analyse] Error:', err.message);
    return res.status(500).json({ error: 'Internal server error during analysis.' });
  }
});
 
module.exports = router;
