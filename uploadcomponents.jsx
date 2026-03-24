// UploadComponent.jsx
// React component — File upload page with drag-and-drop support.
// Submits file to POST /api/analyse and navigates to results on success.
 
import { useState, useCallback } from 'react';
import axios from 'axios';
 
export default function UploadComponent({ onResults }) {
  const [dragging,   setDragging]   = useState(false);
  const [uploading,  setUploading]  = useState(false);
  const [progress,   setProgress]   = useState(0);
  const [errorMsg,   setErrorMsg]   = useState('');
 
  const ACCEPTED = ['.csv', '.pcap'];
  const MAX_MB   = 50;
 
  // ── Validate before submitting ─────────────────────────────────────
  function validate(file) {
    const ext = file.name.slice(file.name.lastIndexOf('.')).toLowerCase();
    if (!ACCEPTED.includes(ext)) {
      return `Unsupported type "${ext}". Please upload .csv or .pcap.`;
    }
    if (file.size > MAX_MB * 1024 * 1024) {
      return `File exceeds ${MAX_MB} MB limit.`;
    }
    return null;
  }
 
  // ── Submit file to backend ─────────────────────────────────────────
  const handleFile = useCallback(async (file) => {
    const err = validate(file);
    if (err) { setErrorMsg(err); return; }
 
    setErrorMsg('');
    setUploading(true);
    setProgress(0);
 
    const formData = new FormData();
    formData.append('file', file);
 
    try {
      const { data } = await axios.post('/api/analyse', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
        onUploadProgress: (e) => {
          setProgress(Math.round((e.loaded / e.total) * 100));
        },
      });
      onResults(data);   // lift results up to parent / router
    } catch (e) {
      const msg = e.response?.data?.error || 'Upload failed. Please try again.';
      setErrorMsg(msg);
    } finally {
      setUploading(false);
    }
  }, [onResults]);
 
  // ── Drag-and-drop handlers ────────────────────────────────────────
  const onDragOver  = (e) => { e.preventDefault(); setDragging(true);  };
  const onDragLeave = ()  => setDragging(false);
  const onDrop      = (e) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  };
  const onBrowse    = (e) => {
    const file = e.target.files[0];
    if (file) handleFile(file);
  };
 
  return (
    <div className="upload-page">
      <h1>DNS Tunneling Detection</h1>
      <p className="subtitle">Upload a .csv or .pcap DNS traffic file for AI-powered analysis.</p>
 
      {/* Drop zone */}
      <div
        className={`drop-zone ${dragging ? 'drag-active' : ''}`}
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        onDrop={onDrop}
      >
        <span className="upload-icon">⬆</span>
        <p>Drag and drop your file here</p>
        <p className="or">— or —</p>
        <label className="browse-btn">
          Browse Files
          <input
            type="file"
            accept=".csv,.pcap"
            onChange={onBrowse}
            style={{ display: 'none' }}
          />
        </label>
        <p className="hint">Supported: .csv, .pcap  ·  Max 50 MB</p>
      </div>
 
      {/* Progress / error feedback */}
      {uploading && (
        <div className="progress-bar">
          <div className="fill" style={{ width: `${progress}%` }} />
          <span>{progress}%</span>
        </div>
      )}
      {errorMsg && <p className="error-msg">{errorMsg}</p>}
    </div>
  );
}
