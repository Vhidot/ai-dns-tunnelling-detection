 Source Code
// ResultsComponent.jsx
// React component — Displays classification results dashboard.
// Renders donut chart, metric cards, and filterable query table.
 
import { useState } from 'react';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';
import { Doughnut } from 'react-chartjs-2';
 
ChartJS.register(ArcElement, Tooltip, Legend);
 
export default function ResultsComponent({ data, onReset }) {
  const { summary, results } = data;
  const [filter, setFilter] = useState('all');    // 'all' | 'suspicious' | 'benign'
  const [search, setSearch] = useState('');
 
  // ── Filter + search logic ──────────────────────────────────────────
  const displayed = results.filter(r => {
    const matchFilter =
      filter === 'all'        ? true :
      filter === 'suspicious' ? r.label === 'Suspicious' :
                                r.label === 'Benign';
    const matchSearch = r.query.toLowerCase().includes(search.toLowerCase());
    return matchFilter && matchSearch;
  });
 
  // ── Chart data ────────────────────────────────────────────────────
  const chartData = {
    labels: [`Benign: ${((summary.benign / summary.total) * 100).toFixed(1)}%`,
             `Suspicious: ${((summary.suspicious / summary.total) * 100).toFixed(1)}%`],
    datasets: [{
      data: [summary.benign, summary.suspicious],
      backgroundColor: ['#81C784', '#F48FB1'],
      borderColor:     ['#ffffff', '#ffffff'],
      borderWidth: 3,
    }],
  };
 
  return (
    <div className="results-page">
      <div className="results-header">
        <h2>Analysis Results</h2>
        <button className="new-btn" onClick={onReset}>New Analysis</button>
      </div>
 
      {/* Summary section */}
      <div className="summary-card">
        <div className="chart-area">
          <Doughnut data={chartData} />
        </div>
        <div className="metric-cards">
          <div className="metric">
            <span className="label">Total Queries</span>
            <span className="value">{summary.total.toLocaleString()}</span>
          </div>
          <div className="metric suspicious">
            <span className="label">Suspicious Queries</span>
            <span className="value">{summary.suspicious.toLocaleString()}</span>
          </div>
          <div className="metric benign">
            <span className="label">Benign Queries</span>
            <span className="value">{summary.benign.toLocaleString()}</span>
          </div>
          <div className="metric">
            <span className="label">Suspicious Rate</span>
            <span className="value">
              {((summary.suspicious / summary.total) * 100).toFixed(1)}%
            </span>
          </div>
        </div>
      </div>
 
      {/* Detailed table */}
      <div className="table-section">
        <h3>Detailed Query Results</h3>
        <div className="table-controls">
          <input
            placeholder="Search by domain..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
          <div className="filter-btns">
            {['all', 'suspicious', 'benign'].map(f => (
              <button
                key={f}
                className={filter === f ? 'active' : ''}
                onClick={() => setFilter(f)}
              >
                {f.charAt(0).toUpperCase() + f.slice(1)}
              </button>
            ))}
          </div>
        </div>
 
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Domain Name</th>
              <th>Length</th>
              <th>Entropy</th>
              <th>Classification</th>
              <th>Confidence</th>
            </tr>
          </thead>
          <tbody>
            {displayed.map(r => (
              <tr key={r.id} className={r.label === 'Suspicious' ? 'row-sus' : ''}>
                <td>{r.id}</td>
                <td>{r.query || '—'}</td>
                <td>{r.subdomain_length}</td>
                <td>{typeof r.entropy === 'number' ? r.entropy.toFixed(3) : r.entropy}</td>
                <td>
                  <span className={`badge ${r.label === 'Suspicious' ? 'badge-sus' : 'badge-ok'}`}>
                    {r.label}
                  </span>
                </td>
                <td>
                  <div className="conf-bar">
                    <div className="conf-fill"
                         style={{ width: `${r.confidence}%`,
                                  background: r.label === 'Suspicious' ? '#e91e63' : '#4caf50' }} />
                    <span>{r.confidence}%</span>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
