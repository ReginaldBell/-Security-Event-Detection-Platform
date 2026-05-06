import React, { useCallback, useEffect, useState } from 'react';
import { Play, RefreshCw } from 'lucide-react';

const API_BASE = window.location.origin;

const KNOWN_SCENARIOS = [
  { id: 'password_spray', label: 'Password Spray', type: 'attack' },
  { id: 'normal_login_activity', label: 'Normal Activity', type: 'benign' },
];

function StatusBadge({ status }) {
  const styles = {
    pass: 'bg-green-600 text-white',
    fail: 'bg-red-600 text-white',
    false_positive: 'bg-orange-500 text-white',
  };
  const labels = {
    pass: 'PASS',
    fail: 'FAIL',
    false_positive: 'FALSE POSITIVE',
  };
  return (
    <span className={`px-2 py-0.5 text-[10px] font-semibold ${styles[status] ?? styles.fail}`}>
      {labels[status] ?? (status ?? 'fail').toUpperCase()}
    </span>
  );
}

function DetectedCell({ detected, isBenign, falsePositive }) {
  if (isBenign) {
    return falsePositive
      ? <span className="text-orange-500 font-bold text-[11px]">FP</span>
      : <span className="text-green-600 font-bold">✔</span>;
  }
  return detected
    ? <span className="text-green-600 font-bold">✔</span>
    : <span className="text-red-500 font-bold">✖</span>;
}

function MitreCoveragePanel({ coverage }) {
  const entries = Object.entries(coverage);
  if (entries.length === 0) return null;

  return (
    <div>
      <div className="text-xs font-semibold text-gray-700 mb-2 uppercase tracking-wide">
        MITRE ATT&CK Coverage
      </div>
      <div className="flex flex-wrap gap-3">
        {entries.map(([technique, data]) => {
          const pct = data.success_rate ?? 0;
          const barColor = pct === 100
            ? 'bg-green-500'
            : pct > 0
              ? 'bg-yellow-400'
              : 'bg-red-500';
          const labelColor = pct === 100
            ? 'text-green-700'
            : pct > 0
              ? 'text-yellow-700'
              : 'text-red-600';
          return (
            <div key={technique} className="border border-gray-200 bg-white rounded px-3 py-2 min-w-[180px] text-xs">
              <div className="flex items-center justify-between mb-1">
                <span className="font-mono font-semibold text-gray-800">{technique}</span>
                <span className={`font-semibold ${labelColor}`}>{pct}%</span>
              </div>
              <div className="h-1.5 w-full bg-gray-200 rounded overflow-hidden">
                <div className={`h-full rounded ${barColor} transition-all`} style={{ width: `${pct}%` }} />
              </div>
              <div className="mt-1 text-gray-400 text-[10px]">
                {data.detected}/{data.tested} runs detected
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default function DetectionQualityTable() {
  const [results, setResults] = useState([]);
  const [coverage, setCoverage] = useState({});
  const [running, setRunning] = useState('');
  const [error, setError] = useState('');

  const fetchResults = useCallback(async () => {
    try {
      const [resultsRes, coverageRes] = await Promise.all([
        fetch(`${API_BASE}/validate/results`),
        fetch(`${API_BASE}/validate/results/mitre-coverage`),
      ]);
      if (!resultsRes.ok) throw new Error('Failed to load validation results');
      const data = await resultsRes.json();
      setResults(Array.isArray(data) ? [...data].reverse() : []);
      if (coverageRes.ok) setCoverage(await coverageRes.json());
    } catch (e) {
      setError(e.message);
    }
  }, []);

  useEffect(() => { fetchResults(); }, [fetchResults]);

  const runScenario = async (scenarioId) => {
    setRunning(scenarioId);
    setError('');
    try {
      const res = await fetch(`${API_BASE}/validate/${scenarioId}`, { method: 'POST' });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || 'Scenario run failed');
      }
      await fetchResults();
    } catch (e) {
      setError(`Run failed: ${e.message}`);
    } finally {
      setRunning('');
    }
  };

  return (
    <div className="flex flex-col gap-4 p-4">

      {/* ── Run controls ────────────────────────────────────── */}
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-xs font-semibold text-gray-700">Run Scenario:</span>
        {KNOWN_SCENARIOS.map(({ id, label, type }) => (
          <button
            key={id}
            type="button"
            disabled={!!running}
            onClick={() => runScenario(id)}
            className={`flex items-center gap-1 px-2 py-1 text-xs border disabled:text-gray-400 hover:bg-gray-50 ${
              type === 'benign'
                ? 'border-gray-300 bg-gray-50 text-gray-600'
                : 'border-gray-300 bg-white'
            }`}
          >
            <Play className="w-3 h-3" />
            {running === id ? 'Running…' : label}
            {type === 'benign' && (
              <span className="ml-1 px-1 text-[9px] bg-gray-200 text-gray-500 rounded">benign</span>
            )}
          </button>
        ))}
        <button
          type="button"
          onClick={fetchResults}
          className="ml-auto flex items-center gap-1 px-2 py-1 text-xs border border-gray-300 bg-white hover:bg-gray-50"
        >
          <RefreshCw className="w-3 h-3" />
          Refresh
        </button>
      </div>

      {error && (
        <div className="text-xs text-red-700 bg-red-50 border border-red-200 px-3 py-2">{error}</div>
      )}

      {/* ── MITRE Coverage ───────────────────────────────────── */}
      <MitreCoveragePanel coverage={coverage} />

      {/* ── Results table ───────────────────────────────────── */}
      <table className="w-full text-xs">
        <thead className="bg-gray-100 border-b border-gray-300 sticky top-0">
          <tr>
            <th className="px-2 py-2 text-left">Scenario</th>
            <th className="px-2 py-2 text-left">MITRE</th>
            <th className="px-2 py-2 text-left">Expected</th>
            <th className="px-2 py-2 text-center">Detected</th>
            <th className="px-2 py-2 text-right">Latency</th>
            <th className="px-2 py-2 text-right">Score</th>
            <th className="px-2 py-2 text-left">Validation</th>
            <th className="px-2 py-2 text-left">Run At</th>
          </tr>
        </thead>
        <tbody>
          {results.length === 0 ? (
            <tr>
              <td colSpan={8} className="px-3 py-8 text-center text-gray-500">
                No validation results yet. Run a scenario above.
              </td>
            </tr>
          ) : (
            results.map((r, i) => {
              const isBenign = r.validation?.expected == null;
              const fp = r.validation?.false_positive ?? false;
              const mitre = r.mitre;
              const technique = typeof mitre === 'object' && mitre !== null
                ? mitre.technique
                : (mitre ?? null);
              const tactic = typeof mitre === 'object' && mitre !== null
                ? mitre.tactic
                : null;

              return (
                <tr
                  key={i}
                  className={`border-b border-gray-200 hover:bg-gray-50 ${fp ? 'bg-orange-50' : ''}`}
                >
                  {/* Scenario name + ID */}
                  <td className="px-2 py-2">
                    <div className="font-semibold text-gray-800">
                      {r.scenario_name || r.scenario}
                    </div>
                    {r.scenario_name && (
                      <div className="font-mono text-[10px] text-gray-400">{r.scenario}</div>
                    )}
                  </td>

                  {/* MITRE technique + tactic */}
                  <td className="px-2 py-2">
                    {technique ? (
                      <>
                        <div className="font-mono text-gray-700">{technique}</div>
                        {tactic && <div className="text-[10px] text-gray-400">{tactic}</div>}
                      </>
                    ) : (
                      <span className="text-gray-300 italic text-[10px]">—</span>
                    )}
                  </td>

                  {/* Expected detection */}
                  <td className="px-2 py-2 font-mono">
                    {isBenign
                      ? <span className="italic text-gray-400">benign</span>
                      : (r.validation?.expected ?? '—')}
                  </td>

                  {/* Detected indicator */}
                  <td className="px-2 py-2 text-center">
                    <DetectedCell
                      detected={r.validation?.detected}
                      isBenign={isBenign}
                      falsePositive={fp}
                    />
                  </td>

                  {/* Latency */}
                  <td className="px-2 py-2 text-right font-mono">
                    {r.latency_seconds != null ? (
                      <span className={
                        r.latency_seconds < 2 ? 'text-green-600 font-semibold' :
                        r.latency_seconds < 10 ? 'text-yellow-600' :
                        'text-red-600'
                      }>
                        {r.latency_seconds.toFixed(2)}s
                      </span>
                    ) : '—'}
                  </td>

                  {/* Score */}
                  <td className="px-2 py-2 text-right font-mono font-semibold">
                    {r.score?.score ?? 0}
                  </td>

                  {/* Validation badge */}
                  <td className="px-2 py-2">
                    <StatusBadge status={r.score?.status ?? 'fail'} />
                  </td>

                  {/* Run timestamp */}
                  <td className="px-2 py-2 font-mono text-gray-500">
                    {r.run_at ? r.run_at.replace('T', ' ').slice(0, 19) : '—'}
                  </td>
                </tr>
              );
            })
          )}
        </tbody>
      </table>
    </div>
  );
}
