import React, { useEffect, useRef, useState } from 'react';
import { RefreshCw } from 'lucide-react';

const API_BASE = window.location.origin;

const MITRE_LABELS = {
  'T1110': 'Brute Force',
  'T1110.001': 'Password Guessing',
  'T1110.003': 'Password Spraying',
  'T1021.002': 'SMB/Windows Admin Shares',
  'T1078': 'Valid Accounts',
  'T1566': 'Phishing',
};

function CoverageCard({ technique, data, isHighlighted, onNavigate, cardRef }) {
  const pct = data.success_rate ?? 0;
  const label = MITRE_LABELS[technique] ?? technique;
  const barColor = pct === 100 ? 'bg-green-500' : pct > 0 ? 'bg-yellow-400' : 'bg-red-500';
  const textColor = pct === 100 ? 'text-green-700' : pct > 0 ? 'text-yellow-600' : 'text-red-600';
  const bgColor = pct === 100 ? 'bg-green-50 border-green-200' : pct > 0 ? 'bg-yellow-50 border-yellow-200' : 'bg-red-50 border-red-200';

  return (
    <div
      ref={cardRef}
      className={`border rounded p-4 transition-all ${bgColor} ${isHighlighted ? 'ring-2 ring-blue-500 ring-offset-2' : ''}`}
    >
      <div className="flex items-start justify-between gap-2 mb-2">
        <div>
          <div className="font-mono font-semibold text-sm text-gray-800">{technique}</div>
          <div className="text-xs text-gray-500 mt-0.5">{label}</div>
        </div>
        <div className={`text-lg font-bold font-mono ${textColor}`}>{pct}%</div>
      </div>
      <div className="h-2 w-full bg-gray-200 rounded overflow-hidden mb-2">
        <div className={`h-full rounded ${barColor} transition-all duration-500`} style={{ width: `${pct}%` }} />
      </div>
      <div className="flex justify-between items-center text-[11px] text-gray-500">
        <span>{data.detected} detected of {data.tested} tested</span>
        {onNavigate && (
          <button
            type="button"
            onClick={() => onNavigate({ view: 'incidents', mitreTechnique: technique })}
            className="text-blue-600 hover:underline"
          >
            incidents →
          </button>
        )}
      </div>
    </div>
  );
}

export default function MitreCoverageView({ highlight, onNavigate }) {
  const [coverage, setCoverage] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const cardRefs = useRef({});

  const fetchCoverage = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`${API_BASE}/validate/results/mitre-coverage`);
      if (!res.ok) throw new Error('Failed to load MITRE coverage');
      setCoverage(await res.json());
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchCoverage(); }, []);

  useEffect(() => {
    if (highlight && cardRefs.current[highlight]) {
      cardRefs.current[highlight].scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  }, [highlight, coverage]);

  const entries = Object.entries(coverage);
  const totalTested = entries.length;
  const totalDetected = entries.filter(([, d]) => d.detected === d.tested && d.tested > 0).length;
  const avgRate = totalTested > 0
    ? Math.round(entries.reduce((sum, [, d]) => sum + (d.success_rate ?? 0), 0) / totalTested)
    : 0;

  // Sort worst-first so gaps are immediately visible
  const sorted = [...entries].sort((a, b) => (a[1].success_rate ?? 0) - (b[1].success_rate ?? 0));
  const weaknesses = sorted.filter(([, d]) => (d.success_rate ?? 0) < 100);

  return (
    <div className="p-4 flex flex-col gap-4">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <div className="text-sm font-semibold text-gray-800">MITRE ATT&amp;CK Coverage</div>
          <div className="text-xs text-gray-500 mt-0.5">Detection success rate per technique across all validation runs</div>
        </div>
        <button type="button" onClick={fetchCoverage} className="flex items-center gap-1 px-2 py-1 text-xs border border-gray-300 bg-white hover:bg-gray-50">
          <RefreshCw className="w-3 h-3" />
          Refresh
        </button>
      </div>

      {error && <div className="text-xs text-red-700 bg-red-50 border border-red-200 px-3 py-2">{error}</div>}

      {/* Summary KPIs */}
      {!loading && totalTested > 0 && (
        <div className="flex gap-4 flex-wrap border border-gray-200 bg-white rounded p-3 text-xs">
          <div>
            <div className="text-gray-500">Techniques Tested</div>
            <div className="font-mono font-semibold text-lg text-gray-800">{totalTested}</div>
          </div>
          <div>
            <div className="text-gray-500">Fully Detected</div>
            <div className="font-mono font-semibold text-lg text-green-700">{totalDetected}</div>
          </div>
          <div>
            <div className="text-gray-500">Avg Detection Rate</div>
            <div className={`font-mono font-semibold text-lg ${avgRate === 100 ? 'text-green-700' : avgRate >= 50 ? 'text-yellow-600' : 'text-red-600'}`}>
              {avgRate}%
            </div>
          </div>
          <div>
            <div className="text-gray-500">Detection Gaps</div>
            <div className={`font-mono font-semibold text-lg ${weaknesses.length > 0 ? 'text-red-600' : 'text-green-700'}`}>
              {weaknesses.length}
            </div>
          </div>
        </div>
      )}

      {/* Top Weaknesses callout */}
      {!loading && weaknesses.length > 0 && (
        <div className="border border-red-200 bg-red-50 rounded p-3">
          <div className="text-xs font-bold text-red-700 uppercase tracking-wide mb-3">Top Detection Gaps</div>
          <div className="flex flex-col gap-2">
            {weaknesses.map(([tech, data]) => {
              const pct = data.success_rate ?? 0;
              return (
                <div key={tech} className="flex items-center gap-3">
                  <span className="font-mono text-[11px] text-red-700 w-24 flex-shrink-0">{tech}</span>
                  <div className="flex-1 h-2.5 bg-red-100 rounded overflow-hidden">
                    <div
                      className={`h-full rounded transition-all duration-500 ${pct === 0 ? 'bg-red-600' : 'bg-orange-400'}`}
                      style={{ width: pct === 0 ? '100%' : `${pct}%` }}
                    />
                  </div>
                  <span className={`text-[11px] font-mono font-semibold w-8 text-right flex-shrink-0 ${pct === 0 ? 'text-red-600' : 'text-orange-600'}`}>{pct}%</span>
                  <span className="text-[10px] text-gray-500 hidden sm:block">{MITRE_LABELS[tech] ?? '—'}</span>
                  {onNavigate && (
                    <button
                      type="button"
                      onClick={() => onNavigate({ view: 'incidents', mitreTechnique: tech })}
                      className="ml-auto text-[10px] text-blue-600 hover:underline whitespace-nowrap flex-shrink-0"
                    >
                      view incidents →
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Coverage cards — sorted worst-first */}
      {loading ? (
        <div className="text-xs text-gray-400 py-8 text-center">Loading coverage data…</div>
      ) : entries.length === 0 ? (
        <div className="text-xs text-gray-500 py-8 text-center">
          No validation runs yet. Run scenarios from the Detection Quality tab first.
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {sorted.map(([technique, data]) => (
            <CoverageCard
              key={technique}
              technique={technique}
              data={data}
              isHighlighted={highlight === technique}
              onNavigate={onNavigate}
              cardRef={(el) => { cardRefs.current[technique] = el; }}
            />
          ))}
        </div>
      )}

      {/* Detail table */}
      {!loading && entries.length > 0 && (
        <div>
          <div className="text-xs font-semibold text-gray-700 mb-2 uppercase tracking-wide">Detail Table</div>
          <table className="w-full text-xs border border-gray-200">
            <thead className="bg-gray-100 border-b border-gray-200">
              <tr>
                <th className="px-3 py-2 text-left font-bold text-gray-900">Technique</th>
                <th className="px-3 py-2 text-left font-medium text-gray-500">Name</th>
                <th className="px-3 py-2 text-right font-medium text-gray-500">Tested</th>
                <th className="px-3 py-2 text-right font-medium text-gray-500">Detected</th>
                <th className="px-3 py-2 text-right font-bold text-gray-900">Detection Rate</th>
                {onNavigate && <th className="px-3 py-2" />}
              </tr>
            </thead>
            <tbody>
              {sorted.map(([tech, data]) => {
                const pct = data.success_rate ?? 0;
                const rateColor = pct === 100 ? 'text-green-700' : pct > 0 ? 'text-yellow-600' : 'text-red-600';
                return (
                  <tr key={tech} className={`border-b border-gray-200 hover:bg-gray-50 ${highlight === tech ? 'bg-blue-50' : ''}`}>
                    <td className="px-3 py-2 font-mono">{tech}</td>
                    <td className="px-3 py-2 text-gray-600">{MITRE_LABELS[tech] ?? '—'}</td>
                    <td className="px-3 py-2 text-right font-mono">{data.tested}</td>
                    <td className="px-3 py-2 text-right font-mono">{data.detected}</td>
                    <td className={`px-3 py-2 text-right font-mono font-semibold ${rateColor}`}>{pct}%</td>
                    {onNavigate && (
                      <td className="px-3 py-2 text-right">
                        <button
                          type="button"
                          onClick={() => onNavigate({ view: 'incidents', mitreTechnique: tech })}
                          className="text-[10px] text-blue-600 hover:underline"
                        >
                          incidents →
                        </button>
                      </td>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
