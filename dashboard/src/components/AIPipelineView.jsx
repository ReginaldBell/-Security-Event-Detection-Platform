import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ChevronRight, Play, RefreshCw, Zap } from 'lucide-react';

const API_BASE = window.location.origin;
const WS_URL = `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/ai-pipeline/ws`;
const MODE_ORDER = { OFF: 0, PARTIAL: 1, FULL: 2 };

const RISK_COLORS = (score) => {
  if (score >= 80) return 'bg-red-600 text-white';
  if (score >= 60) return 'bg-orange-500 text-white';
  if (score >= 40) return 'bg-yellow-400 text-black';
  return 'bg-green-500 text-white';
};

const ACTION_STYLES = {
  block: 'bg-red-600 text-white',
  redact: 'bg-orange-500 text-white',
  warn: 'bg-yellow-400 text-black',
  allow: 'bg-green-600 text-white',
  alert_only: 'bg-blue-500 text-white',
};

const LAYER_STYLES = {
  dlp: 'bg-purple-100 border border-purple-300 text-purple-800',
  pattern: 'bg-blue-100 border border-blue-300 text-blue-800',
  semantic: 'bg-indigo-100 border border-indigo-300 text-indigo-800',
};

const MODE_STYLES = {
  OFF: 'bg-gray-100 border border-gray-300 text-gray-600',
  PARTIAL: 'bg-yellow-50 border border-yellow-300 text-yellow-800',
  FULL: 'bg-green-50 border border-green-300 text-green-800',
};

function RiskBadge({ score }) {
  return (
    <span className={`inline-flex min-w-[36px] justify-center px-1.5 py-0.5 font-mono text-[11px] font-semibold rounded ${RISK_COLORS(score)}`}>
      {score}
    </span>
  );
}

function ActionBadge({ action }) {
  const label = (action ?? 'allow').toUpperCase();
  const style = ACTION_STYLES[(action ?? 'allow').toLowerCase()] ?? ACTION_STYLES.allow;
  return <span className={`px-2 py-0.5 text-[10px] font-semibold ${style}`}>{label}</span>;
}

function LayerBadge({ layer }) {
  if (!layer) return <span className="text-gray-300 text-[10px]">—</span>;
  const style = LAYER_STYLES[layer] ?? 'bg-gray-100 border border-gray-200 text-gray-600';
  return <span className={`px-1.5 py-0.5 text-[10px] font-mono rounded ${style}`}>{layer}</span>;
}

function ModeBadge({ mode }) {
  const style = MODE_STYLES[mode] ?? MODE_STYLES.OFF;
  return <span className={`px-1.5 py-0.5 text-[10px] font-mono rounded ${style}`}>{mode}</span>;
}

function SummaryCards({ results }) {
  const total = results.length;
  const detected = results.filter((r) => r.detected).length;
  const succeeded = results.filter((r) => r.success).length;
  const missed = results.filter((r) => r.success && !r.detected).length;
  const blocked = results.filter((r) => r.risk_action === 'block').length;
  const incidents = results.filter((r) => r.incident_id).length;

  const cards = [
    { label: 'Total Runs', value: total, color: 'text-gray-800' },
    { label: 'Attack Succeeded', value: succeeded, color: 'text-red-600' },
    { label: 'Detected', value: detected, color: 'text-green-700' },
    { label: 'Missed', value: missed, color: 'text-red-700' },
    { label: 'Blocked', value: blocked, color: 'text-orange-700' },
    { label: 'Incidents Created', value: incidents, color: 'text-purple-700' },
  ];

  return (
    <div className="flex flex-wrap gap-3">
      {cards.map(({ label, value, color }) => (
        <div key={label} className="border border-gray-200 bg-white rounded px-4 py-2 min-w-[120px]">
          <div className="text-[10px] text-gray-500 uppercase tracking-wide">{label}</div>
          <div className={`text-xl font-bold font-mono mt-0.5 ${color}`}>{value}</div>
        </div>
      ))}
    </div>
  );
}

function DLPFindingsList({ findings }) {
  if (!findings?.length) return <span className="text-gray-400 text-[11px]">none</span>;
  return (
    <div className="flex flex-col gap-1">
      {findings.map((f, i) => (
        <div key={i} className="flex items-center gap-2 text-[11px]">
          <span className="font-mono text-gray-600">{f.finding_type}</span>
          <span className={`px-1 py-0.5 text-[9px] font-semibold rounded ${
            f.severity === 'critical' ? 'bg-red-100 text-red-700' :
            f.severity === 'high' ? 'bg-orange-100 text-orange-700' :
            'bg-yellow-100 text-yellow-700'
          }`}>{f.severity}</span>
          <span className="text-gray-400">{(f.confidence * 100).toFixed(0)}%</span>
          <span className="font-mono text-gray-400 text-[10px]">sha:{f.sha256_prefix}</span>
        </div>
      ))}
    </div>
  );
}

function ExpandedDetail({ result }) {
  return (
    <div className="px-4 py-3 grid grid-cols-1 gap-3 md:grid-cols-2">
      <div className="rounded border border-gray-200 bg-white p-3">
        <div className="text-[11px] font-semibold uppercase tracking-wide text-gray-600 mb-2">Response</div>
        <pre className="text-[11px] font-mono overflow-auto max-h-32 whitespace-pre-wrap text-gray-800 bg-gray-50 border border-gray-200 p-2 rounded">
          {result.response || '(empty)'}
        </pre>
      </div>
      <div className="rounded border border-gray-200 bg-white p-3 flex flex-col gap-2">
        <div className="text-[11px] font-semibold uppercase tracking-wide text-gray-600 mb-1">Detection Detail</div>
        <div className="text-[11px] grid grid-cols-2 gap-x-4 gap-y-1">
          <span className="text-gray-500">Detection Reason</span>
          <span className="font-mono text-gray-800">{result.detection_reason || '—'}</span>
          <span className="text-gray-500">Layers Hit</span>
          <span className="flex flex-wrap gap-1">
            {result.detection_layers?.length
              ? result.detection_layers.map((l) => <LayerBadge key={l} layer={l} />)
              : <span className="text-gray-300">none</span>}
          </span>
          <span className="text-gray-500">Combined Detection</span>
          <span className={result.combined_detection ? 'text-orange-600 font-semibold' : 'text-gray-400'}>
            {result.combined_detection ? 'YES' : 'no'}
          </span>
          <span className="text-gray-500">Latency</span>
          <span className="font-mono">{result.latency_ms?.toFixed(1)} ms</span>
        </div>
        <div className="mt-1">
          <div className="text-[11px] text-gray-500 mb-1">DLP Findings</div>
          <DLPFindingsList findings={result.dlp_findings} />
        </div>
      </div>
    </div>
  );
}

export default function AIPipelineView({ onNavigate }) {
  const [results, setResults] = useState([]);
  const [running, setRunning] = useState(false);
  const [streaming, setStreaming] = useState(false);
  const [llmMode, setLlmMode] = useState('mock');
  const [secMode, setSecMode] = useState('');
  const [expandedKey, setExpandedKey] = useState('');
  const [collapsedGroups, setCollapsedGroups] = useState(new Set());
  const [error, setError] = useState('');
  const [filterMode, setFilterMode] = useState('');
  const [filterAction, setFilterAction] = useState('');
  const [dceChains, setDceChains] = useState([]);
  const wsRef = useRef(null);

  const connectWs = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;
    const ws = new WebSocket(WS_URL);
    ws.onmessage = (evt) => {
      try {
        const data = JSON.parse(evt.data);
        if (data.event_type === 'ai_pipeline_result' && data.result) {
          setResults((prev) => {
            const key = `${data.result.attack}|${data.result.mode}`;
            const exists = prev.findIndex((r) => `${r.attack}|${r.mode}` === key);
            if (exists >= 0) {
              const next = [...prev];
              next[exists] = data.result;
              return next;
            }
            return [...prev, data.result];
          });
        }
      } catch {
        // Ignore malformed streaming payloads; the next valid event will update the view.
      }
    };
    ws.onopen = () => setStreaming(true);
    ws.onclose = () => setStreaming(false);
    wsRef.current = ws;
  }, []);

  const fetchLatest = useCallback(async () => {
    try {
      const [pipelineRes, chainsRes] = await Promise.all([
        fetch(`${API_BASE}/ai-pipeline/results`),
        fetch(`${API_BASE}/dce/chains`),
      ]);
      if (!pipelineRes.ok) throw new Error('Failed to load AI pipeline results');
      const data = await pipelineRes.json();
      setResults(Array.isArray(data.results) ? data.results : []);
      setDceChains(chainsRes.ok ? await chainsRes.json() : []);
      setError('');
    } catch (e) {
      setError(e.message);
    }
  }, []);

  useEffect(() => {
    connectWs();
    fetchLatest();
    return () => wsRef.current?.close();
  }, [connectWs, fetchLatest]);

  const runPipeline = async () => {
    setRunning(true);
    setError('');
    setResults([]);
    setCollapsedGroups(new Set());
    connectWs();
    try {
      const body = { mode: llmMode };
      if (secMode) body.security = secMode;
      const res = await fetch(`${API_BASE}/ai-pipeline/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || 'Run failed');
      }
      const data = await res.json();
      setResults(Array.isArray(data.results) ? data.results : []);
    } catch (e) {
      setError(e.message);
    } finally {
      setRunning(false);
    }
  };

  const filtered = results.filter((r) => {
    if (filterMode && r.mode !== filterMode) return false;
    if (filterAction && r.risk_action !== filterAction) return false;
    return true;
  });

  // Group by attack type, sort modes OFF → PARTIAL → FULL within each group
  const grouped = useMemo(() => {
    const map = new Map();
    filtered.forEach((r) => {
      if (!map.has(r.attack)) map.set(r.attack, []);
      map.get(r.attack).push(r);
    });
    for (const rows of map.values()) {
      rows.sort((a, b) => (MODE_ORDER[a.mode] ?? 9) - (MODE_ORDER[b.mode] ?? 9));
    }
    return [...map.entries()].sort(([a], [b]) => a.localeCompare(b));
  }, [filtered]);

  const toggleGroup = (attack) => setCollapsedGroups((prev) => {
    const next = new Set(prev);
    next.has(attack) ? next.delete(attack) : next.add(attack);
    return next;
  });

  const rowKey = (r) => `${r.attack}|${r.mode}`;
  const COL_COUNT = 10;

  return (
    <div className="flex flex-col gap-4 p-4">

      {/* Controls */}
      <div className="flex flex-wrap items-center gap-2">
        <Zap className="w-4 h-4 text-indigo-600" />
        <span className="text-xs font-semibold text-gray-700">LLM Mode:</span>
        <select className="text-xs border border-gray-300 px-2 py-1 bg-white" value={llmMode} onChange={(e) => setLlmMode(e.target.value)} disabled={running}>
          <option value="mock">Mock</option>
          <option value="live">Live (requires ANTHROPIC_API_KEY)</option>
        </select>
        <span className="text-xs font-semibold text-gray-700">Security Mode:</span>
        <select className="text-xs border border-gray-300 px-2 py-1 bg-white" value={secMode} onChange={(e) => setSecMode(e.target.value)} disabled={running}>
          <option value="">All Modes (OFF + PARTIAL + FULL)</option>
          <option value="OFF">OFF</option>
          <option value="PARTIAL">PARTIAL</option>
          <option value="FULL">FULL</option>
        </select>
        <button type="button" disabled={running} onClick={runPipeline} className="flex items-center gap-1 px-3 py-1 text-xs bg-indigo-600 text-white disabled:bg-gray-400 hover:bg-indigo-700">
          <Play className="w-3 h-3" />
          {running ? 'Running…' : '▶ Run Pipeline'}
        </button>
        <button type="button" onClick={fetchLatest} disabled={running} className="flex items-center gap-1 px-2 py-1 text-xs border border-gray-300 bg-white hover:bg-gray-50 disabled:text-gray-400">
          <RefreshCw className="w-3 h-3" />
          Refresh
        </button>
        <div className={`ml-auto flex items-center gap-1 text-[11px] ${streaming ? 'text-green-600' : 'text-gray-400'}`}>
          <span className={`w-1.5 h-1.5 rounded-full ${streaming ? 'bg-green-500 animate-pulse' : 'bg-gray-300'}`} />
          {streaming ? 'Live' : 'Disconnected'}
        </div>
      </div>

      {error && <div className="text-xs text-red-700 bg-red-50 border border-red-200 px-3 py-2">{error}</div>}

      {results.length > 0 && <SummaryCards results={results} />}

      {results.length > 0 && (
        <div className="flex items-center gap-2">
          <span className="text-[11px] text-gray-500">Filter:</span>
          <select className="text-xs border border-gray-300 px-2 py-1 bg-white" value={filterMode} onChange={(e) => setFilterMode(e.target.value)}>
            <option value="">All security modes</option>
            <option value="OFF">OFF</option>
            <option value="PARTIAL">PARTIAL</option>
            <option value="FULL">FULL</option>
          </select>
          <select className="text-xs border border-gray-300 px-2 py-1 bg-white" value={filterAction} onChange={(e) => setFilterAction(e.target.value)}>
            <option value="">All actions</option>
            <option value="block">BLOCK</option>
            <option value="redact">REDACT</option>
            <option value="warn">WARN</option>
            <option value="allow">ALLOW</option>
          </select>
          <span className="text-[11px] text-gray-400">{filtered.length} of {results.length} rows</span>
        </div>
      )}

      {/* Results table — grouped by attack */}
      <table className="w-full text-xs">
        <thead className="bg-gray-100 border-b border-gray-300 sticky top-0 z-10">
          <tr>
            <th className="w-6 px-1 py-2" />
            <th className="px-2 py-2 text-left font-medium text-gray-500">Security Mode</th>
            <th className="px-2 py-2 text-center font-bold text-gray-900">Attack Success</th>
            <th className="px-2 py-2 text-center font-bold text-gray-900">Detection</th>
            <th className="px-2 py-2 text-left font-medium text-gray-500">Layer</th>
            <th className="px-2 py-2 text-right font-medium text-gray-500">Risk</th>
            <th className="px-2 py-2 text-left font-medium text-gray-500">Action</th>
            <th className="px-2 py-2 text-center font-medium text-gray-500">DLP Hits</th>
            <th className="px-2 py-2 text-right font-medium text-gray-500">Latency</th>
            <th className="px-2 py-2 text-left font-medium text-gray-500">Incident</th>
          </tr>
        </thead>
        <tbody>
          {grouped.length === 0 ? (
            <tr>
              <td colSpan={COL_COUNT} className="px-3 py-8 text-center text-gray-500">
                {running
                  ? 'Running AI pipeline — results will appear as each attack completes…'
                  : 'No results yet. Click ▶ Run Pipeline to start.'}
              </td>
            </tr>
          ) : (
            grouped.map(([attack, rows]) => {
              const isCollapsed = collapsedGroups.has(attack);
              const breaches = rows.filter((r) => r.success).length;
              const detections = rows.filter((r) => r.detected).length;
              const missed = rows.filter((r) => r.success && !r.detected).length;

              return (
                <React.Fragment key={attack}>
                  {/* Attack group header */}
                  <tr
                    className="bg-gray-800 hover:bg-gray-700 cursor-pointer select-none"
                    onClick={() => toggleGroup(attack)}
                  >
                    <td colSpan={COL_COUNT} className="px-3 py-2">
                      <div className="flex items-center gap-3">
                        <ChevronRight className={`w-3 h-3 text-gray-300 flex-shrink-0 transition-transform duration-200 ${isCollapsed ? '' : 'rotate-90'}`} />
                        <span className="font-mono font-semibold text-white">{attack}</span>
                        <span className="text-[10px] text-gray-400">{rows.length} mode{rows.length !== 1 ? 's' : ''}</span>
                        {missed > 0 && (
                          <span className="px-1.5 py-0.5 text-[10px] bg-red-600 text-white font-bold">
                            {missed} MISSED
                          </span>
                        )}
                        {breaches > 0 && missed === 0 && (
                          <span className="text-[10px] text-red-300">{breaches} breach{breaches > 1 ? 'es' : ''}</span>
                        )}
                        {detections > 0 && (
                          <span className="text-[10px] text-green-400">{detections} detected</span>
                        )}
                        {onNavigate && (
                          <button
                            type="button"
                            onClick={(e) => { e.stopPropagation(); onNavigate({ view: 'incidents', attackType: attack }); }}
                            className="ml-auto text-[10px] text-blue-300 hover:text-blue-200 hover:underline flex-shrink-0"
                          >
                            View in Registry →
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>

                  {/* Mode rows */}
                  {!isCollapsed && rows.map((r) => {
                    const key = rowKey(r);
                    const expanded = expandedKey === key;
                    const isMissed = r.success && !r.detected;
                    return (
                      <React.Fragment key={key}>
                        <tr
                          className={`border-b border-gray-200 hover:bg-blue-50 cursor-pointer transition-colors ${isMissed ? 'bg-red-50/40' : ''}`}
                          onClick={() => setExpandedKey(expanded ? '' : key)}
                        >
                          <td className="px-1 py-2 pl-5">
                            <button
                              type="button"
                              className="inline-flex h-5 w-5 items-center justify-center rounded border border-gray-200 bg-white text-gray-500 hover:bg-gray-100"
                              onClick={(e) => { e.stopPropagation(); setExpandedKey(expanded ? '' : key); }}
                              aria-label={expanded ? 'Collapse' : 'Expand'}
                            >
                              <ChevronRight className={`w-3 h-3 transition-transform duration-200 ${expanded ? 'rotate-90' : ''}`} />
                            </button>
                          </td>
                          <td className="px-2 py-2"><ModeBadge mode={r.mode} /></td>

                          {/* Attack Success — BREACHED = bad, BLOCKED = good */}
                          <td className="px-2 py-2 text-center">
                            {r.success
                              ? <span className="px-2 py-0.5 text-[10px] font-bold bg-red-600 text-white">BREACHED</span>
                              : <span className="px-2 py-0.5 text-[10px] font-bold bg-green-600 text-white">BLOCKED</span>}
                          </td>

                          {/* Detection Status — DETECTED = good, MISSED = bad */}
                          <td className="px-2 py-2 text-center">
                            {r.detected
                              ? <span className="px-2 py-0.5 text-[10px] font-bold bg-green-600 text-white">DETECTED</span>
                              : <span className="px-2 py-0.5 text-[10px] font-bold bg-red-500 text-white">MISSED</span>}
                          </td>

                          <td className="px-2 py-2"><LayerBadge layer={r.detection_layer} /></td>
                          <td className="px-2 py-2 text-right"><RiskBadge score={r.risk_score} /></td>
                          <td className="px-2 py-2"><ActionBadge action={r.risk_action} /></td>
                          <td className="px-2 py-2 text-center font-mono">
                            {r.dlp_finding_count > 0 ? (
                              <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                                r.dlp_max_severity === 'critical' ? 'bg-red-100 text-red-700' :
                                r.dlp_max_severity === 'high' ? 'bg-orange-100 text-orange-700' :
                                'bg-yellow-100 text-yellow-700'
                              }`}>
                                {r.dlp_finding_count} {r.dlp_max_severity}
                              </span>
                            ) : (
                              <span className="text-gray-300">—</span>
                            )}
                          </td>
                          <td className="px-2 py-2 text-right font-mono text-gray-500">
                            {r.latency_ms != null ? `${r.latency_ms.toFixed(0)}ms` : '—'}
                          </td>
                          <td className="px-2 py-2" onClick={(e) => e.stopPropagation()}>
                            {r.incident_id ? (
                              onNavigate ? (
                                <button
                                  type="button"
                                  onClick={() => onNavigate({ view: 'incidents', incidentId: r.incident_id })}
                                  className="font-mono text-[10px] text-purple-700 hover:underline"
                                  title="Open in Incident Registry"
                                >
                                  {r.incident_id.slice(0, 18)}…
                                </button>
                              ) : (
                                <span className="font-mono text-[10px] text-purple-700">{r.incident_id.slice(0, 18)}…</span>
                              )
                            ) : (
                              <span className="text-gray-300">—</span>
                            )}
                          </td>
                        </tr>

                        {/* Expanded detail */}
                        <tr className="bg-gray-50 border-b border-gray-200">
                          <td colSpan={COL_COUNT} className="p-0">
                            <div className={`grid transition-all duration-200 ${expanded ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0'}`}>
                              <div className="overflow-hidden">
                                <ExpandedDetail result={r} />
                              </div>
                            </div>
                          </td>
                        </tr>
                      </React.Fragment>
                    );
                  })}
                </React.Fragment>
              );
            })
          )}
        </tbody>
      </table>

      {running && (
        <div className="text-xs text-indigo-600 text-center py-2 animate-pulse">
          Pipeline running — {results.length} result{results.length !== 1 ? 's' : ''} received so far…
        </div>
      )}

      {/* DCE Attack Chain Audit Log */}
      {dceChains.length > 0 && (
        <div className="mt-4 border border-gray-200 rounded">
          <div className="px-4 py-2 border-b border-gray-200 bg-gray-50 flex items-center justify-between">
            <div className="text-xs font-semibold text-gray-700 uppercase tracking-wide">DCE Attack Chain Log</div>
            <span className="text-[10px] text-gray-400">{dceChains.length} chain{dceChains.length !== 1 ? 's' : ''} observed</span>
          </div>
          <div className="divide-y divide-gray-100">
            {dceChains.map((chain) => (
              <div key={chain.chain_id} className="px-4 py-3 flex flex-wrap items-start gap-4 text-xs">
                <div className="flex-1 min-w-[160px]">
                  <div className="font-mono text-[10px] text-gray-400 mb-0.5">Chain</div>
                  <div className="font-mono text-[11px] text-blue-700 break-all">{chain.chain_id}</div>
                </div>
                <div>
                  <div className="font-mono text-[10px] text-gray-400 mb-0.5">Stages</div>
                  <div className="flex gap-1">
                    {[1, 2, 3, 4].map((s) => (
                      <span
                        key={s}
                        className={`w-5 h-5 flex items-center justify-center rounded-full text-[10px] font-mono font-bold ${
                          (chain.stages_observed || []).includes(s)
                            ? 'bg-blue-600 text-white'
                            : 'bg-gray-100 text-gray-400'
                        }`}
                      >
                        {s}
                      </span>
                    ))}
                  </div>
                </div>
                <div>
                  <div className="font-mono text-[10px] text-gray-400 mb-0.5">Complete</div>
                  <span className={`px-2 py-0.5 text-[10px] font-semibold rounded ${chain.chain_complete ? 'bg-red-100 text-red-700' : 'bg-gray-100 text-gray-600'}`}>
                    {chain.chain_complete ? 'FULL CHAIN' : 'partial'}
                  </span>
                </div>
                <div>
                  <div className="font-mono text-[10px] text-gray-400 mb-0.5">Incidents</div>
                  <div className="text-[11px] font-mono text-gray-700">{(chain.incidents || []).length}</div>
                </div>
                <div>
                  <div className="font-mono text-[10px] text-gray-400 mb-0.5">Last Seen</div>
                  <div className="text-[10px] font-mono text-gray-500">{chain.last_seen?.replace('T', ' ').replace('Z', '') || '—'}</div>
                </div>
                {onNavigate && chain.incidents?.length > 0 && (
                  <div className="flex items-end">
                    <button
                      type="button"
                      onClick={() => onNavigate({ view: 'incidents', incidentId: chain.incidents[0] })}
                      className="text-[10px] text-blue-600 hover:underline"
                    >
                      view →
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
