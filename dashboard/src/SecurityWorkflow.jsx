import React, { useEffect, useMemo, useRef, useState } from 'react';
import { AlertTriangle, ChevronRight, ExternalLink, Filter, Search, Upload, X } from 'lucide-react';
import securewatchLogo from './images/Securewatch.png';
import DetectionQualityTable from './components/DetectionQualityTable';
import MitreCoverageView from './components/MitreCoverageView';
import AIPipelineView from './components/AIPipelineView';

const API_BASE = window.location.origin;

const STATUS_BADGES = {
  open: 'bg-green-600 text-white',
  acknowledged: 'bg-yellow-500 text-black',
  escalated: 'bg-orange-600 text-white',
  closed: 'bg-gray-500 text-white'
};

const SEVERITY_COLORS = {
  critical: 'bg-red-700 text-white',
  high: 'bg-red-500 text-white',
  medium: 'bg-orange-500 text-white',
  low: 'bg-sky-500 text-white'
};

const TYPE_LABELS = {
  brute_force: 'Brute Force',
  credential_abuse: 'Credential Abuse'
};

const PIVOT_SUGGESTIONS = {
  brute_force: [
    'Search successful logins from same IP within +1h window',
    'Check lateral movement from source after lockout',
    'Review all accounts targeted by this IP',
    'Correlate with off-hours activity patterns'
  ],
  credential_abuse: [
    'Check MFA bypass attempts for this account',
    'Review privilege escalation following successful auth',
    'Audit resources accessed post-login',
    'Look for account creation events from same session'
  ]
};

const defaultMitreMapping = (incidentType, mitreTechnique) => {
  if (incidentType === 'credential_abuse') {
    return { tactic: 'Credential Access', technique: 'T1110.003', technique_name: 'Password Spraying' };
  }
  return { tactic: 'Credential Access', technique: mitreTechnique || 'T1110', technique_name: 'Brute Force' };
};

const SAMPLE_DATASETS = [
  { value: 'fixtures/sample-bruteforce.json', label: 'Brute Force Sample' },
  { value: 'fixtures/sample-credential-abuse.json', label: 'Credential Abuse Sample' },
  { value: 'fixtures/sample-mixed-noise.json', label: 'Mixed Noise Sample' }
];

const VALIDATION_SCENARIOS = [
  { id: 'password_spray', label: 'Password Spray' },
  { id: 'normal_login_activity', label: 'Normal Activity (Benign)' },
];

const BOOT_LOADING_MIN_MS = 3200;
const BOOT_FADE_OUT_MS = 700;

const LOADING_STAGES = [
  'Initializing telemetry ingestion',
  'Loading MITRE correlation models',
  'Syncing incident registry',
  'Hydrating entity risk graph',
  'Validating telemetry channels',
  'Preparing analyst workspace'
];

const LogoIdentity = ({ compact = false }) => (
  <div className={`flex items-center ${compact ? 'gap-3' : 'gap-3.5'} min-w-0`}>
    <img
      src={securewatchLogo}
      alt="SecureWatch Engine logo"
      className={`${compact ? 'w-14 h-14' : 'w-[60px] h-[60px]'} object-contain rounded-xl flex-shrink-0`}
    />
    <div className="min-w-0">
      <div className={`${compact ? 'text-base' : 'text-lg'} font-semibold leading-tight text-gray-900 whitespace-nowrap`}>
        SecureWatch Engine
      </div>
      <div className={`${compact ? 'text-[11px]' : 'text-xs'} leading-snug text-gray-500 whitespace-nowrap`}>
        Detection &amp; Incident Platform
      </div>
    </div>
  </div>
);

const AppLoadingState = ({ fadeOut = false, stage = LOADING_STAGES[0] }) => (
  <div className={`securewatch-loader ${fadeOut ? 'fade-out' : ''} min-h-screen flex items-center justify-center px-6 py-10`}>
    <div className="securewatch-loader-grid" aria-hidden="true" />
    <div className="relative w-full max-w-[480px] text-center">
      <div className="relative mx-auto h-60 w-60 sm:h-72 sm:w-72">
        <div className="securewatch-loader-orbit securewatch-loader-orbit-outer" aria-hidden="true" />
        <div className="securewatch-loader-orbit securewatch-loader-orbit-inner" aria-hidden="true" />
        <div className="securewatch-loader-sweep" aria-hidden="true" />
        <div className="securewatch-loader-scanline" aria-hidden="true" />
        <div className="securewatch-loader-logo-frame absolute inset-[46px] sm:inset-[54px] flex items-center justify-center rounded-[22px] border border-cyan-200/20 bg-white shadow-[0_0_44px_rgba(34,211,238,0.24)]">
          <img
            src={securewatchLogo}
            alt="SecureWatch Engine logo"
            className="securewatch-loader-logo h-32 w-32 sm:h-40 sm:w-40 object-contain"
          />
        </div>
      </div>

      <div className="mt-7 space-y-5">
        <div>
          <div className="text-[11px] font-semibold uppercase text-cyan-300">SecureWatch Engine</div>
          <div className="mt-1 text-xl font-semibold text-white">Initializing detection workspace</div>
          <div key={stage} className="securewatch-loader-stage mt-2 text-sm text-slate-300">
            {stage}
          </div>
        </div>

        <div className="mx-auto max-w-sm space-y-3">
          <div className="securewatch-loader-progress h-1 overflow-hidden rounded-full bg-slate-800" aria-hidden="true">
            <div className="h-full rounded-full" />
          </div>
          <div className="grid grid-cols-3 gap-2 text-[11px] text-slate-400">
            {['Telemetry', 'Correlation', 'Response'].map((label, index) => (
              <div key={label} className="flex items-center justify-center gap-1.5">
                <span className={`securewatch-loader-dot securewatch-loader-dot-${index + 1}`} />
                <span>{label}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  </div>
);

const SEVERITY_WEIGHTS = { critical: 4, high: 3, medium: 2, low: 1 };

const normalizeSeverity = (value) => (typeof value === 'string' ? value.toLowerCase() : '');
const formatTimestamp = (value) => (typeof value === 'string' ? value.replace('T', ' ').replace('Z', '') : '');
const toTimestampMs = (value) => {
  if (typeof value !== 'string' || !value) return 0;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? 0 : parsed;
};
const formatUtcTimestamp = (value) => {
  if (typeof value !== 'string' || !value) return 'N/A';
  const parsed = toTimestampMs(value);
  if (!parsed) return formatTimestamp(value);
  return new Date(parsed).toISOString().replace('T', ' ').replace('Z', ' UTC');
};
const formatConfidencePercent = (value) => {
  const num = Number(value);
  return Number.isFinite(num) ? `${(num * 100).toFixed(0)}%` : '0%';
};
const formatDuration = (seconds) => {
  const total = Number(seconds);
  if (!Number.isFinite(total) || total < 0) return 'N/A';
  if (total < 60) return `${Math.floor(total)}s`;
  const minutes = Math.floor(total / 60);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours}h ${minutes % 60}m`;
  const days = Math.floor(hours / 24);
  return `${days}d ${hours % 24}h`;
};
const safe = (v) => `"${String(v).replace(/"/g, '')}"`;
const hasPivotValue = (v) => v != null && String(v).trim() !== '' && String(v).trim().toLowerCase() !== 'unknown';
const buildPivotQueries = (incident) => [
  hasPivotValue(incident.subject?.username) && `search user=${safe(incident.subject.username)}`,
  hasPivotValue(incident.subject?.source_ip) && `search src=${safe(incident.subject.source_ip)}`,
  hasPivotValue(incident.dest) && `search dest=${safe(incident.dest)}`
].filter(Boolean);
const copyToClipboard = async (value) => {
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    window.prompt('Copy pivot query:', value);
  }
};
const setDashboardRoute = (params) => {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value) query.set(key, value);
  });
  window.history.pushState({}, '', `/?${query.toString()}`);
};

const computeRollingRiskScore = (entityIncidents) => {
  if (!Array.isArray(entityIncidents) || entityIncidents.length === 0) return 0;
  const nowMs = Date.now();
  const rawScore = entityIncidents.reduce((total, inc) => {
    const confidence = Number(inc.confidence);
    const confidenceWeight = Number.isFinite(confidence) ? Math.min(Math.max(confidence, 0), 1) : 0;
    const severityWeight = SEVERITY_WEIGHTS[inc.severity] || 1;
    const statusWeight = inc.status === 'open' ? 1.3 : inc.status === 'escalated' ? 1.2 : inc.status === 'acknowledged' ? 1 : 0.6;
    const seenMs = toTimestampMs(inc.last_seen || inc.first_seen || inc.timestamp);
    const ageHours = seenMs > 0 ? Math.max(0, (nowMs - seenMs) / 3600000) : 0;
    const decay = Math.exp(-ageHours / (24 * 7));
    return total + (confidenceWeight * severityWeight * statusWeight * decay);
  }, 0);
  return Math.min(100, Math.round(rawScore * 30));
};

const getSeverityMismatch = (inc) => {
  const conf = Number(inc.confidence);
  if (!Number.isFinite(conf)) return null;
  if ((inc.severity === 'high' || inc.severity === 'critical') && conf < 0.5) return 'High sev, low confidence';
  if (inc.severity === 'low' && conf > 0.85) return 'Low sev, high confidence';
  return null;
};

const formatSignals = (explanation) => {
  const obs = explanation?.observed;
  const thr = explanation?.threshold;
  const win = explanation?.window;
  if (obs == null && thr == null) return '—';
  return `${obs ?? '?'}/${thr ?? '?'}${win ? ` (${win})` : ''}`;
};

const ATTACK_CHAIN = [
  { technique: 'T1110', label: 'Credential attack', state: 'active' },
  { technique: 'T1078', label: 'Valid account use', state: 'hunt' },
  { technique: 'T1021', label: 'Remote services', state: 'hunt' }
];

const getChainStage = (inc) => {
  const technique = inc.mitre?.technique === 'T1110.003' ? 'T1110' : inc.mitre?.technique;
  const index = Math.max(ATTACK_CHAIN.findIndex((step) => step.technique === technique), 0);
  return {
    stage: index + 1,
    total: ATTACK_CHAIN.length,
    next: ATTACK_CHAIN[index + 1] || null
  };
};

const canTransitionTo = (inc, status) => (
  Array.isArray(inc.valid_next_statuses)
    ? inc.valid_next_statuses.includes(status)
    : false
);

const buildSignalBreakdown = (inc) => [
  {
    label: 'Threshold condition',
    value: `${inc.explanation?.observed ?? '?'} observed / ${inc.explanation?.threshold ?? '?'} required`,
    result: Number(inc.explanation?.observed ?? 0) >= Number(inc.explanation?.threshold ?? Infinity) ? 'met' : 'review'
  },
  {
    label: 'Time window',
    value: inc.explanation?.window || 'not supplied',
    result: 'applied'
  },
  {
    label: 'Grouping field',
    value: inc.explanation?.trigger_field || (inc.type === 'credential_abuse' ? 'source_ip' : 'username'),
    result: 'applied'
  },
  {
    label: 'Evidence volume',
    value: `${inc.evidence_count ?? inc.events?.length ?? 0} events`,
    result: 'collected'
  },
  {
    label: 'Confidence',
    value: inc.confidenceText,
    result: Number(inc.confidence) >= 0.8 ? 'strong' : 'review'
  }
];

const getTriageChecklist = (incident, playbook) => {
  if (Array.isArray(playbook?.triage) && playbook.triage.length > 0) return playbook.triage;
  if (Array.isArray(playbook?.questions) && playbook.questions.length > 0) return playbook.questions;
  if (Array.isArray(incident?.recommended_actions) && incident.recommended_actions.length > 0) return incident.recommended_actions;
  return ['Review event context', 'Check related activity'];
};

const getEscalationItems = (playbook) => {
  if (Array.isArray(playbook?.escalation_conditions) && playbook.escalation_conditions.length > 0) {
    return playbook.escalation_conditions;
  }
  if (typeof playbook?.escalation?.condition === 'string') {
    return [`${playbook.escalation.condition}${playbook.escalation.sla ? ` / SLA ${playbook.escalation.sla}` : ''}`];
  }
  return ['manual / SLA 30m'];
};

const buildPlaybookDashboardHref = (technique) => {
  const params = new URLSearchParams({ view: 'playbooks', technique });
  return `${window.location.origin}${window.location.pathname}?${params.toString()}`;
};

const PlaybookPanel = ({ playbook, onTechniqueClick, compact = false }) => {
  if (!playbook) return null;
  const detectionLogic = Object.entries(playbook.detection_logic || {});
  const deploymentContext = Object.entries(playbook.deployment_context || {});

  return (
    <div className={compact ? 'space-y-4' : 'space-y-5'}>
      <section>
        <div className="flex items-start justify-between gap-3">
          <div>
            <div className={compact ? 'text-xs font-bold text-gray-900' : 'text-sm font-bold text-gray-900'}>{playbook.name}</div>
            <div className="mt-0.5 font-mono text-[10px] text-blue-700">{playbook.id}</div>
          </div>
          <button
            type="button"
            onClick={() => onTechniqueClick?.(playbook.technique_id)}
            className="px-1.5 py-0.5 text-[9px] font-mono bg-blue-50 border border-blue-200 text-blue-700 rounded hover:bg-blue-100 flex-shrink-0"
          >
            {playbook.technique_id}
          </button>
        </div>
      </section>

      <section>
        <div className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold mb-2">Deployment Context</div>
        <div className="flex flex-wrap gap-1.5">
          {deploymentContext.length === 0 ? (
            <span className="text-xs text-gray-500">No deployment requirements defined.</span>
          ) : deploymentContext.map(([key, value]) => (
            <span key={key} className="px-2 py-1 rounded border border-gray-200 bg-gray-50 text-[11px] text-gray-700">
              <span className="font-mono text-gray-500">{key}</span>: <span className="font-semibold">{value}</span>
            </span>
          ))}
        </div>
      </section>

      <section>
        <div className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold mb-2">Detection (SPL)</div>
        <div className="rounded border border-gray-200 bg-gray-50 p-2 text-[11px] text-gray-700">
          <span className="text-gray-500">Primary detection: </span>
          <span className="font-mono font-semibold">{playbook.detections?.primary || 'manual_review'}</span>
        </div>
        {playbook.detections?.variants?.length > 0 && (
          <div className="mt-2 flex flex-wrap gap-1">
            {playbook.detections.variants.map((variant) => (
              <span key={variant} className="px-1.5 py-0.5 text-[10px] font-mono border border-gray-200 bg-gray-50 text-gray-600 rounded">
                {variant}
              </span>
            ))}
          </div>
        )}
        <div className="mt-3 space-y-3">
          {detectionLogic.length === 0 ? (
            <pre className="rounded border border-gray-200 bg-gray-950 p-3 font-mono text-[10px] text-green-100 overflow-auto">manual_review</pre>
          ) : detectionLogic.map(([logicName, logic]) => (
            <div key={logicName}>
              <div className="mb-1 text-[11px] font-semibold text-gray-700 capitalize">{logicName.replace(/_/g, ' ')}</div>
              <pre className={`rounded border border-gray-200 bg-gray-950 p-3 font-mono text-[10px] text-green-100 overflow-auto whitespace-pre-wrap ${compact ? 'max-h-44' : 'max-h-72'}`}>
                {logic}
              </pre>
            </div>
          ))}
        </div>
      </section>

      <section>
        <div className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold mb-2">Summary</div>
        <div className="rounded border border-blue-100 bg-blue-50 p-3 text-xs text-blue-900">
          {playbook.correlation || 'Manual investigation playbook for events without a specific correlation rule.'}
        </div>
      </section>

      <section>
        <div className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold mb-2">Triage Checklist</div>
        <ul className="space-y-1.5">
          {(playbook.triage || []).map((item) => (
            <li key={item} className="flex items-start gap-2 text-xs text-gray-700">
              <ChevronRight className="w-3 h-3 text-gray-400 mt-0.5 flex-shrink-0" />{item}
            </li>
          ))}
        </ul>
      </section>

      <section>
        <div className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold mb-2">False Positives</div>
        <div className="flex flex-wrap gap-1.5">
          {(playbook.false_positives || []).map((item) => (
            <span key={item} className="px-2 py-1 rounded border border-gray-200 bg-gray-50 text-[11px] text-gray-600">
              {item}
            </span>
          ))}
        </div>
        {playbook.false_positive_logic && (
          <div className="mt-3">
            <div className="mb-1 text-[11px] font-semibold text-gray-700">False Positive Handling</div>
            <pre className="rounded border border-gray-200 bg-gray-950 p-3 font-mono text-[10px] text-green-100 overflow-auto whitespace-pre-wrap">
              {playbook.false_positive_logic}
            </pre>
          </div>
        )}
      </section>

      <section>
        <div className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold mb-2">Escalation</div>
        <div className="rounded border border-orange-200 bg-orange-50 p-3 text-xs text-orange-900">
          <span className="font-semibold">{playbook.escalation?.condition || 'manual'}</span>
          <span className="ml-2 font-mono text-[11px] text-orange-700">SLA {playbook.escalation?.sla || '30m'}</span>
        </div>
        {playbook.escalation_criteria?.length > 0 && (
          <ul className="mt-2 space-y-1.5">
            {playbook.escalation_criteria.map((item) => (
              <li key={item} className="flex items-start gap-2 text-xs text-gray-700">
                <AlertTriangle className="w-3 h-3 text-orange-500 mt-0.5 flex-shrink-0" />{item}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section>
        <div className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold mb-2">Risk Fields</div>
        <div className="flex flex-wrap gap-1.5">
          {(playbook.risk?.fields || ['risk_score', 'risk_level']).map((field) => (
            <span key={field} className="px-2 py-1 rounded border border-gray-200 bg-white font-mono text-[11px] text-gray-700">
              {field}
            </span>
          ))}
        </div>
      </section>

      <section>
        <div className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold mb-2">Attack Chain</div>
        {playbook.chain_steps?.length > 0 && (
          <div className="mb-2 rounded border border-gray-200 bg-gray-50 p-2 text-xs text-gray-700">
            {playbook.chain_steps.join(' -> ')}
          </div>
        )}
        {playbook.chain?.length > 0 ? (
          <div className="flex flex-wrap gap-1.5">
            {playbook.chain.map((technique) => (
              <button
                key={technique}
                type="button"
                onClick={() => onTechniqueClick?.(technique)}
                className="px-2 py-1 text-[10px] font-mono border border-blue-200 bg-blue-50 text-blue-700 rounded hover:bg-blue-100"
              >
                {technique}
              </button>
            ))}
          </div>
        ) : (
          <div className="text-xs text-gray-500">No chained techniques defined.</div>
        )}
      </section>
    </div>
  );
};

const IncidentPlaybookPanel = ({ incident, playbook, onTechniqueClick }) => {
  if (!playbook) return null;
  const technique = playbook.technique_id || incident?.mitre?.technique || 'GENERIC';
  const fullPlaybookHref = buildPlaybookDashboardHref(technique);
  const chainTechniques = Array.isArray(playbook.chain) && playbook.chain.length > 0
    ? playbook.chain
    : [technique].filter(Boolean);

  return (
    <div className="space-y-4">
      <section>
        <div className="flex items-start justify-between gap-3">
          <div>
            <div className="text-[10px] uppercase tracking-wider text-indigo-500 font-semibold">Playbook</div>
            <div className="text-xs font-bold text-gray-900">{playbook.name}</div>
          </div>
          <a
            href={fullPlaybookHref}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1 rounded border border-indigo-200 bg-indigo-50 px-2 py-1 text-[10px] font-semibold text-indigo-700 hover:bg-indigo-100"
            title={`Open full playbook dashboard view for ${technique}`}
          >
            View Full Playbook
            <ExternalLink className="h-3 w-3" />
          </a>
        </div>
      </section>

      <section>
        <div className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold mb-2">Triage Checklist</div>
        <ul className="space-y-1.5">
          {getTriageChecklist(incident, playbook).map((item) => (
            <li key={item} className="flex items-start gap-2 text-xs text-gray-700">
              <ChevronRight className="w-3 h-3 text-gray-400 mt-0.5 flex-shrink-0" />{item}
            </li>
          ))}
        </ul>
      </section>

      <section>
        <div className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold mb-2">Escalation Criteria</div>
        <ul className="space-y-1.5">
          {getEscalationItems(playbook).map((condition) => (
            <li key={condition} className="flex items-start gap-2 text-xs text-gray-700">
              <AlertTriangle className="w-3 h-3 text-orange-500 mt-0.5 flex-shrink-0" />{condition}
            </li>
          ))}
        </ul>
      </section>

      <section>
        <div className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold mb-2">Attack Chain</div>
        {Array.isArray(playbook.chain_steps) && playbook.chain_steps.length > 0 && (
          <div className="mb-2 rounded border border-gray-200 bg-gray-50 p-2 text-xs text-gray-700">
            {playbook.chain_steps.join(' -> ')}
          </div>
        )}
        {playbook.chain_context && (
          <div className="mb-2 text-[11px] text-gray-600">{playbook.chain_context}</div>
        )}
        <div className="flex flex-wrap gap-1.5">
          {chainTechniques.map((chainTechnique) => (
            <button
              key={chainTechnique}
              type="button"
              onClick={() => onTechniqueClick?.(chainTechnique)}
              className="px-2 py-1 text-[10px] font-mono border border-blue-200 bg-blue-50 text-blue-700 rounded hover:bg-blue-100"
              title={`View MITRE coverage for ${chainTechnique}`}
            >
              {chainTechnique}
            </button>
          ))}
        </div>
      </section>
    </div>
  );
};

const whyDetectionFired = (inc) => {
  const observed = inc.explanation?.observed ?? inc.evidence_count ?? '?';
  const threshold = inc.explanation?.threshold ?? '?';
  const window = inc.explanation?.window || 'the detection window';
  if (inc.type === 'credential_abuse') {
    return `${observed} failed authentications crossed the ${threshold} event threshold across multiple accounts from ${inc.sourceIp} within ${window}.`;
  }
  return `${observed} failed authentications crossed the ${threshold} event threshold for ${inc.user} from ${inc.sourceIp} within ${window}.`;
};

const buildTimelineRows = (inc) => {
  const evidenceTimeline = Array.isArray(inc.evidence?.timeline) ? inc.evidence.timeline : [];
  const events = evidenceTimeline.length > 0 ? evidenceTimeline : (Array.isArray(inc.events) ? inc.events : []);
  return events.slice(0, 8).map((event, index) => ({
    id: `${inc.id}-timeline-${index}`,
    timestamp: event.timestamp || inc.first_seen || inc.last_seen,
    label: event.event_type || event.type || event.action || 'auth event',
    detail: [event.username, event.result, event.reason].filter(Boolean).join(' / ') || 'evidence event'
  }));
};

const getRelatedIncidents = (inc, allIncidents) => allIncidents
  .filter((candidate) => candidate.id !== inc.id)
  .filter((candidate) => (
    candidate.sourceIp === inc.sourceIp ||
    candidate.user === inc.user ||
    candidate.affected?.some((entity) => inc.affected?.includes(entity))
  ))
  .slice(0, 5);

const mapIncident = (incident) => {
  const subject = incident?.subject || {};
  return {
    ...incident,
    id: incident.incident_id,
    typeLabel: TYPE_LABELS[incident.type] || incident.type,
    severity: normalizeSeverity(incident.severity),
    timestamp: formatTimestamp(incident.last_seen || incident?.evidence?.window_end || incident.first_seen),
    user: subject.username || 'unknown',
    sourceIp: subject.source_ip || 'unknown',
    dest: incident.dest || subject.host || null,
    riskScore: incident.risk_score ?? null,
    riskLevel: incident.risk_level || null,
    confidenceText: formatConfidencePercent(incident.confidence),
    mitre: incident?.mitre || defaultMitreMapping(incident.type, incident.mitre_technique),
    explanation: incident.explanation || {},
    affected: Array.isArray(incident.affected_entities) ? incident.affected_entities : [],
    events: Array.isArray(incident?.evidence?.events) ? incident.evidence.events : []
  };
};

export default function SecurityWorkflow() {
  const initialRoute = useMemo(() => {
    const params = new URLSearchParams(window.location.search);
    return {
      view: params.get('view') || 'incidents',
      technique: params.get('technique') || '',
      entityType: params.get('entity_type') || '',
      entityId: params.get('entity_id') || ''
    };
  }, []);
  const [runs, setRuns] = useState([]);
  const [selectedRun, setSelectedRun] = useState('');
  const [runMeta, setRunMeta] = useState(null);
  const [normalizedCount, setNormalizedCount] = useState(0);
  const [incidentCount, setIncidentCount] = useState(0);
  const [incidents, setIncidents] = useState([]);
  const [playbooks, setPlaybooks] = useState([]);
  const [selectedPlaybookId, setSelectedPlaybookId] = useState('');
  const [selected, setSelected] = useState(new Set());
  const [sidePanelInc, setSidePanelInc] = useState(null);
  const [auditEvents, setAuditEvents] = useState([]);
  const [investigation, setInvestigation] = useState(null);
  const [incidentPlaybook, setIncidentPlaybook] = useState(null);
  const [highlightMitre, setHighlightMitre] = useState('');
  const [error, setError] = useState('');
  const [bootLoading, setBootLoading] = useState(true);
  const [bootFadeOut, setBootFadeOut] = useState(false);
  const [stageIndex, setStageIndex] = useState(0);
  const [loading, setLoading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [loadingSample, setLoadingSample] = useState(false);
  const [search, setSearch] = useState('');
  const [filters, setFilters] = useState({ severity: '', status: '' });
  const [activeView, setActiveView] = useState(initialRoute.view);
  const [entityView, setEntityView] = useState('username');
  const [selectedEntity, setSelectedEntity] = useState(
    initialRoute.entityType && initialRoute.entityId
      ? { entity_type: initialRoute.entityType, entity_id: initialRoute.entityId }
      : null
  );
  const [entityDetail, setEntityDetail] = useState(null);
  const [selectedSample, setSelectedSample] = useState(SAMPLE_DATASETS[0].value);
  const [selectedScenario, setSelectedScenario] = useState(VALIDATION_SCENARIOS[0].id);
  const [runningScenario, setRunningScenario] = useState(false);
  const [exportingReport, setExportingReport] = useState(false);
  const [dceContext, setDceContext] = useState(null);
  const fileInputRef = useRef(null);

  useEffect(() => {
    if (!initialRoute.technique || playbooks.length === 0) return;
    const match = playbooks.find((playbook) => playbook.technique_id === initialRoute.technique);
    if (!match) return;
    setActiveView('playbooks');
    setSelectedPlaybookId(match.id);
    setSearch('');
  }, [initialRoute.technique, playbooks]);

  useEffect(() => {
    if (!initialRoute.entityType || !initialRoute.entityId) return;
    setActiveView('entities');
    setEntityView(initialRoute.entityType);
    setSelectedEntity({ entity_type: initialRoute.entityType, entity_id: initialRoute.entityId });
    setSearch('');
  }, [initialRoute.entityType, initialRoute.entityId]);

  useEffect(() => {
    if (!selectedEntity?.entity_type || !selectedEntity?.entity_id) {
      setEntityDetail(null);
      return;
    }
    (async () => {
      try {
        const res = await fetch(`${API_BASE}/entities/${selectedEntity.entity_type}/${encodeURIComponent(selectedEntity.entity_id)}`);
        setEntityDetail(res.ok ? await res.json() : null);
      } catch {
        setEntityDetail(null);
      }
    })();
  }, [selectedEntity]);

  // Keep side panel in sync after incident reload
  useEffect(() => {
    setSidePanelInc((prev) => {
      if (!prev) return null;
      const updated = incidents.find((i) => i.id === prev.id);
      return updated || prev;
    });
  }, [incidents]);

  useEffect(() => {
    if (!sidePanelInc?.id) {
      setAuditEvents([]);
      setInvestigation(null);
      setIncidentPlaybook(null);
      setDceContext(null);
      return;
    }
    (async () => {
      try {
        const [auditRes, investigationRes, playbookRes, dceRes] = await Promise.all([
          fetch(`${API_BASE}/incidents/${sidePanelInc.id}/audit`),
          fetch(`${API_BASE}/incidents/${sidePanelInc.id}/investigation`),
          fetch(`${API_BASE}/incidents/${sidePanelInc.id}/playbook`),
          fetch(`${API_BASE}/dce/context/${sidePanelInc.id}`)
        ]);
        if (!auditRes.ok) return;
        const payload = await auditRes.json();
        setAuditEvents(Array.isArray(payload.events) ? payload.events.slice().reverse() : []);
        setInvestigation(investigationRes.ok ? await investigationRes.json() : sidePanelInc.investigation || null);
        setIncidentPlaybook(playbookRes.ok ? await playbookRes.json() : null);
        setDceContext(dceRes.ok ? await dceRes.json() : null);
      } catch {
        setAuditEvents([]);
        setInvestigation(sidePanelInc.investigation || null);
        setIncidentPlaybook(null);
        setDceContext(null);
      }
    })();
  }, [sidePanelInc?.id, sidePanelInc?.status, sidePanelInc?.assignee, sidePanelInc?.investigation]);

  const loadRuns = async () => {
    const res = await fetch(`${API_BASE}/runs/`);
    if (!res.ok) throw new Error('Failed to load runs');
    const data = await res.json();
    setRuns(Array.isArray(data) ? data : []);
  };

  const loadIncidents = async () => {
    const res = await fetch(`${API_BASE}/incidents/`);
    if (!res.ok) throw new Error('Failed to load incident registry');
    const payload = await res.json();
    setIncidentCount(typeof payload.incident_count === 'number' ? payload.incident_count : 0);
    setIncidents((Array.isArray(payload.incidents) ? payload.incidents : []).map(mapIncident));
  };

  const loadPlaybooks = async () => {
    const res = await fetch(`${API_BASE}/playbooks/`);
    if (!res.ok) throw new Error('Failed to load playbooks');
    const payload = await res.json();
    const rows = Array.isArray(payload.playbooks) ? payload.playbooks : [];
    setPlaybooks(rows);
    setSelectedPlaybookId((prev) => prev || rows[0]?.id || '');
  };

  const loadRunContext = async (runId) => {
    if (!runId) return;
    setSelectedRun(runId);
    setLoading(true);
    try {
      const [metaRes, normalizedRes, incidentsRes] = await Promise.all([
        fetch(`${API_BASE}/runs/${runId}/meta`),
        fetch(`${API_BASE}/runs/${runId}/normalized`),
        fetch(`${API_BASE}/incidents/`)
      ]);
      const meta = metaRes.ok ? await metaRes.json() : null;
      const normalized = normalizedRes.ok ? await normalizedRes.json() : { event_count: 0 };
      const registry = incidentsRes.ok ? await incidentsRes.json() : { incident_count: 0, incidents: [] };
      setRunMeta(meta);
      setNormalizedCount(typeof normalized.event_count === 'number' ? normalized.event_count : 0);
      setIncidentCount(typeof registry.incident_count === 'number' ? registry.incident_count : 0);
      setIncidents((Array.isArray(registry.incidents) ? registry.incidents : []).map(mapIncident));
      setSelected(new Set());
      setError('');
    } catch {
      setError('Failed to load dashboard data');
    } finally {
      setLoading(false);
    }
  };

  const patchSelected = async (targetStatus) => {
    if (!selected.size) return;
    setLoading(true);
    try {
      const payload = targetStatus === 'closed'
        ? { incident_ids: [...selected], status: 'closed', resolution_reason: 'closed_from_ui' }
        : { incident_ids: [...selected], status: targetStatus };
      const res = await fetch(`${API_BASE}/incidents/bulk`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || 'Bulk patch failed');
      }
      await loadIncidents();
      setSelected(new Set());
      setError('');
    } catch (e) {
      setError(`Status update failed: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  const assignSelected = async () => {
    if (!selected.size) return;
    const assignee = window.prompt('Assign selected incidents to analyst/team:', 'tier2');
    if (assignee == null) return;
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/incidents/bulk`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ incident_ids: [...selected], assignee })
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || 'Bulk assignment failed');
      }
      await loadIncidents();
      setSelected(new Set());
      setError('');
    } catch (e) {
      setError(`Bulk assignment failed: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  const patchSingle = async (id, targetStatus) => {
    setLoading(true);
    try {
      const payload = targetStatus === 'closed'
        ? { status: 'closed', resolution_reason: 'closed_from_ui' }
        : { status: targetStatus };
      const res = await fetch(`${API_BASE}/incidents/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || `Patch failed for ${id}`);
      }
      await loadIncidents();
      setError('');
    } catch (e) {
      setError(`Status update failed: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  const assignIncident = async (id) => {
    const assignee = window.prompt('Assign incident to analyst/team:', sidePanelInc?.assignee || 'tier2');
    if (assignee == null) return;
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/incidents/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ assignee })
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || `Assignment failed for ${id}`);
      }
      await loadIncidents();
      setError('');
    } catch (e) {
      setError(`Assignment failed: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  // Navigation handlers for cross-view linking
  const goToMitreCoverage = (technique) => {
    setHighlightMitre(technique);
    setActiveView('mitre_coverage');
    setDashboardRoute({ view: 'mitre_coverage', technique });
  };

  const goToEntityView = (entityType, value) => {
    setSidePanelInc(null);
    setEntityView(entityType);
    setSelectedEntity({ entity_type: entityType, entity_id: value });
    setSearch('');
    setActiveView('entities');
    setDashboardRoute({ view: 'entities', entity_type: entityType, entity_id: value });
  };

  const goToPlaybook = (playbook) => {
    if (!playbook?.id) return;
    setSelectedPlaybookId(playbook.id);
    setSearch('');
    setActiveView('playbooks');
    setDashboardRoute({ view: 'playbooks', technique: playbook.technique_id });
  };

  const handleAINavigate = ({ view, incidentId, attackType }) => {
    if (view !== 'incidents') return;
    setActiveView('incidents');
    if (attackType) setSearch(attackType);
    if (incidentId) {
      const inc = incidents.find((i) => i.id === incidentId || i.incident_id === incidentId);
      if (inc) setSidePanelInc(inc);
    }
  };

  const handleMitreNavigate = ({ view, mitreTechnique }) => {
    if (view !== 'incidents') return;
    setActiveView('incidents');
    if (mitreTechnique) setSearch(mitreTechnique);
  };

  const canAcknowledge = useMemo(() => {
    const rows = incidents.filter((inc) => selected.has(inc.id));
    return rows.length > 0 && rows.every((inc) => inc.status === 'open');
  }, [incidents, selected]);

  const canEscalate = useMemo(() => {
    const rows = incidents.filter((inc) => selected.has(inc.id));
    return rows.length > 0 && rows.every((inc) => inc.status === 'acknowledged');
  }, [incidents, selected]);

  const canClose = useMemo(() => {
    const rows = incidents.filter((inc) => selected.has(inc.id));
    return rows.length > 0 && rows.every((inc) => inc.status === 'escalated');
  }, [incidents, selected]);

  // Search scope includes MITRE technique and raw incident type for cross-view navigation
  const filtered = incidents.filter((inc) => {
    if (filters.severity && inc.severity !== filters.severity) return false;
    if (filters.status && inc.status !== filters.status) return false;
    if (!search) return true;
    const q = search.toLowerCase();
    return (
      inc.id.toLowerCase().includes(q) ||
      inc.user.toLowerCase().includes(q) ||
      inc.sourceIp.toLowerCase().includes(q) ||
      inc.typeLabel.toLowerCase().includes(q) ||
      (inc.type || '').toLowerCase().includes(q) ||
      (inc.mitre?.technique || '').toLowerCase().includes(q)
    );
  });

  const entityRows = useMemo(() => {
    const grouped = new Map();
    incidents.forEach((inc) => {
      const rawEntity = entityView === 'username' ? inc.user : inc.sourceIp;
      const entity = typeof rawEntity === 'string' && rawEntity.trim() ? rawEntity.trim() : 'unknown';
      if (!grouped.has(entity)) {
        grouped.set(entity, { entity, totalIncidents: 0, openIncidents: 0, highestConfidence: 0, lastSeen: '', lastSeenMs: 0, incidents: [] });
      }
      const row = grouped.get(entity);
      row.totalIncidents += 1;
      if (inc.status === 'open') row.openIncidents += 1;
      const confidence = Number(inc.confidence);
      if (Number.isFinite(confidence) && confidence > row.highestConfidence) row.highestConfidence = confidence;
      const seenRaw = inc.last_seen || inc.first_seen || inc.timestamp;
      const seenMs = toTimestampMs(seenRaw);
      if (seenMs >= row.lastSeenMs) { row.lastSeenMs = seenMs; row.lastSeen = seenRaw || ''; }
      row.incidents.push(inc);
    });
    return [...grouped.values()]
      .map((row) => ({ ...row, rollingRiskScore: computeRollingRiskScore(row.incidents) }))
      .sort((a, b) => b.rollingRiskScore - a.rollingRiskScore || b.openIncidents - a.openIncidents || b.highestConfidence - a.highestConfidence || b.lastSeenMs - a.lastSeenMs);
  }, [incidents, entityView]);

  const filteredEntities = useMemo(() => {
    if (!search) return entityRows;
    const q = search.toLowerCase();
    return entityRows.filter((row) => row.entity.toLowerCase().includes(q));
  }, [entityRows, search]);

  const filteredPlaybooks = useMemo(() => {
    if (!search) return playbooks;
    const q = search.toLowerCase();
    return playbooks.filter((playbook) => (
      playbook.id.toLowerCase().includes(q) ||
      playbook.name.toLowerCase().includes(q) ||
      playbook.technique_id.toLowerCase().includes(q) ||
      (playbook.detections?.primary || '').toLowerCase().includes(q) ||
      (playbook.triage || []).some((item) => item.toLowerCase().includes(q))
    ));
  }, [playbooks, search]);

  const selectedPlaybook = useMemo(() => (
    playbooks.find((playbook) => playbook.id === selectedPlaybookId) ||
    filteredPlaybooks[0] ||
    playbooks[0] ||
    null
  ), [playbooks, selectedPlaybookId, filteredPlaybooks]);

  const playbookIncidentCounts = useMemo(() => {
    const counts = new Map();
    incidents.forEach((incident) => {
      const technique = incident.mitre?.technique || incident.mitre_technique || 'GENERIC';
      counts.set(technique, (counts.get(technique) || 0) + 1);
    });
    return counts;
  }, [incidents]);

  useEffect(() => {
    if (!bootLoading || bootFadeOut) return undefined;
    const interval = window.setInterval(() => {
      setStageIndex((prev) => (prev + 1) % LOADING_STAGES.length);
    }, 700);
    return () => window.clearInterval(interval);
  }, [bootLoading, bootFadeOut]);

  useEffect(() => {
    let cancelled = false;
    const timers = [];
    const wait = (ms) => new Promise((resolve) => {
      const timer = window.setTimeout(resolve, Math.max(0, ms));
      timers.push(timer);
    });

    (async () => {
      const bootStartedAt = performance.now();
      setBootLoading(true);
      setBootFadeOut(false);
      setStageIndex(0);
      try {
        await Promise.all([loadRuns(), loadIncidents(), loadPlaybooks()]);
      } catch {
        setError('Failed to connect to backend');
      } finally {
        const elapsedMs = performance.now() - bootStartedAt;
        await wait(BOOT_LOADING_MIN_MS - elapsedMs);
        if (!cancelled) {
          setBootFadeOut(true);
          await wait(BOOT_FADE_OUT_MS);
        }
        if (!cancelled) {
          setBootLoading(false);
        }
      }
    })();

    return () => {
      cancelled = true;
      timers.forEach((timer) => window.clearTimeout(timer));
    };
  }, []);

  useEffect(() => {
    if (runs.length > 0 && !selectedRun) loadRunContext(runs[0]);
  }, [runs, selectedRun]);

  const ingestEvents = async (events) => {
    const res = await fetch(`${API_BASE}/ingest/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(events)
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.detail || 'Ingest failed');
    }
    const payload = await res.json();
    await loadRuns();
    await loadRunContext(payload.run_id);
  };

  const onUpload = async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    setUploading(true);
    try {
      const text = await file.text();
      const events = JSON.parse(text);
      await ingestEvents(events);
    } catch (e) {
      setError(`Upload failed: ${e.message}`);
    } finally {
      setUploading(false);
      event.target.value = '';
    }
  };

  const onLoadSample = async () => {
    setLoadingSample(true);
    try {
      const fixtureRes = await fetch(`/${selectedSample}`, { cache: 'no-store' });
      if (!fixtureRes.ok) throw new Error('Failed to load sample fixture');
      const events = await fixtureRes.json();
      if (!Array.isArray(events)) throw new Error('Sample fixture must be a JSON array');
      await ingestEvents(events);
      setActiveView('incidents');
      setError('');
    } catch (e) {
      setError(`Sample ingest failed: ${e.message}`);
    } finally {
      setLoadingSample(false);
    }
  };

  const seedDemoMode = async () => {
    setLoadingSample(true);
    setError('');
    try {
      const res = await fetch(`${API_BASE}/incidents/demo-seed`, { method: 'POST' });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || 'Demo seed failed');
      }
      const payload = await res.json();
      setIncidentCount(typeof payload.incident_count === 'number' ? payload.incident_count : 0);
      setIncidents((Array.isArray(payload.incidents) ? payload.incidents : []).map(mapIncident));
      setSelected(new Set());
      setActiveView('incidents');
    } catch (e) {
      setError(`Demo seed failed: ${e.message}`);
    } finally {
      setLoadingSample(false);
    }
  };

  const runValidationScenario = async () => {
    setRunningScenario(true);
    setError('');
    try {
      const res = await fetch(`${API_BASE}/validate/${selectedScenario}`, { method: 'POST' });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || 'Scenario run failed');
      }
      await Promise.all([loadRuns(), loadIncidents(), loadPlaybooks()]);
      setActiveView('detection_quality');
    } catch (e) {
      setError(`Scenario run failed: ${e.message}`);
    } finally {
      setRunningScenario(false);
    }
  };

  const exportReport = async () => {
    setExportingReport(true);
    setError('');
    try {
      const res = await fetch(`${API_BASE}/validate/results/report`);
      if (!res.ok) throw new Error('Report generation failed');
      const text = await res.text();
      const blob = new Blob([text], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `securewatch-report-${new Date().toISOString().slice(0, 10)}.txt`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (e) {
      setError(`Export failed: ${e.message}`);
    } finally {
      setExportingReport(false);
    }
  };

  if (bootLoading) {
    return <AppLoadingState fadeOut={bootFadeOut} stage={LOADING_STAGES[stageIndex]} />;
  }

  return (
    <div className="h-screen flex flex-col bg-gray-50">
      {/* Header — three-zone: Left identity | Center controls | Right metrics */}
      <header className="border-b border-gray-300 bg-white flex items-stretch flex-shrink-0 min-h-[80px] flex-wrap">
        {/* Left: logo + product identity */}
        <div className="flex items-center px-4 py-2 border-r border-gray-200 min-w-[288px] max-w-full flex-shrink-0 shadow-[2px_0_8px_-4px_rgba(59,130,246,0.25)]">
          <LogoIdentity />
        </div>

        {/* Center: dataset + scenario controls; wraps below identity at small widths */}
        <div className="flex-1 flex items-center gap-3 px-4 py-2 flex-wrap min-w-0">
          {/* Data zone */}
          <div className="flex items-center gap-2">
            <span className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold select-none">Data</span>
            <select className="text-xs border border-gray-300 px-2 py-1 bg-white" value={selectedRun} onChange={(e) => loadRunContext(e.target.value)}>
              {runs.map((runId) => <option key={runId} value={runId}>{runId}</option>)}
            </select>
            <label className="px-2 py-1 text-xs bg-blue-600 text-white cursor-pointer flex items-center gap-1 select-none">
              <Upload className="w-3 h-3" />
              {uploading ? 'Uploading...' : 'Upload'}
              <input ref={fileInputRef} type="file" accept=".json" className="hidden" onChange={onUpload} disabled={uploading} />
            </label>
            <select className="text-xs border border-gray-300 px-2 py-1 bg-white" value={selectedSample} onChange={(e) => setSelectedSample(e.target.value)} disabled={uploading || loadingSample}>
              {SAMPLE_DATASETS.map((d) => <option key={d.value} value={d.value}>{d.label}</option>)}
            </select>
            <button type="button" className="px-2 py-1 text-xs border border-gray-300 bg-white disabled:text-gray-400" onClick={onLoadSample} disabled={uploading || loadingSample}>
              {loadingSample ? 'Loading...' : 'Load Dataset'}
            </button>
            <button type="button" className="px-2 py-1 text-xs border border-emerald-300 text-emerald-700 bg-white disabled:text-gray-400" onClick={seedDemoMode} disabled={uploading || loadingSample}>
              Demo Seed
            </button>
          </div>

          <div className="w-px h-5 bg-gray-300 flex-shrink-0" />

          {/* Scenario zone */}
          <div className="flex items-center gap-2">
            <span className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold select-none">Run</span>
            <select className="text-xs border border-gray-300 px-2 py-1 bg-white" value={selectedScenario} onChange={(e) => setSelectedScenario(e.target.value)} disabled={runningScenario}>
              {VALIDATION_SCENARIOS.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
            </select>
            <button type="button" className="px-2 py-1 text-xs bg-indigo-600 text-white disabled:bg-gray-400" onClick={runValidationScenario} disabled={runningScenario}>
              {runningScenario ? 'Running...' : 'Run Scenario'}
            </button>
          </div>

          {/* Bulk actions — only when rows are selected in incident view */}
          {activeView === 'incidents' && selected.size > 0 && (
            <>
              <div className="w-px h-5 bg-gray-300 flex-shrink-0" />
              <div className="flex items-center gap-2">
                <button className="px-2 py-1 text-xs border border-gray-300 disabled:text-gray-400" disabled={!canAcknowledge || loading} onClick={() => patchSelected('acknowledged')}>Mark Acknowledged</button>
                <button className="px-2 py-1 text-xs border border-blue-300 text-blue-700 disabled:text-gray-400" disabled={!selected.size || loading} onClick={assignSelected}>Assign Selected</button>
                <button className="px-2 py-1 text-xs border border-orange-300 text-orange-700 disabled:text-gray-400" disabled={!canEscalate || loading} onClick={() => patchSelected('escalated')}>Escalate Selected</button>
                <button className="px-2 py-1 text-xs border border-gray-300 disabled:text-gray-400" disabled={!canClose || loading} onClick={() => patchSelected('closed')}>Mark Closed</button>
              </div>
            </>
          )}
        </div>

        {/* Right: metrics + export + API link */}
        <div className="flex items-center gap-3 px-4 border-l border-gray-200 flex-shrink-0">
          <div className="text-[11px] text-gray-600 whitespace-nowrap">
            Events: {runMeta?.event_count ?? 0} &middot; Normalized: {normalizedCount} &middot; Incidents: {incidentCount}
          </div>
          <div className="w-px h-5 bg-gray-300 flex-shrink-0" />
          <button type="button" className="px-2 py-1 text-xs border border-gray-300 bg-white disabled:text-gray-400" onClick={exportReport} disabled={exportingReport}>
            {exportingReport ? 'Generating...' : 'Export Report'}
          </button>
          <a href={`${API_BASE}/openapi.json`} target="_blank" rel="noreferrer" className="text-xs underline text-gray-700">API Contract</a>
        </div>
      </header>

      {error && <div className="px-4 py-2 text-xs bg-red-50 border-b border-red-200 text-red-700 flex-shrink-0">{error}</div>}


      {/* View tabs */}
      <div className="border-b border-gray-200 bg-white px-4 py-2 flex items-center gap-2 flex-shrink-0">
        {[
          { id: 'incidents', label: 'Incident Registry' },
          { id: 'playbooks', label: 'Playbooks' },
          { id: 'entities', label: 'Entity Risk View' },
          { id: 'detection_quality', label: 'Detection Quality' },
          { id: 'mitre_coverage', label: 'MITRE Coverage' },
          { id: 'ai_pipeline', label: 'AI Security', accent: true }
        ].map(({ id, label, accent }) => (
          <button
            key={id}
            type="button"
            className={`px-2 py-1 text-xs border ${activeView === id ? (accent ? 'border-indigo-600 bg-indigo-600 text-white' : 'border-blue-600 bg-blue-600 text-white') : 'border-gray-300 bg-white text-gray-700'}`}
            onClick={() => setActiveView(id)}
          >
            {label}
          </button>
        ))}
        {activeView === 'entities' && (
          <div className="ml-2 flex items-center gap-2">
            <button type="button" className={`px-2 py-1 text-xs border ${entityView === 'username' ? 'border-gray-900 bg-gray-900 text-white' : 'border-gray-300 bg-white text-gray-700'}`} onClick={() => setEntityView('username')}>View by Username</button>
            <button type="button" className={`px-2 py-1 text-xs border ${entityView === 'source_ip' ? 'border-gray-900 bg-gray-900 text-white' : 'border-gray-300 bg-white text-gray-700'}`} onClick={() => setEntityView('source_ip')}>View by Source IP</button>
          </div>
        )}
      </div>

      {/* Search + filters */}
      <div className="border-b border-gray-200 bg-white px-4 py-2 flex items-center gap-2 flex-shrink-0">
        <div className="relative w-80">
          <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-gray-400" />
          <input value={search} onChange={(e) => setSearch(e.target.value)} className="w-full pl-7 pr-2 py-1 text-xs border border-gray-300" placeholder={activeView === 'incidents' ? 'Search ID, user, IP, type, MITRE…' : activeView === 'playbooks' ? 'Search playbooks, technique, detection…' : entityView === 'username' ? 'Search usernames' : 'Search source IPs'} />
        </div>
        {search && (
          <button type="button" onClick={() => setSearch('')} className="text-[10px] text-gray-400 hover:text-gray-600 underline">clear</button>
        )}
        {activeView === 'incidents' && (
          <>
            <Filter className="w-3 h-3 text-gray-500" />
            <select className="text-xs border border-gray-300 px-2 py-1" value={filters.severity} onChange={(e) => setFilters({ ...filters, severity: e.target.value })}>
              <option value="">All severity</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
            </select>
            <select className="text-xs border border-gray-300 px-2 py-1" value={filters.status} onChange={(e) => setFilters({ ...filters, status: e.target.value })}>
              <option value="">All status</option><option value="open">Open</option><option value="acknowledged">Acknowledged</option><option value="escalated">Escalated</option><option value="closed">Closed</option>
            </select>
          </>
        )}
      </div>

      {/* Main content area */}
      <div className="flex-1 overflow-auto flex min-h-0">
        {/* Primary panel */}
        <div className="flex-1 overflow-auto">
          {activeView === 'ai_pipeline' ? (
            <AIPipelineView onNavigate={handleAINavigate} />
          ) : activeView === 'detection_quality' ? (
            <DetectionQualityTable />
          ) : activeView === 'mitre_coverage' ? (
            <MitreCoverageView highlight={highlightMitre} onNavigate={handleMitreNavigate} />
          ) : activeView === 'playbooks' ? (
            <div className="h-full flex min-h-0">
              <div className="w-[420px] border-r border-gray-200 bg-white overflow-auto flex-shrink-0">
                <div className="sticky top-0 z-10 bg-gray-100 border-b border-gray-300 px-3 py-2">
                  <div className="text-xs font-bold text-gray-900">SOC Playbooks</div>
                  <div className="text-[11px] text-gray-500">{filteredPlaybooks.length} visible of {playbooks.length} total playbooks</div>
                </div>
                <div className="divide-y divide-gray-200">
                  {filteredPlaybooks.length === 0 ? (
                    <div className="px-3 py-8 text-center text-xs text-gray-500">No playbooks match the current search.</div>
                  ) : filteredPlaybooks.map((playbook) => {
                    const isActive = selectedPlaybook?.id === playbook.id;
                    const incidentMatches = playbookIncidentCounts.get(playbook.technique_id) || 0;
                    return (
                      <button
                        key={playbook.id}
                        type="button"
                        onClick={() => setSelectedPlaybookId(playbook.id)}
                        className={`w-full px-3 py-3 text-left hover:bg-blue-50 ${isActive ? 'bg-blue-50' : 'bg-white'}`}
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div>
                            <div className="text-xs font-semibold text-gray-900">{playbook.name}</div>
                            <div className="mt-0.5 font-mono text-[10px] text-blue-700">{playbook.id}</div>
                          </div>
                          <span className="px-1.5 py-0.5 text-[9px] font-mono bg-blue-50 border border-blue-200 text-blue-700 rounded whitespace-nowrap">
                            {playbook.technique_id}
                          </span>
                        </div>
                        <div className="mt-2 flex items-center justify-between gap-2 text-[11px] text-gray-500">
                          <span className="font-mono">{playbook.detections?.primary || 'manual'}</span>
                          <span>{incidentMatches} incidents</span>
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>

              <div className="flex-1 overflow-auto bg-white">
                {selectedPlaybook ? (
                  <div className="p-4 space-y-5">
                    <section className="border-b border-gray-200 pb-4">
                      <div className="flex items-start justify-between gap-4">
                        <div>
                          <div className="text-sm font-bold text-gray-900">Playbook Reference</div>
                          <div className="mt-1 text-[11px] text-gray-500">Standalone explorer for reviewing registered playbooks.</div>
                        </div>
                        <span className="px-2 py-1 text-[10px] border border-gray-200 bg-gray-50 text-gray-600 rounded">
                          {playbookIncidentCounts.get(selectedPlaybook.technique_id) || 0} matching incidents
                        </span>
                      </div>
                    </section>
                    <PlaybookPanel playbook={selectedPlaybook} onTechniqueClick={goToMitreCoverage} />
                  </div>
                ) : (
                  <div className="px-3 py-8 text-center text-xs text-gray-500">No playbook selected.</div>
                )}
              </div>
            </div>
          ) : activeView === 'incidents' ? (
            <table className="w-full text-xs">
              <thead className="bg-gray-100 border-b border-gray-300 sticky top-0 z-10">
                <tr>
                  <th className="px-2 py-2 w-8">
                    <input type="checkbox" checked={selected.size > 0 && selected.size === filtered.length} onChange={() => setSelected(selected.size === filtered.length ? new Set() : new Set(filtered.map((inc) => inc.id)))} />
                  </th>
                  <th className="px-2 py-2 text-left text-gray-500 font-medium">ID</th>
                  <th className="px-2 py-2 text-left text-gray-500 font-medium">Time</th>
                  <th className="px-2 py-2 text-left text-gray-900 font-bold">Type</th>
                  <th className="px-2 py-2 text-left text-gray-500 font-medium">MITRE</th>
                  <th className="px-2 py-2 text-left text-gray-900 font-bold">Severity</th>
                  <th className="px-2 py-2 text-left text-gray-500 font-medium">User</th>
                  <th className="px-2 py-2 text-left text-gray-500 font-medium">Source IP</th>
                  <th className="px-2 py-2 text-left text-gray-500 font-medium">Signals</th>
                  <th className="px-2 py-2 text-left text-gray-400 font-medium">Confidence</th>
                  <th className="px-2 py-2 text-left text-gray-500 font-medium">SLA</th>
                  <th className="px-2 py-2 text-left text-gray-500 font-medium">Status</th>
                  <th className="px-2 py-2 text-left text-gray-500 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((inc, idx) => {
                  const mismatch = getSeverityMismatch(inc);
                  const isSelected = selected.has(inc.id);
                  const isActive = sidePanelInc?.id === inc.id;
                  const rowBg = isActive ? 'bg-blue-50' : isSelected ? 'bg-indigo-50' : idx % 2 === 0 ? 'bg-white' : 'bg-gray-50/60';
                  return (
                    <tr
                      key={inc.id}
                      className={`border-b border-gray-200 cursor-pointer hover:bg-blue-50 transition-colors ${rowBg}`}
                      onClick={() => setSidePanelInc(sidePanelInc?.id === inc.id ? null : inc)}
                    >
                      <td className="px-2 py-2">
                        <input type="checkbox" checked={isSelected} onChange={() => {}} onClick={(e) => { e.stopPropagation(); const next = new Set(selected); next.has(inc.id) ? next.delete(inc.id) : next.add(inc.id); setSelected(next); }} />
                      </td>
                      <td className="px-2 py-2 font-mono text-blue-700">{inc.id}</td>
                      <td className="px-2 py-2 font-mono text-gray-500">{inc.timestamp}</td>
                      <td className="px-2 py-2 font-semibold text-gray-800">{inc.typeLabel}</td>

                      {/* MITRE badge — click to jump to MITRE Coverage view */}
                      <td className="px-2 py-2" onClick={(e) => e.stopPropagation()}>
                        {inc.mitre?.technique && (
                          <button
                            type="button"
                            onClick={() => goToMitreCoverage(inc.mitre.technique)}
                            className="px-1.5 py-0.5 text-[9px] font-mono bg-blue-50 border border-blue-200 text-blue-700 rounded whitespace-nowrap hover:bg-blue-100 cursor-pointer"
                            title={`View ${inc.mitre.technique} in MITRE Coverage`}
                          >
                            {inc.mitre.technique}
                          </button>
                        )}
                      </td>

                      <td className="px-2 py-2">
                        <div className="flex items-center gap-1">
                          <span className={`px-2 py-0.5 text-[10px] font-bold rounded-sm capitalize ${SEVERITY_COLORS[inc.severity] || 'bg-gray-400 text-white'}`}>
                            {inc.severity}
                          </span>
                          {mismatch && <AlertTriangle className="w-3 h-3 text-orange-500 flex-shrink-0" title={mismatch} />}
                        </div>
                      </td>

                      {/* User — click to jump to Entity Risk View filtered by this user */}
                      <td className="px-2 py-2" onClick={(e) => e.stopPropagation()}>
                        <button
                          type="button"
                          onClick={() => goToEntityView('username', inc.user)}
                          className="hover:underline text-left"
                          title={`View entity profile for ${inc.user}`}
                        >
                          {inc.user}
                        </button>
                      </td>

                      {/* Source IP — click to jump to Entity Risk View filtered by this IP */}
                      <td className="px-2 py-2" onClick={(e) => e.stopPropagation()}>
                        <button
                          type="button"
                          onClick={() => goToEntityView('source_ip', inc.sourceIp)}
                          className="font-mono hover:underline text-left"
                          title={`View entity profile for ${inc.sourceIp}`}
                        >
                          {inc.sourceIp}
                        </button>
                      </td>

                      <td className="px-2 py-2 font-mono text-gray-600">{formatSignals(inc.explanation)}</td>
                      <td className="px-2 py-2 font-mono text-gray-400 text-[11px]">{inc.confidenceText}</td>
                      <td className="px-2 py-2">
                        {(() => {
                          const deadline = Number(inc.sla_deadline_minutes ?? 480) * 60;
                          const age = Number(inc.time_since_alert_seconds ?? 0);
                          const state = inc.sla_breached ? 'breach' : age > deadline * 0.75 ? 'warning' : 'ok';
                          const cls = state === 'breach' ? 'bg-red-50 text-red-700 border-red-200' : state === 'warning' ? 'bg-yellow-50 text-yellow-700 border-yellow-200' : 'bg-green-50 text-green-700 border-green-200';
                          return (
                            <span className={`px-1.5 py-0.5 text-[10px] font-mono rounded border ${cls}`}>
                              {state} / {formatDuration(age)}
                            </span>
                          );
                        })()}
                      </td>
                      <td className="px-2 py-2">
                        <span className={`px-2 py-0.5 text-[10px] font-semibold ${STATUS_BADGES[inc.status] || STATUS_BADGES.open}`}>{inc.status}</span>
                      </td>
                      <td className="px-2 py-2" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center gap-1">
                          {canTransitionTo(inc, 'acknowledged') && (
                            <button type="button" onClick={() => patchSingle(inc.id, 'acknowledged')} className="px-1.5 py-0.5 text-[10px] bg-yellow-100 text-yellow-800 border border-yellow-300 rounded hover:bg-yellow-200 whitespace-nowrap">Ack</button>
                          )}
                          {canTransitionTo(inc, 'escalated') && (
                            <button type="button" onClick={() => patchSingle(inc.id, 'escalated')} className="px-1.5 py-0.5 text-[10px] bg-orange-100 text-orange-800 border border-orange-300 rounded hover:bg-orange-200 whitespace-nowrap">Escalate</button>
                          )}
                          {canTransitionTo(inc, 'closed') && (
                            <button type="button" onClick={() => patchSingle(inc.id, 'closed')} className="px-1.5 py-0.5 text-[10px] bg-gray-100 text-gray-700 border border-gray-300 rounded hover:bg-gray-200 whitespace-nowrap">Close</button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          ) : (
            /* Entity Risk View */
            <table className="w-full text-xs">
              <thead className="bg-gray-100 border-b border-gray-300 sticky top-0">
                <tr>
                  <th className="px-2 py-2 text-left font-bold text-gray-900">{entityView === 'username' ? 'Username' : 'Source IP'}</th>
                  <th className="px-2 py-2 text-right font-medium text-gray-500">Total Incidents</th>
                  <th className="px-2 py-2 text-right font-medium text-gray-500">Open Incidents</th>
                  <th className="px-2 py-2 text-right text-gray-400 font-medium">Highest Confidence</th>
                  <th className="px-2 py-2 text-left font-medium text-gray-500">Last Seen</th>
                  <th className="px-2 py-2 text-right font-bold text-gray-900">Rolling Risk Score</th>
                </tr>
              </thead>
              <tbody>
                {filteredEntities.length === 0 ? (
                  <tr className="border-b border-gray-200">
                    <td colSpan={6} className="px-3 py-8 text-center text-gray-500">No entities found for current filters.</td>
                  </tr>
                ) : (
                  filteredEntities.map((row, idx) => (
                    <tr
                      key={row.entity}
                      className={`border-b border-gray-200 hover:bg-blue-50 transition-colors cursor-pointer ${idx % 2 === 0 ? 'bg-white' : 'bg-gray-50/60'}`}
                      onClick={() => goToEntityView(entityView, row.entity)}
                      title={`Open drilldown for ${row.entity}`}
                    >
                      <td className="px-2 py-2 font-mono text-blue-700">{row.entity}</td>
                      <td className="px-2 py-2 text-right font-mono">{row.totalIncidents}</td>
                      <td className="px-2 py-2 text-right font-mono">{row.openIncidents}</td>
                      <td className="px-2 py-2 text-right font-mono text-gray-400">{formatConfidencePercent(row.highestConfidence)}</td>
                      <td className="px-2 py-2 font-mono">{formatUtcTimestamp(row.lastSeen)}</td>
                      <td className="px-2 py-2 text-right">
                        <span
                          className={`inline-flex min-w-[44px] justify-center rounded px-2 py-0.5 font-mono text-[11px] font-semibold ${row.rollingRiskScore >= 75 ? 'bg-red-600 text-white' : row.rollingRiskScore >= 50 ? 'bg-orange-500 text-white' : row.rollingRiskScore >= 25 ? 'bg-yellow-400 text-black' : 'bg-green-500 text-white'}`}
                          title="Risk Score = detection confidence × severity weight × status weight, with 7-day time decay"
                        >
                          {row.rollingRiskScore}
                        </span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          )}
        </div>

        {/* Entity drilldown panel */}
        {activeView === 'entities' && selectedEntity && (
          <div className="w-[420px] border-l border-gray-300 bg-white overflow-auto flex-shrink-0">
            {!entityDetail ? (
              <div className="px-4 py-8 text-center text-xs text-gray-500">Loading entity drilldown...</div>
            ) : (
              <div className="p-4 space-y-5">
                <section className="border-b border-gray-200 pb-4">
                  <div className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold">Entity Drilldown</div>
                  <div className="mt-1 font-mono text-sm font-bold text-gray-900">{entityDetail.entity_id}</div>
                  <div className="mt-1 text-[11px] text-gray-500">{entityDetail.entity_type}</div>
                </section>

                <section>
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div className="rounded border border-gray-200 bg-gray-50 p-2">
                      <div className="text-[10px] text-gray-400">Risk Score</div>
                      <div className="font-mono font-bold text-gray-900">{entityDetail.risk_score}</div>
                    </div>
                    <div className="rounded border border-gray-200 bg-gray-50 p-2">
                      <div className="text-[10px] text-gray-400">Open Incidents</div>
                      <div className="font-mono font-bold text-gray-900">{entityDetail.open_incidents}</div>
                    </div>
                    <div className="rounded border border-gray-200 bg-gray-50 p-2">
                      <div className="text-[10px] text-gray-400">Total Incidents</div>
                      <div className="font-mono font-bold text-gray-900">{entityDetail.total_incidents}</div>
                    </div>
                    <div className="rounded border border-gray-200 bg-gray-50 p-2">
                      <div className="text-[10px] text-gray-400">Highest Confidence</div>
                      <div className="font-mono font-bold text-gray-900">{formatConfidencePercent(entityDetail.highest_confidence)}</div>
                    </div>
                  </div>
                  <div className="mt-2 font-mono text-[11px] text-gray-500">Last seen: {formatUtcTimestamp(entityDetail.last_seen)}</div>
                </section>

                <section>
                  <div className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold mb-2">MITRE Techniques</div>
                  <div className="flex flex-wrap gap-1.5">
                    {(entityDetail.mitre_techniques || []).map((technique) => (
                      <button key={technique} type="button" onClick={() => goToMitreCoverage(technique)} className="px-2 py-1 text-[10px] font-mono border border-blue-200 bg-blue-50 text-blue-700 rounded hover:bg-blue-100">
                        {technique}
                      </button>
                    ))}
                  </div>
                </section>

                <section>
                  <div className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold mb-2">Linked Playbooks</div>
                  <div className="space-y-2">
                    {(entityDetail.playbooks || []).map((playbook) => (
                      <button key={playbook.id} type="button" onClick={() => goToPlaybook(playbook)} className="w-full rounded border border-indigo-200 bg-indigo-50 p-2 text-left hover:bg-indigo-100">
                        <div className="text-xs font-semibold text-indigo-900">{playbook.name}</div>
                        <div className="mt-0.5 font-mono text-[10px] text-indigo-700">{playbook.technique_id}</div>
                      </button>
                    ))}
                  </div>
                </section>

                <section>
                  <div className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold mb-2">Investigation Pivots</div>
                  <div className="space-y-2">
                    {(entityDetail.investigation_pivots || []).map((pivot) => (
                      <button key={pivot.name} type="button" onClick={() => copyToClipboard(pivot.query)} className="w-full rounded border border-gray-200 bg-gray-50 p-2 text-left hover:bg-blue-50">
                        <div className="text-[11px] font-semibold text-gray-800">{pivot.name}</div>
                        <div className="mt-0.5 text-[10px] text-gray-500">{pivot.description}</div>
                      </button>
                    ))}
                  </div>
                </section>

                <section>
                  <div className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold mb-2">Related Incidents</div>
                  <div className="rounded border border-gray-200 bg-gray-50 divide-y divide-gray-200">
                    {(entityDetail.incidents || []).map((incident) => (
                      <button
                        key={incident.incident_id}
                        type="button"
                        onClick={() => {
                          const mapped = incidents.find((inc) => inc.id === incident.incident_id) || mapIncident(incident);
                          setSidePanelInc(mapped);
                          setActiveView('incidents');
                        }}
                        className="w-full px-2 py-2 text-left hover:bg-blue-50"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-mono text-[10px] text-blue-700">{incident.incident_id}</span>
                          <span className={`px-1.5 py-0.5 text-[9px] font-semibold ${STATUS_BADGES[incident.status] || STATUS_BADGES.open}`}>{incident.status}</span>
                        </div>
                        <div className="mt-0.5 text-[11px] text-gray-700">{TYPE_LABELS[incident.type] || incident.type}</div>
                        <div className="font-mono text-[10px] text-gray-400">{incident.mitre?.technique || incident.mitre_technique}</div>
                      </button>
                    ))}
                  </div>
                </section>
              </div>
            )}
          </div>
        )}

        {/* Incident focus panel */}
        {activeView === 'incidents' && sidePanelInc && (
          <div className="w-96 border-l border-gray-300 bg-white flex flex-col flex-shrink-0">
            {/* Panel header */}
            <div className="px-4 py-3 border-b border-gray-200 bg-gray-50 flex items-start justify-between flex-shrink-0">
              <div>
                <div className="text-xs font-mono text-blue-700 font-semibold">{sidePanelInc.id}</div>
                <div className="text-[11px] text-gray-600 mt-0.5 font-semibold">{sidePanelInc.typeLabel}</div>
              </div>
              <button type="button" onClick={() => setSidePanelInc(null)} className="p-1 hover:bg-gray-200 rounded text-gray-500" aria-label="Close panel">
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Status + severity row */}
            <div className="px-4 py-2 border-b border-gray-100 flex items-center gap-2 flex-shrink-0 flex-wrap">
              <span className={`px-2 py-0.5 text-[10px] font-semibold ${STATUS_BADGES[sidePanelInc.status] || STATUS_BADGES.open}`}>{sidePanelInc.status}</span>
              <span className={`px-2 py-0.5 text-[10px] font-bold capitalize rounded-sm ${SEVERITY_COLORS[sidePanelInc.severity] || 'bg-gray-400 text-white'}`}>{sidePanelInc.severity}</span>
              <span className="px-2 py-0.5 text-[10px] font-mono bg-white border border-gray-200 text-gray-600 rounded-sm">
                owner: {sidePanelInc.assignee || 'unassigned'}
              </span>
              <span className="px-2 py-0.5 text-[10px] font-mono bg-blue-50 border border-blue-200 text-blue-700 rounded-sm">
                Technique {sidePanelInc.mitre?.technique || sidePanelInc.mitre_technique || 'GENERIC'}
              </span>
              <span className="px-2 py-0.5 text-[10px] bg-indigo-50 border border-indigo-200 text-indigo-700 rounded-sm">
                Playbook {incidentPlaybook?.name || sidePanelInc.playbook_id || 'loading'}
              </span>
              {(() => {
                const state = dceContext?.sla_state || (sidePanelInc.sla_breached ? 'breach' : 'ok');
                const cls = state === 'breach' ? 'bg-red-50 border-red-200 text-red-700' : state === 'warning' ? 'bg-yellow-50 border-yellow-200 text-yellow-700' : 'bg-green-50 border-green-200 text-green-700';
                return <span className={`px-2 py-0.5 text-[10px] font-mono border rounded-sm ${cls}`}>SLA {state}</span>;
              })()}
              {getSeverityMismatch(sidePanelInc) && (
                <span className="flex items-center gap-1 text-[10px] text-orange-600 font-medium">
                  <AlertTriangle className="w-3 h-3" />{getSeverityMismatch(sidePanelInc)}
                </span>
              )}
            </div>

            {/* Scrollable body */}
            <div className="flex-1 overflow-auto px-4 py-3 space-y-5 text-xs">

              {/* Subject — clickable to navigate to entity views */}
              <section>
                <div className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold mb-2">Subject</div>
                <div className="space-y-1.5">
                  <div className="flex items-center gap-2">
                    <span className="text-gray-400 text-[10px] w-14 flex-shrink-0">User</span>
                    <button
                      type="button"
                      onClick={() => goToEntityView('username', sidePanelInc.user)}
                      className="font-mono text-[11px] text-blue-700 hover:underline text-left"
                      title="View entity profile"
                    >
                      {sidePanelInc.user}
                    </button>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-gray-400 text-[10px] w-14 flex-shrink-0">Source IP</span>
                    <button
                      type="button"
                      onClick={() => goToEntityView('source_ip', sidePanelInc.sourceIp)}
                      className="font-mono text-[11px] text-blue-700 hover:underline text-left"
                      title="View entity profile"
                    >
                      {sidePanelInc.sourceIp}
                    </button>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-gray-400 text-[10px] w-14 flex-shrink-0">Dest</span>
                    <span className="font-mono text-[11px] text-gray-700">
                      {sidePanelInc.dest || 'Destination not available'}
                    </span>
                  </div>
                </div>
              </section>

              {/* Incident-driven playbook */}
              <section className="rounded border border-indigo-200 bg-indigo-50 p-3">
                <div className="flex items-center justify-between gap-2 mb-3">
                  <div>
                    <div className="text-[10px] uppercase tracking-wider text-indigo-500 font-semibold">Playbook</div>
                    <div className="text-[11px] text-indigo-700">Loaded from this incident, not manual playbook selection.</div>
                  </div>
                  <span className="px-1.5 py-0.5 text-[9px] font-mono bg-white border border-indigo-200 text-indigo-700 rounded">
                    {sidePanelInc.playbook_id || incidentPlaybook?.id || 'pending'}
                  </span>
                </div>
                {incidentPlaybook ? (
                  <div className="rounded border border-indigo-100 bg-white p-3">
                    <IncidentPlaybookPanel incident={sidePanelInc} playbook={incidentPlaybook} onTechniqueClick={goToMitreCoverage} />
                  </div>
                ) : (
                  <div className="rounded border border-indigo-100 bg-white p-2 text-[11px] text-gray-500">Loading incident playbook...</div>
                )}
              </section>

              {/* Timeline */}
              <section>
                <div className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold mb-2">Timeline</div>
                <div className="space-y-2">
                  <div className="flex items-start gap-2">
                    <div className="w-2 h-2 rounded-full bg-blue-400 mt-1 flex-shrink-0" />
                    <div>
                      <div className="text-gray-400 text-[10px]">First Seen</div>
                      <div className="font-mono text-[11px] mt-0.5">{formatUtcTimestamp(sidePanelInc.first_seen)}</div>
                    </div>
                  </div>
                  <div className="ml-[3px] w-px h-3 bg-gray-200" />
                  <div className="flex items-start gap-2">
                    <div className="w-2 h-2 rounded-full bg-red-400 mt-1 flex-shrink-0" />
                    <div>
                      <div className="text-gray-400 text-[10px]">Last Seen</div>
                      <div className="font-mono text-[11px] mt-0.5">{formatUtcTimestamp(sidePanelInc.last_seen)}</div>
                    </div>
                  </div>
                </div>
                <div className="mt-3 rounded border border-gray-200 bg-white divide-y divide-gray-100">
                  {buildTimelineRows(sidePanelInc).length === 0 ? (
                    <div className="px-2 py-2 text-[11px] text-gray-400">No event timeline rows available.</div>
                  ) : buildTimelineRows(sidePanelInc).map((row) => (
                    <div key={row.id} className="px-2 py-2">
                      <div className="font-mono text-[10px] text-gray-400">{formatUtcTimestamp(row.timestamp)}</div>
                      <div className="text-[11px] font-semibold text-gray-700 mt-0.5">{row.label}</div>
                      <div className="text-[11px] text-gray-500">{row.detail}</div>
                    </div>
                  ))}
                </div>
              </section>

              {/* MITRE Chain — technique badge clickable to MITRE Coverage */}
              <section>
                <div className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold mb-2">Attack Chain Awareness</div>
                <div className="rounded border border-gray-200 bg-gray-50 p-2 mb-3">
                  <div className="flex items-center gap-1.5 overflow-x-auto pb-1">
                    {ATTACK_CHAIN.map((step, index) => {
                      const active = sidePanelInc.mitre?.technique === step.technique || (sidePanelInc.mitre?.technique === 'T1110.003' && step.technique === 'T1110');
                      return (
                        <React.Fragment key={step.technique}>
                          {index > 0 && <ChevronRight className="w-3 h-3 text-gray-300 flex-shrink-0" />}
                          <button
                            type="button"
                            onClick={() => goToMitreCoverage(step.technique)}
                            className={`px-2 py-1 rounded border text-left flex-shrink-0 ${active ? 'bg-blue-50 border-blue-200 text-blue-800' : 'bg-white border-gray-200 text-gray-500'}`}
                            title={`Hunt ${step.technique}`}
                          >
                            <div className="font-mono text-[10px]">{step.technique}</div>
                            <div className="text-[10px]">{active ? 'observed' : step.state}</div>
                          </button>
                        </React.Fragment>
                      );
                    })}
                  </div>
                  <div className="mt-2 text-[11px] text-gray-500">
                    {(() => {
                      const chain = getChainStage(sidePanelInc);
                      return (
                        <>
                          This incident is stage <span className="font-mono text-blue-700">{chain.stage}/{chain.total}</span>. Next likely step: <span className="font-mono text-blue-700">{chain.next ? `${chain.next.technique} ${chain.next.label}` : 'chain complete'}</span>.
                        </>
                      );
                    })()}
                  </div>
                </div>
                <div className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold mb-2">MITRE ATT&CK Mapping</div>
                <div className="rounded border border-gray-200 bg-gray-50 p-2 space-y-1.5">
                  <div className="flex items-center gap-2">
                    <span className="text-gray-400 text-[10px] w-14 flex-shrink-0">Tactic</span>
                    <span className="text-[11px] text-purple-700 font-medium">{sidePanelInc.mitre?.tactic || '—'}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-gray-400 text-[10px] w-14 flex-shrink-0">Technique</span>
                    {sidePanelInc.mitre?.technique ? (
                      <button
                        type="button"
                        onClick={() => goToMitreCoverage(sidePanelInc.mitre.technique)}
                        className="px-1.5 py-0.5 text-[9px] font-mono bg-blue-50 border border-blue-200 text-blue-700 rounded hover:bg-blue-100"
                        title="View in MITRE Coverage"
                      >
                        {sidePanelInc.mitre.technique}
                      </button>
                    ) : <span className="text-[11px] font-mono">—</span>}
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-gray-400 text-[10px] w-14 flex-shrink-0">Name</span>
                    <span className="text-[11px] font-mono">{sidePanelInc.mitre?.technique_name || '—'}</span>
                  </div>
                </div>
              </section>

              {/* Detection Signals */}
              <section>
                <div className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold mb-2">Why Detection Fired</div>
                <div className="rounded border border-blue-100 bg-blue-50 p-2 text-[11px] text-blue-900 mb-2">
                  {whyDetectionFired(sidePanelInc)}
                </div>
                <div className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold mb-2">Signal Breakdown</div>
                <div className="rounded border border-gray-200 bg-white p-2 font-mono text-[11px] space-y-1 mb-2">
                  {buildSignalBreakdown(sidePanelInc).map((signal) => (
                    <div key={signal.label} className="flex items-start justify-between gap-3">
                      <span className="text-gray-400">{signal.label}</span>
                      <span className="text-right">
                        <span className="text-gray-800">{signal.value}</span>
                        <span className="ml-1 text-[10px] text-blue-600">({signal.result})</span>
                      </span>
                    </div>
                  ))}
                </div>
                <div className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold mb-2">Raw Signal Fields</div>
                <div className="rounded border border-gray-200 bg-gray-50 p-2 font-mono text-[11px] space-y-1">
                  <div><span className="text-gray-400">Observed:   </span><span className="text-gray-800">{sidePanelInc.explanation?.observed ?? '—'}</span></div>
                  <div><span className="text-gray-400">Threshold:  </span><span className="text-gray-800">{sidePanelInc.explanation?.threshold ?? '—'}</span></div>
                  <div><span className="text-gray-400">Window:     </span><span className="text-gray-800">{sidePanelInc.explanation?.window ?? '—'}</span></div>
                  <div>
                    <span className="text-gray-400">Confidence: </span>
                    <span className={`font-semibold ${Number(sidePanelInc.confidence) >= 0.8 ? 'text-green-700' : Number(sidePanelInc.confidence) >= 0.5 ? 'text-yellow-700' : 'text-red-600'}`}>
                      {sidePanelInc.confidenceText}
                    </span>
                  </div>
                </div>
              </section>

              {/* Risk Panel */}
              <section>
                <div className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold mb-2">Risk Panel</div>
                <div className="rounded border border-gray-200 bg-gray-50 p-2 font-mono text-[11px] space-y-1">
                  {(() => {
                    const score = dceContext?.risk_score ?? sidePanelInc.riskScore;
                    const level = dceContext?.risk_level ?? sidePanelInc.riskLevel;
                    if (score == null && !level) {
                      return <div className="text-gray-500">Central risk score not available.</div>;
                    }
                    return (
                      <>
                        <div>
                          <span className="text-gray-400">Risk Score: </span>
                          <span className={`font-bold ${Number(score) >= 70 ? 'text-red-600' : Number(score) >= 40 ? 'text-orange-600' : 'text-green-700'}`}>
                            {score ?? 'N/A'}
                          </span>
                        </div>
                        <div><span className="text-gray-400">Risk Level: </span><span className="font-semibold text-gray-800">{level || 'N/A'}</span></div>
                      </>
                    );
                  })()}
                </div>
              </section>

              {/* Affected Entities */}
              {sidePanelInc.affected?.length > 0 && (
                <section>
                  <div className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold mb-2">Affected Entities</div>
                  <div className="flex flex-wrap gap-1">
                    {sidePanelInc.affected.map((e) => (
                      <span key={e} className="px-2 py-0.5 text-[11px] font-mono bg-gray-100 border border-gray-200 rounded">{e}</span>
                    ))}
                  </div>
                </section>
              )}

              {/* Pivot Queries */}
              <section>
                <div className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold mb-2">Pivot Queries</div>
                {buildPivotQueries(sidePanelInc).length === 0 ? (
                  <div className="rounded border border-gray-200 bg-gray-50 p-2 text-[11px] text-gray-500">No pivotable subject fields available.</div>
                ) : (
                  <div className="space-y-2">
                    {buildPivotQueries(sidePanelInc).map((pivot) => (
                      <button
                        key={pivot}
                        type="button"
                        onClick={() => copyToClipboard(pivot)}
                        className="w-full rounded border border-blue-200 bg-blue-50 p-2 text-left hover:bg-blue-100"
                        title="Copy pivot query"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-[10px] font-semibold text-blue-700">Run Pivot</span>
                          <span className="text-[9px] text-blue-500">copy</span>
                        </div>
                        <pre className="mt-1 font-mono text-[10px] text-blue-950 overflow-auto whitespace-pre-wrap">{pivot}</pre>
                      </button>
                    ))}
                  </div>
                )}
                {!sidePanelInc.dest && (
                  <div className="mt-2 rounded border border-yellow-200 bg-yellow-50 p-2 text-[11px] text-yellow-800">Destination not available</div>
                )}
                <ul className="mt-2 space-y-1.5">
                  {(PIVOT_SUGGESTIONS[sidePanelInc.type] || [
                    'Review correlated events in the same time window',
                    'Check for related activity from this source',
                    'Cross-reference with entity risk score'
                  ]).map((pivot) => (
                    <li key={pivot} className="flex items-start gap-1.5 text-[11px] text-gray-600">
                      <ChevronRight className="w-3 h-3 text-gray-400 mt-0.5 flex-shrink-0" />{pivot}
                    </li>
                  ))}
                </ul>
              </section>

              {!incidentPlaybook && investigation && (
                <section>
                  <div className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold mb-2">Investigation Playbook</div>
                  <div className="space-y-3">
                    <div>
                      <div className="text-[10px] text-gray-400 font-semibold mb-1">Triage Checklist</div>
                      <ul className="space-y-1">
                        {getTriageChecklist(sidePanelInc, investigation).map((item) => (
                          <li key={item} className="text-[11px] text-gray-600 flex gap-1.5">
                            <ChevronRight className="w-3 h-3 text-gray-400 mt-0.5 flex-shrink-0" />{item}
                          </li>
                        ))}
                      </ul>
                    </div>
                    <div>
                      <div className="text-[10px] text-gray-400 font-semibold mb-1">Escalation</div>
                      <ul className="space-y-1">
                        {getEscalationItems(investigation).map((condition) => (
                          <li key={condition} className="text-[11px] text-gray-600 flex gap-1.5">
                            <AlertTriangle className="w-3 h-3 text-orange-500 mt-0.5 flex-shrink-0" />{condition}
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </section>
              )}

              {/* Related Incidents */}
              <section>
                <div className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold mb-2">Related Incidents</div>
                <div className="rounded border border-gray-200 bg-gray-50 divide-y divide-gray-200">
                  {getRelatedIncidents(sidePanelInc, incidents).length === 0 ? (
                    <div className="px-2 py-2 text-[11px] text-gray-400">No related incidents by shared user, source IP, or affected entity.</div>
                  ) : getRelatedIncidents(sidePanelInc, incidents).map((related) => (
                    <button
                      key={related.id}
                      type="button"
                      onClick={() => setSidePanelInc(related)}
                      className="w-full px-2 py-2 text-left hover:bg-blue-50"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono text-[10px] text-blue-700">{related.id}</span>
                        <span className={`px-1.5 py-0.5 text-[9px] font-semibold ${STATUS_BADGES[related.status] || STATUS_BADGES.open}`}>{related.status}</span>
                      </div>
                      <div className="mt-0.5 text-[11px] text-gray-700">{related.typeLabel}</div>
                      <div className="font-mono text-[10px] text-gray-400">{related.user} / {related.sourceIp}</div>
                    </button>
                  ))}
                </div>
              </section>

              {/* Evidence */}
              <section>
                <div className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold mb-1">Evidence</div>
                <div className="font-mono text-[11px] text-gray-600">{sidePanelInc.evidence_count ?? 0} events collected</div>
              </section>

              {/* Secure Context — live DCE */}
              <section>
                <div className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold mb-1">Secure Context Layer (DCE)</div>
                <div className="text-[11px] text-gray-500 mb-2">Live DCE context: PII-sanitized, chain-correlated, risk-scored. No raw events or identifiers.</div>
                <pre className="rounded border border-gray-200 bg-gray-50 p-2 font-mono text-[10px] text-gray-600 overflow-auto max-h-44">
                  {dceContext ? JSON.stringify(dceContext, null, 2) : '(loading DCE context…)'}
                </pre>
              </section>

              {/* DCE Risk Score */}
              {dceContext?.risk_score != null && (
                <section>
                  <div className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold mb-2">DCE Risk Engine</div>
                  <div className="rounded border border-gray-200 bg-gray-50 p-2 font-mono text-[11px] space-y-1">
                    <div>
                      <span className="text-gray-400">Risk Score: </span>
                      <span className={`font-bold ${dceContext.risk_score >= 80 ? 'text-red-600' : dceContext.risk_score >= 60 ? 'text-orange-600' : dceContext.risk_score >= 35 ? 'text-yellow-700' : 'text-green-700'}`}>
                        {dceContext.risk_score} / 100
                      </span>
                      {dceContext.risk_level && <span className="ml-2 text-gray-400 text-[10px]">({dceContext.risk_level})</span>}
                    </div>
                    {dceContext.risk_factors && Object.entries(dceContext.risk_factors).map(([k, v]) => (
                      <div key={k}><span className="text-gray-400">{k}: </span><span className="text-gray-700">{v}</span></div>
                    ))}
                  </div>
                </section>
              )}

              {/* DCE Chain Correlation */}
              {dceContext?.chain_correlation && (
                <section>
                  <div className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold mb-2">DCE Chain Correlation</div>
                  <div className="rounded border border-gray-200 bg-gray-50 p-2 font-mono text-[11px] space-y-1">
                    <div><span className="text-gray-400">Stage: </span>{dceContext.chain_correlation.chain_stage || '—'} of {4}</div>
                    <div><span className="text-gray-400">Stages seen: </span>{(dceContext.chain_correlation.stages_observed || []).join(', ') || 'none'}</div>
                    <div>
                      <span className="text-gray-400">Chain complete: </span>
                      <span className={dceContext.chain_correlation.chain_complete ? 'text-red-600 font-semibold' : 'text-green-700'}>
                        {dceContext.chain_correlation.chain_complete ? 'YES — full attack chain' : 'no'}
                      </span>
                    </div>
                    {dceContext.chain_correlation.peer_incidents?.length > 0 && (
                      <div><span className="text-gray-400">Peer incidents: </span><span className="text-gray-700">{dceContext.chain_correlation.peer_incidents.slice(0, 3).join(', ')}</span></div>
                    )}
                  </div>
                </section>
              )}

              {/* SLA */}
              <section>
                <div className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold mb-2">SLA / Time Tracking</div>
                <div className="rounded border border-gray-200 bg-gray-50 p-2 font-mono text-[11px] space-y-1">
                  {(() => {
                    const state = dceContext?.sla_state || (sidePanelInc.sla_breached ? 'breach' : 'ok');
                    const stateColor = state === 'breach' ? 'text-red-600 font-semibold' : state === 'warning' ? 'text-yellow-700 font-semibold' : 'text-green-700';
                    return <div><span className="text-gray-400">State: </span><span className={stateColor}>{state}</span></div>;
                  })()}
                  <div><span className="text-gray-400">Time since alert: </span>{formatDuration(sidePanelInc.time_since_alert_seconds)}</div>
                  <div><span className="text-gray-400">Time in state: </span>{formatDuration(sidePanelInc.time_in_state_seconds)}</div>
                  <div><span className="text-gray-400">Deadline: </span>{dceContext?.sla_deadline_minutes ?? sidePanelInc.sla_deadline_minutes ?? 'N/A'}m</div>
                  {dceContext?.sla_deadline_utc && <div><span className="text-gray-400">Deadline UTC: </span>{formatUtcTimestamp(dceContext.sla_deadline_utc)}</div>}
                  {dceContext?.sla_remaining_seconds != null && <div><span className="text-gray-400">Remaining: </span>{formatDuration(dceContext.sla_remaining_seconds)}</div>}
                  <div><span className="text-gray-400">Effective priority: </span>{dceContext?.effective_priority || sidePanelInc.effective_priority || sidePanelInc.severity}</div>
                  <div><span className="text-gray-400">Action required: </span><span className={sidePanelInc.sla_action_required ? 'text-red-600 font-semibold' : 'text-green-700 font-semibold'}>{sidePanelInc.sla_action_required ? 'escalate' : 'none'}</span></div>
                </div>
              </section>

              {/* Actions */}
              <section>
                <div className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold mb-2">Actions</div>
                <div className="flex flex-col gap-1.5">
                  {canTransitionTo(sidePanelInc, 'acknowledged') && (
                    <button type="button" onClick={() => patchSingle(sidePanelInc.id, 'acknowledged')} disabled={loading} className="px-3 py-1.5 text-xs bg-yellow-500 text-black hover:bg-yellow-400 disabled:opacity-50 font-medium text-left">
                      Acknowledge
                    </button>
                  )}
                  {canTransitionTo(sidePanelInc, 'escalated') && (
                    <button type="button" onClick={() => patchSingle(sidePanelInc.id, 'escalated')} disabled={loading} className="px-3 py-1.5 text-xs border border-orange-300 text-orange-700 hover:bg-orange-50 disabled:opacity-50 font-medium text-left">
                      Escalate
                    </button>
                  )}
                  <button type="button" onClick={() => assignIncident(sidePanelInc.id)} disabled={loading} className="px-3 py-1.5 text-xs border border-blue-300 text-blue-700 hover:bg-blue-50 disabled:opacity-50 font-medium text-left">
                    Assign
                  </button>
                  {canTransitionTo(sidePanelInc, 'closed') && (
                    <button type="button" onClick={() => patchSingle(sidePanelInc.id, 'closed')} disabled={loading} className="px-3 py-1.5 text-xs bg-gray-600 text-white hover:bg-gray-500 disabled:opacity-50 font-medium text-left">
                      Close Incident
                    </button>
                  )}
                </div>
              </section>

              {/* Lifecycle */}
              <section>
                <div className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold mb-2">Lifecycle</div>
                <div className="space-y-1 font-mono text-[11px]">
                  <div><span className="text-gray-400">Created: </span>{formatUtcTimestamp(sidePanelInc.created_at)}</div>
                  <div><span className="text-gray-400">Updated: </span>{formatUtcTimestamp(sidePanelInc.updated_at)}</div>
                  <div><span className="text-gray-400">Assignee: </span>{sidePanelInc.assignee || 'unassigned'}</div>
                  {sidePanelInc.resolution_reason && (
                    <div><span className="text-gray-400">Resolution: </span>{sidePanelInc.resolution_reason}</div>
                  )}
                </div>
              </section>

              {/* Audit Log */}
              <section>
                <div className="text-[10px] uppercase tracking-wider text-gray-400 font-semibold mb-2">Action Audit Log</div>
                <div className="rounded border border-gray-200 bg-gray-50 divide-y divide-gray-200 max-h-44 overflow-auto">
                  {auditEvents.length === 0 ? (
                    <div className="px-2 py-2 text-[11px] text-gray-400">No audit events recorded.</div>
                  ) : auditEvents.map((event, index) => (
                    <div key={`${event.timestamp}-${index}`} className="px-2 py-2">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-semibold text-[11px] text-gray-700">{event.action}</span>
                        <span className="font-mono text-[10px] text-gray-400">{formatUtcTimestamp(event.timestamp)}</span>
                      </div>
                      <div className="font-mono text-[10px] text-gray-500">
                        {event.user} / {event.before_status || '-'} -&gt; {event.after_status || '-'} {event.assignee ? `/ ${event.assignee}` : ''}
                      </div>
                    </div>
                  ))}
                </div>
              </section>
            </div>
          </div>
        )}
      </div>

      {/* Status bar */}
      <div className="border-t border-gray-300 bg-gray-100 px-4 py-1.5 text-xs text-gray-600 flex-shrink-0">
        {activeView === 'incidents'
          ? `${filtered.length} visible of ${incidentCount} total incidents${search ? ` · filtered by "${search}"` : ''}`
          : activeView === 'playbooks'
            ? `${filteredPlaybooks.length} visible of ${playbooks.length} total playbooks${search ? ` · filtered by "${search}"` : ''}`
            : `${filteredEntities.length} visible entities from ${incidentCount} total incidents`}
      </div>
    </div>
  );
}
