import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const outDir = "docs/architecture";
mkdirSync(outDir, { recursive: true });

const W = 2560;
const H = 1440;
const colors = {
  bg: "#f8fafc",
  ink: "#101828",
  muted: "#475467",
  line: "#667085",
  blue: "#dbeafe",
  blueStroke: "#175cd3",
  purple: "#eee9ff",
  purpleStroke: "#6941c6",
  red: "#ffe4e6",
  redStroke: "#b91230",
  green: "#dcfce7",
  greenStroke: "#027a48",
  amber: "#fff7cc",
  amberStroke: "#b54708",
  slate: "#f1f5f9",
  slateStroke: "#475569",
  white: "#ffffff",
};

function esc(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function text(lines, x, y, opts = {}) {
  const arr = Array.isArray(lines) ? lines : String(lines).split("\n");
  const size = opts.size ?? 24;
  const weight = opts.weight ?? 500;
  const color = opts.color ?? colors.ink;
  const anchor = opts.anchor ?? "start";
  const family = "Inter, Segoe UI, Arial, sans-serif";
  return `<text x="${x}" y="${y}" font-family="${family}" font-size="${size}" font-weight="${weight}" fill="${color}" text-anchor="${anchor}">${arr
    .map((line, index) => `<tspan x="${x}" dy="${index === 0 ? 0 : size * 1.35}">${esc(line)}</tspan>`)
    .join("")}</text>`;
}

function rect(x, y, w, h, fill, stroke, opts = {}) {
  return `<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="${opts.rx ?? 14}" fill="${fill}" stroke="${stroke}" stroke-width="${opts.sw ?? 2}"/>`;
}

function box(label, x, y, w, h, fill, stroke, opts = {}) {
  const lines = String(label).split("\n");
  const size = opts.size ?? 22;
  const lineHeight = size * 1.28;
  const startY = y + h / 2 - ((lines.length - 1) * lineHeight) / 2 + size * 0.35;
  return [
    rect(x, y, w, h, fill, stroke, { rx: opts.rx ?? 12, sw: opts.sw ?? 2 }),
    text(lines, x + w / 2, startY, { size, weight: opts.weight ?? 600, anchor: "middle" }),
  ].join("\n");
}

function container(title, subtitle, x, y, w, h, fill, stroke) {
  return [
    rect(x, y, w, h, fill, stroke, { rx: 20, sw: 3 }),
    text(title, x + 30, y + 46, { size: 28, weight: 700 }),
    subtitle ? text(subtitle, x + 30, y + 82, { size: 19, weight: 400, color: colors.muted }) : "",
  ].join("\n");
}

function arrow(x1, y1, x2, y2, label = "") {
  const midX = (x1 + x2) / 2;
  const midY = (y1 + y2) / 2;
  return [
    `<path d="M ${x1} ${y1} L ${x2} ${y2}" stroke="${colors.line}" stroke-width="5" fill="none" marker-end="url(#arrow)"/>`,
    label ? text(label, midX, midY - 16, { size: 18, weight: 600, color: colors.muted, anchor: "middle" }) : "",
  ].join("\n");
}

function legend() {
  const items = [
    ["External systems", colors.blue, colors.blueStroke],
    ["Core processing", colors.purple, colors.purpleStroke],
    ["Security analytics", colors.red, colors.redStroke],
    ["Analyst layer", colors.green, colors.greenStroke],
  ];
  return items
    .map(([label, fill, stroke], index) => {
      const x = 1530 + index * 245;
      return `${rect(x, 76, 28, 28, fill, stroke, { rx: 6, sw: 2 })}${text(label, x + 42, 98, {
        size: 20,
        weight: 600,
        color: colors.muted,
      })}`;
    })
    .join("\n");
}

function frame(title, subtitle, body) {
  return `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(title)}">
  <defs>
    <marker id="arrow" markerWidth="14" markerHeight="14" refX="12" refY="7" orient="auto" markerUnits="strokeWidth">
      <path d="M 0 0 L 14 7 L 0 14 z" fill="${colors.line}"/>
    </marker>
  </defs>
  <rect width="${W}" height="${H}" fill="${colors.bg}"/>
  <rect x="1" y="1" width="${W - 2}" height="${H - 2}" fill="none" stroke="#cbd5e1" stroke-width="2"/>
  ${text(title, 80, 96, { size: 50, weight: 800 })}
  ${text(subtitle, 84, 140, { size: 24, weight: 400, color: colors.muted })}
  ${legend()}
  ${body}
</svg>
`;
}

const overview = frame(
  "A. SecureWatch System Overview",
  "High-level SOC data flow from telemetry to analyst action.",
  [
    container("Tier 1: External Systems", "Telemetry, lab inputs, and validation sources outside the backend boundary", 100, 210, 2360, 170, colors.blue, colors.blueStroke),
    ["Wazuh", "Sysmon", "Windows Logs", "EDR Events", "API Sources", "Lab Inputs"]
      .map((item, i) => box(item, 150 + i * 380, 300, 300, 52, colors.white, colors.blueStroke, { size: 18 }))
      .join("\n"),
    container("Tier 2: Core Processing", "Deterministic ingestion, normalization, queueing, and stateful correlation", 100, 460, 2360, 220, colors.purple, colors.purpleStroke),
    ["Ingestion API", "Schema Validation", "Normalization", "Event Bus", "Correlation Engine", "Risk Engine"]
      .map((item, i) => box(item, 150 + i * 380, 555, 300, 72, colors.white, colors.purpleStroke))
      .join("\n"),
    container("Tier 3: Security Analytics", "Detection engineering outputs: MITRE mapping, scoring, evidence, and incidents", 100, 760, 2360, 220, colors.red, colors.redStroke),
    ["Detection Rules", "MITRE Enrichment", "Confidence Scoring", "Incident Builder", "Deduplication", "SLA Tagging"]
      .map((item, i) => box(item, 150 + i * 380, 855, 300, 72, colors.white, colors.redStroke))
      .join("\n"),
    container("Tier 4: Analyst Layer", "SOC workflows exposed through APIs and the React dashboard", 100, 1060, 2360, 210, colors.green, colors.greenStroke),
    ["Incident Registry", "Entity Risk", "Playbooks", "Investigation Workflow", "Metrics", "React Dashboard"]
      .map((item, i) => box(item, 150 + i * 380, 1152, 300, 72, colors.white, colors.greenStroke))
      .join("\n"),
    arrow(1280, 380, 1280, 460, "accepted events"),
    arrow(1280, 680, 1280, 760, "candidate findings"),
    arrow(1280, 980, 1280, 1060, "actionable incidents"),
    rect(1540, 1300, 820, 72, colors.amber, colors.amberStroke, { rx: 10, sw: 1.5 }),
    text("Frame is 2560 x 1440. Export PNG 2x, SVG, or PDF.", 1560, 1344, { size: 18, weight: 500 }),
  ].join("\n"),
);

const backend = frame(
  "B. Backend Architecture",
  "Detailed service boundaries for the backend-first detection engineering platform.",
  [
    container("Public API Trust Boundary", "Authentication, authorization, rate limits, validation, and trace context at ingress", 120, 210, 2320, 185, colors.slate, colors.slateStroke),
    ["FastAPI Ingestion", "AI Validation API", "JWT/API Keys", "RBAC Middleware", "Tenant Scope", "Trace IDs"]
      .map((item, i) => box(item, 170 + i * 370, 305, 285, 52, colors.white, colors.slateStroke, { size: 18 }))
      .join("\n"),
    container("Core Processing Boundary", "Async services that normalize, queue, consume, and maintain detection state", 120, 455, 1100, 570, colors.purple, colors.purpleStroke),
    box("Normalization Service\nYAML mappings + canonical schema", 180, 555, 430, 95, colors.white, colors.purpleStroke),
    box("Event Bus\nKafka or Redis Streams", 700, 555, 430, 95, colors.white, colors.purpleStroke),
    box("Async Worker Pool\npartitioned by tenant/entity", 180, 745, 430, 95, colors.white, colors.purpleStroke),
    box("Correlation Engine\nwindows + sessionization", 700, 745, 430, 95, colors.white, colors.purpleStroke),
    ["Retry Queue", "Dead-letter Queue", "Worker Health"].map((item, i) => box(item, 180 + i * 320, 925, 270, 60, colors.white, colors.amberStroke, { size: 20 })).join("\n"),
    container("Analytics Boundary", "Detections, AI validation, scoring, and incident construction", 1340, 455, 1100, 570, colors.red, colors.redStroke),
    box("Detection Engine\nrule + Sigma-compatible logic", 1400, 555, 430, 95, colors.white, colors.redStroke),
    box("AI Security Layer\nsemantic + DLP + policy checks", 1920, 555, 430, 95, colors.white, colors.redStroke),
    box("Risk Engine\nentity score + decay", 1400, 745, 430, 95, colors.white, colors.redStroke),
    box("Incident Builder\nSHA-256 IDs + evidence merge", 1920, 745, 430, 95, colors.white, colors.redStroke),
    ["Playbook Resolver", "Severity + SLA", "Audit Writer"].map((item, i) => box(item, 1400 + i * 320, 925, 270, 60, colors.white, colors.redStroke, { size: 20 })).join("\n"),
    container("Persistence Boundary", "Durable stores with tenant-aware access patterns", 120, 1090, 1120, 220, colors.green, colors.greenStroke),
    ["PostgreSQL\nincidents, risk, users, tenants", "Object Storage\nraw evidence, logs, AI artifacts", "Redis\ncache, sessions, correlation windows"].map((item, i) => box(item, 180 + i * 350, 1180, 300, 78, colors.white, colors.greenStroke, { size: 18 })).join("\n"),
    container("Internal API + Dashboard Boundary", "Tenant-scoped APIs consumed by analyst workflows", 1340, 1090, 1100, 220, colors.green, colors.greenStroke),
    ["REST API", "Incident APIs", "Risk APIs", "Playbook APIs", "React SOC"].map((item, i) => box(item, 1400 + i * 200, 1190, 165, 58, colors.white, colors.greenStroke, { size: 18 })).join("\n"),
    arrow(1280, 395, 1280, 455, "validated requests"),
    arrow(1220, 745, 1340, 745, "findings"),
    arrow(1890, 1025, 1890, 1090, "incident state"),
    arrow(700, 1025, 700, 1090, "writes"),
  ].join("\n"),
);

const detection = frame(
  "C. Detection Pipeline",
  "Focused drill-down from raw event to deterministic incident generation.",
  [
    container("Raw Event Intake", "Sysmon, Windows events, Wazuh alerts, authentication logs, EDR telemetry, and JSON API payloads", 220, 215, 2120, 150, colors.blue, colors.blueStroke),
    box("Raw Event\nsource payload + tenant + trace ID", 930, 285, 700, 70, colors.white, colors.blueStroke),
    container("Normalization and Enrichment", "Convert vendor-specific payloads into canonical, queryable security events", 220, 445, 2120, 205, colors.purple, colors.purpleStroke),
    ["YAML Field Mapping", "Pydantic v2 Validation", "Canonical Event Schema", "Entity Extraction", "MITRE ATT&CK Mapping"].map((item, i) => box(item, 310 + i * 390, 535, 300, 68, colors.white, colors.purpleStroke, { size: 20 })).join("\n"),
    container("Detection and Correlation", "Stateful detection logic over sliding windows and linked entities", 220, 735, 2120, 250, colors.red, colors.redStroke),
    ["Rule Detections", "Threshold Detections", "Behavioral Detections", "Sliding Windows", "Sessionization", "Cross-event Correlation"].map((item, i) => box(item, 300 + (i % 3) * 650, 815 + Math.floor(i / 3) * 90, 430, 64, colors.white, colors.redStroke, { size: 20 })).join("\n"),
    container("Risk and Incident Generation", "Deterministic incident assembly for SOC triage and lifecycle tracking", 220, 1070, 2120, 230, colors.green, colors.greenStroke),
    ["Entity Risk Scoring", "Risk Decay", "Confidence Scoring", "SHA-256 Incident ID", "Deduplication", "Evidence Merge", "Severity + SLA"].map((item, i) => box(item, 300 + i * 300, 1172, 230, 58, colors.white, colors.greenStroke, { size: 18 })).join("\n"),
    arrow(1280, 365, 1280, 445, "accepted event"),
    arrow(1280, 650, 1280, 735, "canonical event"),
    arrow(1280, 985, 1280, 1070, "scored finding"),
    rect(520, 1320, 1520, 72, colors.amber, colors.amberStroke, { rx: 10, sw: 1.5 }),
    text("Output: incident record, evidence timeline, risk metadata, playbook linkage, and audit trail.", 550, 1364, { size: 18, weight: 500 }),
  ].join("\n"),
);

const infrastructure = frame(
  "D. Infrastructure and Deployment",
  "MVP deployment path with clear future scaling boundaries.",
  [
    container("Lab and Telemetry Environment", "Security lab sources and enterprise telemetry producers", 130, 220, 2300, 170, colors.blue, colors.blueStroke),
    ["Windows VM\nSysmon", "Wazuh Agent", "EDR Sensor", "API Clients", "Synthetic AI Tests"].map((item, i) => box(item, 230 + i * 430, 300, 330, 64, colors.white, colors.blueStroke, { size: 20 })).join("\n"),
    container("Docker Compose MVP Boundary", "Early-stage deployment optimized for demos, validation, and local SOC workflow testing", 130, 465, 1080, 610, colors.purple, colors.purpleStroke),
    box("securewatch-api\nFastAPI + REST endpoints", 210, 560, 400, 80, colors.white, colors.purpleStroke),
    box("securewatch-worker\ndetections + AI validation", 710, 560, 400, 80, colors.white, colors.purpleStroke),
    box("postgres\nincidents + users + tenants", 210, 760, 400, 80, colors.white, colors.greenStroke),
    box("redis\ncache + queue + windows", 710, 760, 400, 80, colors.white, colors.greenStroke),
    box("dashboard\nReact build served by API", 460, 940, 400, 80, colors.white, colors.greenStroke),
    container("Production Future Boundary", "Scalable deployment target for commercial SOC/SIEM evolution", 1350, 465, 1080, 610, colors.red, colors.redStroke),
    box("Kubernetes Cluster\nhorizontal services", 1430, 560, 400, 80, colors.white, colors.redStroke),
    box("Managed Event Bus\nKafka partitions", 1930, 560, 400, 80, colors.white, colors.redStroke),
    box("Worker Autoscaling\nconsumer groups", 1430, 760, 400, 80, colors.white, colors.redStroke),
    box("Tenant Isolation\nrow-level + namespace controls", 1930, 760, 400, 80, colors.white, colors.redStroke),
    box("Multi-region Future\nDR + regional data plane", 1680, 940, 400, 80, colors.white, colors.redStroke),
    container("Operational Controls", "Reliability, observability, and security controls required for SOC operations", 130, 1155, 2300, 170, colors.slate, colors.slateStroke),
    ["Prometheus", "Grafana", "Structured Logs", "Audit Logs", "Trace IDs", "Secrets Mgmt", "Rate Limits", "Secure Worker Comms"].map((item, i) => box(item, 220 + i * 280, 1245, 220, 52, colors.white, colors.slateStroke, { size: 18 })).join("\n"),
    arrow(1280, 390, 1280, 465, "deployment boundary"),
    arrow(1210, 760, 1350, 760, "scale path"),
    rect(680, 1350, 1200, 60, colors.amber, colors.amberStroke, { rx: 10, sw: 1.5 }),
    text("Export each frame independently; no infinite-canvas whitespace.", 1280, 1388, { size: 18, weight: 600, anchor: "middle" }),
  ].join("\n"),
);

const files = [
  ["securewatch-system-overview.svg", overview],
  ["securewatch-backend-architecture.svg", backend],
  ["securewatch-detection-pipeline.svg", detection],
  ["securewatch-infrastructure-deployment.svg", infrastructure],
];

for (const [name, data] of files) {
  writeFileSync(join(outDir, name), data, "utf8");
}

console.log(`Wrote ${files.length} architecture SVG frames to ${outDir}`);
