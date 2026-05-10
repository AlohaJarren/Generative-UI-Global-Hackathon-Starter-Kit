"use client";

import type { ReactNode } from "react";
import { useMemo, useState } from "react";
import {
  AlertTriangle,
  Ban,
  CheckCircle2,
  Clock3,
  Code2,
  Database,
  Eye,
  FileWarning,
  Fingerprint,
  GitBranch,
  KeyRound,
  LayoutDashboard,
  Loader2,
  LockKeyhole,
  Network,
  Play,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  TerminalSquare,
  XCircle,
  Zap
} from "lucide-react";
import { DecisionImpactCenter } from "./DecisionImpactCenter";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";

type RiskTier = "Critical" | "High" | "Medium" | "Low";
type Status = "Pending" | "Approved" | "Quarantined" | "Denied";

type McpTool = {
  id: string;
  name: string;
  server: string;
  category: string;
  owner: string;
  score: number;
  tier: RiskTier;
  status: Status;
  scopes: string[];
  actions: string[];
  dataAccess: string;
  authMode: string;
  risks: string[];
  recommendation: string;
  dataClasses?: string[];
  trustBoundary?: string;
  privileges?: string[];
  missingControls?: string[];
  blastRadius?: string;
  businessImpact?: string;
};

type Approval = {
  id: string;
  title: string;
  toolName: string;
  action: string;
  tier: RiskTier;
  reason: string;
  recommendedDecision: "Approve" | "Quarantine" | "Deny";
  evidenceNeeded?: string[];
};

type RiskCockpitSpec = {
  title: string;
  subtitle: string;
  generatedFor: string;
  sections: Array<{
    type:
      | "hero"
      | "metrics"
      | "bar_chart"
      | "line_chart"
      | "tool_cards"
      | "approval_queue"
      | "policy_preview"
      | "threat_model"
      | "action_plan"
      | "attack_path"
      | "simulation_lab"
      | "evidence_timeline"
      | "control_roadmap"
      | "compliance_map"
      | "decision_diff"
      | "risk_register"
      | "architecture_map";
    title?: string;
    subtitle?: string;
    content?: string;
    metrics?: Array<{
      label: string;
      value: string;
      detail: string;
      tier: RiskTier;
    }>;
    data?: Array<Record<string, string | number>>;
    tools?: McpTool[];
    approvals?: Approval[];
    policy?: {
      defaultDecision: string;
      requireHumanApprovalFor: string[];
      allowedReadOnlyScopes: string[];
      blockedActions: string[];
      guardrails: string[];
      auditEvents?: string[];
    };
    threats?: Array<{
      title: string;
      scenario: string;
      impact: string;
      control: string;
      tier: RiskTier;
      affectedTools?: string[];
    }>;
    actions?: Array<{
      priority: "P0" | "P1" | "P2";
      title: string;
      owner: string;
      outcome: string;
      effort?: "Low" | "Medium" | "High";
    }>;
    attackPaths?: Array<{
      id: string;
      title: string;
      entryPoint: string;
      target: string;
      tier: RiskTier;
      steps: string[];
      impact: string;
      blockedBy: string[];
    }>;
    simulations?: Array<{
      id: string;
      title: string;
      toolName: string;
      maliciousInput: string;
      unsafeOutcome: string;
      guardedOutcome: string;
      controlsTriggered: string[];
      tier: RiskTier;
    }>;
    evidence?: Array<{
      time: string;
      source: string;
      event: string;
      summary: string;
      tier: RiskTier;
    }>;
    controls?: Array<{
      phase: string;
      title: string;
      owner: string;
      status: "Not Started" | "In Progress" | "Ready" | "Blocked";
      effort: "Low" | "Medium" | "High";
      impact: RiskTier;
      tasks: string[];
    }>;
    compliance?: Array<{
      framework: string;
      control: string;
      coverage: "Strong" | "Partial" | "Missing";
      gap: string;
      evidence: string;
      tier: RiskTier;
    }>;
    decisions?: Array<{
      scenario: string;
      withoutCockpit: string;
      withCockpit: string;
      userDecision: "Approve" | "Quarantine" | "Deny" | "Needs Review";
      tier: RiskTier;
    }>;
    risks?: Array<{
      id: string;
      risk: string;
      affectedTools: string[];
      likelihood: "Low" | "Medium" | "High";
      impact: "Low" | "Medium" | "High";
      score: number;
      owner: string;
      status: "Open" | "Mitigating" | "Accepted" | "Closed";
      nextAction: string;
    }>;
    nodes?: Array<{
      id: string;
      label: string;
      kind: "Agent" | "MCP Server" | "Tool" | "Data" | "Human" | "Policy";
      tier: RiskTier;
      note: string;
    }>;
    edges?: Array<{
      from: string;
      to: string;
      label: string;
      tier: RiskTier;
    }>;
  }>;
};

const riskColors: Record<RiskTier, string> = {
  Critical: "#ef4444",
  High: "#f97316",
  Medium: "#eab308",
  Low: "#22c55e"
};

const statusStyles: Record<Status, string> = {
  Pending: "border-yellow-400/40 bg-yellow-400/10 text-yellow-100",
  Approved: "border-emerald-400/40 bg-emerald-400/10 text-emerald-100",
  Quarantined: "border-orange-400/40 bg-orange-400/10 text-orange-100",
  Denied: "border-red-400/40 bg-red-400/10 text-red-100"
};

const starterPrompts = [
  "Generate an enterprise MCP security cockpit that shows attack paths, approval gates, blast radius, audit evidence, and the next controls to implement.",
  "Create a red-team investigation workspace for prompt injection, MCP tool poisoning, and data exfiltration across the MCP inventory.",
  "Generate an executive risk board that explains business impact, high-risk tools, approval decisions, and compliance gaps.",
  "Build a human-in-the-loop approval center for every MCP tool that can write data, execute code, change identity, issue refunds, or post messages.",
  "Generate a least-privilege policy review with allowed scopes, blocked actions, audit events, and a 30-day control roadmap."
];

function getFallbackSpec(): RiskCockpitSpec {
  return {
    title: "MCP Risk Cockpit",
    subtitle:
      "Ask the agent to generate an investigation workspace, executive dashboard, approval center, or red-team simulation from the MCP inventory.",
    generatedFor: "Initial view",
    sections: [
      {
        type: "hero",
        title: "Dynamic Generative UI Mode",
        subtitle:
          "The model chooses which security interface to render based on your prompt.",
        content:
          "This page uses a constrained component registry. Gemini returns a JSON UI spec, then React renders safe sections such as attack paths, approval queues, policy previews, risk registers, and simulation labs."
      },
      {
        type: "metrics",
        title: "Why this matters",
        metrics: [
          { label: "UI source", value: "Model", detail: "runtime spec", tier: "Low" },
          { label: "MCP tools", value: "8", detail: "mock inventory", tier: "High" },
          { label: "Critical paths", value: "4", detail: "write or execute", tier: "Critical" },
          { label: "Human gates", value: "6", detail: "approval layer", tier: "Medium" }
        ]
      },
      {
        type: "action_plan",
        title: "Try a high-impact prompt",
        actions: [
          {
            priority: "P0",
            title:
              "Generate an enterprise MCP security cockpit that shows attack paths, approval gates, blast radius, audit evidence, and the next controls to implement.",
            owner: "You",
            outcome:
              "The app should render multiple sections selected by the model rather than a fixed dashboard.",
            effort: "Low"
          }
        ]
      }
    ]
  };
}

function classNames(...classes: Array<string | false | undefined>) {
  return classes.filter(Boolean).join(" ");
}

function safeArray<T>(value: T[] | undefined): T[] {
  return Array.isArray(value) ? value : [];
}

function getTierFromNumber(value: number): RiskTier {
  if (value >= 90) return "Critical";
  if (value >= 70) return "High";
  if (value >= 45) return "Medium";
  return "Low";
}

function getStatusIcon(status: Status) {
  if (status === "Approved") return <CheckCircle2 className="h-4 w-4" />;
  if (status === "Denied") return <XCircle className="h-4 w-4" />;
  if (status === "Quarantined") return <Ban className="h-4 w-4" />;
  return <Clock3 className="h-4 w-4" />;
}

function getTierIcon(tier: RiskTier) {
  if (tier === "Critical") return <ShieldAlert className="h-4 w-4" />;
  if (tier === "High") return <AlertTriangle className="h-4 w-4" />;
  if (tier === "Medium") return <FileWarning className="h-4 w-4" />;
  return <ShieldCheck className="h-4 w-4" />;
}

export function McpRiskCockpit() {
  const [prompt, setPrompt] = useState(starterPrompts[0]);
  const [spec, setSpec] = useState<RiskCockpitSpec>(getFallbackSpec());
  const [isGenerating, setIsGenerating] = useState(false);
  const [warning, setWarning] = useState<string | null>(null);
  const [lastGeneratedAt, setLastGeneratedAt] = useState<string | null>(null);

  async function generateUi(nextPrompt = prompt) {
    setPrompt(nextPrompt);
    setIsGenerating(true);
    setWarning(null);

    try {
      const response = await fetch("/api/risk-cockpit/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prompt: nextPrompt })
      });

      const data = await response.json();

      if (data.warning) setWarning(data.warning);
      setSpec(data.spec || getFallbackSpec());
      setLastGeneratedAt(new Date().toLocaleTimeString());
    } catch (error) {
      setWarning(error instanceof Error ? error.message : String(error));
      setSpec(getFallbackSpec());
    } finally {
      setIsGenerating(false);
    }
  }

  const sectionCounts = useMemo(() => {
    return spec.sections
      .reduce<Record<string, number>>((acc, section) => {
        acc[section.type] = (acc[section.type] || 0) + 1;
        return acc;
      }, {});
  }, [spec.sections]);

  const sectionCountText = Object.entries(sectionCounts)
    .map(([key, value]) => `${key}: ${value}`)
    .join(" | ");

  return (
    <main className="min-h-screen bg-slate-950 text-slate-50">
      <div className="absolute inset-0 -z-10 bg-[radial-gradient(circle_at_top_left,rgba(56,189,248,0.18),transparent_35%),radial-gradient(circle_at_top_right,rgba(239,68,68,0.16),transparent_32%),linear-gradient(180deg,#020617,#020617)]" />

      <section className="mx-auto flex w-full max-w-7xl flex-col gap-6 px-5 py-6 md:px-8">
        <header className="rounded-[2rem] border border-white/10 bg-white/[0.04] p-6 shadow-2xl shadow-black/40 backdrop-blur">
          <div className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
            <div className="max-w-3xl">
              <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-cyan-400/30 bg-cyan-400/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.25em] text-cyan-100">
                <Sparkles className="h-3.5 w-3.5" />
                Dynamic MCP Generative UI
              </div>
              <h1 className="text-4xl font-semibold tracking-tight text-white md:text-6xl">
                {spec.title}
              </h1>
              <p className="mt-4 max-w-2xl text-sm leading-6 text-slate-300 md:text-base">
                {spec.subtitle}
              </p>
            </div>

            <div className="rounded-3xl border border-white/10 bg-black/20 p-4 text-sm text-slate-300">
              <p className="flex items-center gap-2 font-semibold text-cyan-100">
                <LayoutDashboard className="h-4 w-4" />
                Runtime UI contract
              </p>
              <p className="mt-2 max-w-sm leading-6">
                User request to Gemini JSON spec to safe React component registry.
              </p>
              <p className="mt-2 text-xs text-slate-500">
                Sections: {sectionCountText || "none"}
              </p>
              {lastGeneratedAt ? (
                <p className="mt-1 text-xs text-slate-500">Last generated: {lastGeneratedAt}</p>
              ) : null}
            </div>
          </div>
        </header>

        <section className="rounded-[2rem] border border-white/10 bg-white/[0.04] p-5 shadow-xl shadow-black/30">
          <div className="mb-4 flex items-center gap-2 text-sm font-semibold text-white">
            <Zap className="h-4 w-4 text-cyan-300" />
            Ask the agent to generate a security interface
          </div>

          <div className="grid gap-3 lg:grid-cols-[1fr_auto]">
            <textarea
              value={prompt}
              onChange={(event) => setPrompt(event.target.value)}
              className="min-h-32 rounded-3xl border border-white/10 bg-slate-950 p-4 text-sm leading-6 text-slate-100 outline-none ring-cyan-400/30 placeholder:text-slate-500 focus:ring-4"
              placeholder="Example: Generate an enterprise MCP security cockpit with attack paths, approval gates, blast radius, and audit evidence."
            />

            <button
              onClick={() => generateUi()}
              disabled={isGenerating}
              className="inline-flex min-w-44 items-center justify-center gap-2 rounded-3xl bg-cyan-300 px-5 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-200 disabled:cursor-not-allowed disabled:opacity-70"
            >
              {isGenerating ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
              Generate UI
            </button>
          </div>

          <div className="mt-4 flex flex-wrap gap-2">
            {starterPrompts.map((item) => (
              <button
                key={item}
                onClick={() => generateUi(item)}
                className="rounded-full border border-white/10 bg-white/[0.05] px-3 py-2 text-left text-xs leading-5 text-slate-300 transition hover:border-cyan-400/40 hover:bg-cyan-400/10 hover:text-cyan-50"
              >
                {item}
              </button>
            ))}
          </div>

          {warning ? (
            <div className="mt-4 rounded-2xl border border-yellow-400/30 bg-yellow-400/10 p-3 text-sm text-yellow-100">
              {warning}
            </div>
          ) : null}
        </section>

        <DecisionImpactCenter />

        <section className="grid gap-4">
          {spec.sections.map((section, index) => (
            <GeneratedSection key={`${section.type}-${index}`} section={section} />
          ))}
        </section>
      </section>
    </main>
  );
}

function GeneratedSection({ section }: { section: RiskCockpitSpec["sections"][number] }) {
  switch (section.type) {
    case "hero":
      return <HeroSection section={section} />;
    case "metrics":
      return <MetricsSection section={section} />;
    case "bar_chart":
      return <ChartSection section={section} variant="bar" />;
    case "line_chart":
      return <ChartSection section={section} variant="line" />;
    case "tool_cards":
      return <ToolCardsSection section={section} />;
    case "approval_queue":
      return <ApprovalQueueSection section={section} />;
    case "policy_preview":
      return <PolicySection section={section} />;
    case "threat_model":
      return <ThreatModelSection section={section} />;
    case "action_plan":
      return <ActionPlanSection section={section} />;
    case "attack_path":
      return <AttackPathSection section={section} />;
    case "simulation_lab":
      return <SimulationLabSection section={section} />;
    case "evidence_timeline":
      return <EvidenceTimelineSection section={section} />;
    case "control_roadmap":
      return <ControlRoadmapSection section={section} />;
    case "compliance_map":
      return <ComplianceMapSection section={section} />;
    case "decision_diff":
      return <DecisionDiffSection section={section} />;
    case "risk_register":
      return <RiskRegisterSection section={section} />;
    case "architecture_map":
      return <ArchitectureMapSection section={section} />;
    default:
      return null;
  }
}

function SectionShell({
  title,
  subtitle,
  icon,
  children
}: {
  title?: string;
  subtitle?: string;
  icon?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="rounded-[2rem] border border-white/10 bg-white/[0.04] p-5 shadow-xl shadow-black/30">
      {(title || subtitle) && (
        <div className="mb-5 flex items-start justify-between gap-4">
          <div>
            {title ? <h2 className="text-lg font-semibold text-white">{title}</h2> : null}
            {subtitle ? <p className="mt-1 text-sm leading-6 text-slate-400">{subtitle}</p> : null}
          </div>
          {icon ? <div className="text-cyan-300">{icon}</div> : null}
        </div>
      )}
      {children}
    </section>
  );
}

function HeroSection({ section }: { section: RiskCockpitSpec["sections"][number] }) {
  return (
    <section className="overflow-hidden rounded-[2rem] border border-cyan-400/20 bg-cyan-400/10 p-6 shadow-xl shadow-cyan-950/30">
      <div className="flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-cyan-300/30 bg-cyan-300/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.2em] text-cyan-100">
            <Sparkles className="h-3.5 w-3.5" />
            Model-selected interface
          </div>
          <h2 className="text-3xl font-semibold text-white md:text-4xl">{section.title}</h2>
          {section.subtitle ? (
            <p className="mt-3 max-w-3xl text-sm leading-6 text-cyan-50/85">{section.subtitle}</p>
          ) : null}
        </div>
        <div className="rounded-3xl border border-white/10 bg-slate-950/60 p-4 text-sm leading-6 text-slate-300">
          {section.content}
        </div>
      </div>
    </section>
  );
}

function MetricsSection({ section }: { section: RiskCockpitSpec["sections"][number] }) {
  return (
    <SectionShell title={section.title} subtitle={section.subtitle} icon={<LayoutDashboard className="h-5 w-5" />}>
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        {safeArray(section.metrics).map((metric) => (
          <div key={`${metric.label}-${metric.value}`} className="rounded-3xl border border-white/10 bg-black/25 p-4">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">{metric.label}</p>
            <div className="mt-3 flex items-end justify-between gap-3">
              <span className="text-4xl font-semibold text-white">{metric.value}</span>
              <span
                className="rounded-full px-2 py-1 text-xs font-semibold"
                style={{ background: `${riskColors[metric.tier]}22`, color: riskColors[metric.tier] }}
              >
                {metric.detail}
              </span>
            </div>
          </div>
        ))}
      </div>
    </SectionShell>
  );
}

function ChartSection({
  section,
  variant
}: {
  section: RiskCockpitSpec["sections"][number];
  variant: "bar" | "line";
}) {
  const data = safeArray(section.data);
  const first = data[0] || {};
  const keys = Object.keys(first);
  const labelKey = keys[0] || "label";
  const valueKey = keys.find((key) => key !== labelKey && typeof first[key] === "number") || "value";

  return (
    <SectionShell
      title={section.title}
      subtitle={section.subtitle}
      icon={variant === "bar" ? <Database className="h-5 w-5" /> : <RefreshCw className="h-5 w-5" />}
    >
      <div className="h-80 rounded-3xl border border-white/10 bg-black/20 p-4">
        <ResponsiveContainer width="100%" height="100%">
          {variant === "bar" ? (
            <BarChart data={data}>
              <CartesianGrid stroke="rgba(148,163,184,0.12)" vertical={false} />
              <XAxis dataKey={labelKey} stroke="rgba(226,232,240,0.55)" fontSize={12} />
              <YAxis stroke="rgba(226,232,240,0.55)" fontSize={12} />
              <Tooltip contentStyle={tooltipStyle} />
              <Bar dataKey={valueKey} radius={[10, 10, 0, 0]}>
                {data.map((entry, index) => {
                  const value = Number(entry[valueKey] || 0);
                  return <Cell key={index} fill={riskColors[getTierFromNumber(value)]} />;
                })}
              </Bar>
            </BarChart>
          ) : (
            <LineChart data={data}>
              <CartesianGrid stroke="rgba(148,163,184,0.12)" vertical={false} />
              <XAxis dataKey={labelKey} stroke="rgba(226,232,240,0.55)" fontSize={12} />
              <YAxis stroke="rgba(226,232,240,0.55)" fontSize={12} />
              <Tooltip contentStyle={tooltipStyle} />
              <Line type="monotone" dataKey={valueKey} stroke="#38bdf8" strokeWidth={3} dot={{ r: 4 }} />
            </LineChart>
          )}
        </ResponsiveContainer>
      </div>
    </SectionShell>
  );
}

const tooltipStyle = {
  background: "#020617",
  border: "1px solid rgba(255,255,255,0.12)",
  borderRadius: "16px",
  color: "#e2e8f0"
};

function ToolCardsSection({ section }: { section: RiskCockpitSpec["sections"][number] }) {
  return (
    <SectionShell title={section.title} subtitle={section.subtitle} icon={<Network className="h-5 w-5" />}>
      <div className="grid gap-4 lg:grid-cols-2">
        {safeArray(section.tools).map((tool) => (
          <div key={tool.id} className="rounded-3xl border border-white/10 bg-black/20 p-4">
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <h3 className="text-base font-semibold text-white">{tool.name}</h3>
                  <span className={classNames("inline-flex items-center gap-1 rounded-full border px-2 py-1 text-xs", statusStyles[tool.status])}>
                    {getStatusIcon(tool.status)}
                    {tool.status}
                  </span>
                </div>
                <p className="mt-1 text-xs text-slate-400">
                  {tool.server} - {tool.owner} - {tool.category}
                </p>
              </div>
              <div className="text-right">
                <p className="text-3xl font-semibold" style={{ color: riskColors[tool.tier] }}>
                  {tool.score}
                </p>
                <p className="flex items-center justify-end gap-1 text-xs" style={{ color: riskColors[tool.tier] }}>
                  {getTierIcon(tool.tier)}
                  {tool.tier}
                </p>
              </div>
            </div>

            <div className="mt-4 grid gap-3 md:grid-cols-2">
              <InfoBox icon={<Database className="h-4 w-4" />} label="Data access" value={tool.dataAccess} />
              <InfoBox icon={<LockKeyhole className="h-4 w-4" />} label="Trust boundary" value={tool.trustBoundary || "Agent to tool"} />
              <InfoBox icon={<Zap className="h-4 w-4" />} label="Blast radius" value={tool.blastRadius || "Tool-specific"} />
              <InfoBox icon={<KeyRound className="h-4 w-4" />} label="Auth mode" value={tool.authMode} />
            </div>

            <TagGroup title="Scopes" values={safeArray(tool.scopes)} tone={tool.tier} />
            <TagGroup title="Sensitive data classes" values={safeArray(tool.dataClasses)} tone="High" />
            <TagGroup title="Missing controls" values={safeArray(tool.missingControls)} tone="Critical" />

            <div className="mt-4 rounded-2xl border border-orange-400/20 bg-orange-400/10 p-3">
              <p className="text-sm font-semibold text-orange-100">Recommendation</p>
              <p className="mt-1 text-sm leading-6 text-orange-50/85">{tool.recommendation}</p>
            </div>

            {tool.businessImpact ? (
              <div className="mt-3 rounded-2xl border border-cyan-400/20 bg-cyan-400/10 p-3">
                <p className="text-sm font-semibold text-cyan-100">Business impact</p>
                <p className="mt-1 text-sm leading-6 text-cyan-50/85">{tool.businessImpact}</p>
              </div>
            ) : null}
          </div>
        ))}
      </div>
    </SectionShell>
  );
}

function ApprovalQueueSection({ section }: { section: RiskCockpitSpec["sections"][number] }) {
  const [decisions, setDecisions] = useState<Record<string, string>>({});

  function commitDecision(approval: Approval, decision: "Approve" | "Quarantine" | "Deny") {
    setDecisions((current) => ({ ...current, [approval.id]: decision }));

    window.dispatchEvent(
      new CustomEvent("mcp-risk-decision", {
        detail: {
          ...approval,
          decision,
          decidedAt: new Date().toISOString()
        }
      })
    );
  }

  return (
    <SectionShell title={section.title} subtitle={section.subtitle} icon={<Eye className="h-5 w-5" />}>
      <div className="space-y-3">
        {safeArray(section.approvals).map((approval) => {
          const decision = decisions[approval.id] || approval.recommendedDecision;

          return (
            <div key={approval.id} className="rounded-3xl border border-white/10 bg-black/20 p-4">
              <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-start">
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <TierPill tier={approval.tier} />
                    <span className="rounded-full border border-white/10 bg-white/[0.05] px-2 py-1 text-xs text-slate-300">
                      {approval.action}
                    </span>
                    <span className="rounded-full border border-cyan-400/20 bg-cyan-400/10 px-2 py-1 text-xs text-cyan-100">
                      Decision: {decision}
                    </span>
                  </div>
                  <h3 className="mt-3 text-base font-semibold text-white">{approval.title}</h3>
                  <p className="mt-1 text-sm text-slate-400">{approval.toolName}</p>
                  <p className="mt-3 text-sm leading-6 text-slate-300">{approval.reason}</p>
                  <TagGroup title="Evidence needed" values={safeArray(approval.evidenceNeeded)} tone="Medium" />
                </div>

                <div className="flex shrink-0 flex-wrap gap-2">
                  <button
                    onClick={() => commitDecision(approval, "Approve")}
                    className="rounded-full bg-emerald-400 px-3 py-2 text-xs font-semibold text-slate-950"
                  >
                    Approve
                  </button>
                  <button
                    onClick={() => commitDecision(approval, "Quarantine")}
                    className="rounded-full bg-orange-400 px-3 py-2 text-xs font-semibold text-slate-950"
                  >
                    Quarantine
                  </button>
                  <button
                    onClick={() => commitDecision(approval, "Deny")}
                    className="rounded-full bg-red-500 px-3 py-2 text-xs font-semibold text-white"
                  >
                    Deny
                  </button>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </SectionShell>
  );
}

function PolicySection({ section }: { section: RiskCockpitSpec["sections"][number] }) {
  return (
    <SectionShell title={section.title} subtitle={section.subtitle} icon={<Code2 className="h-5 w-5" />}>
      <div className="grid gap-4 lg:grid-cols-[0.9fr_1.1fr]">
        <div className="rounded-3xl border border-white/10 bg-black/20 p-4">
          <h3 className="text-sm font-semibold text-white">Generated policy summary</h3>
          <p className="mt-3 text-sm leading-6 text-slate-300">
            Default decision:{" "}
            <span className="font-semibold text-cyan-100">
              {section.policy?.defaultDecision || "Require review"}
            </span>
          </p>

          <TagGroup title="Human approval required" values={safeArray(section.policy?.requireHumanApprovalFor)} tone="High" />
          <TagGroup title="Allowed read-only scopes" values={safeArray(section.policy?.allowedReadOnlyScopes)} tone="Low" />
          <TagGroup title="Blocked actions" values={safeArray(section.policy?.blockedActions)} tone="Critical" />
          <TagGroup title="Audit events" values={safeArray(section.policy?.auditEvents)} tone="Medium" />
          <TagGroup title="Guardrails" values={safeArray(section.policy?.guardrails)} tone="Low" />
        </div>

        <pre className="max-h-96 overflow-auto rounded-3xl border border-white/10 bg-slate-950 p-4 text-xs leading-5 text-cyan-50">
          {JSON.stringify(section.policy || {}, null, 2)}
        </pre>
      </div>
    </SectionShell>
  );
}

function ThreatModelSection({ section }: { section: RiskCockpitSpec["sections"][number] }) {
  return (
    <SectionShell title={section.title} subtitle={section.subtitle} icon={<ShieldAlert className="h-5 w-5" />}>
      <div className="grid gap-4 lg:grid-cols-3">
        {safeArray(section.threats).map((threat) => (
          <div key={threat.title} className="rounded-3xl border border-white/10 bg-black/20 p-4">
            <div className="mb-3 flex items-center justify-between gap-3">
              <h3 className="text-sm font-semibold text-white">{threat.title}</h3>
              <TierPill tier={threat.tier} />
            </div>
            <p className="text-sm leading-6 text-slate-300">{threat.scenario}</p>
            <div className="mt-3 rounded-2xl border border-red-400/20 bg-red-400/10 p-3 text-sm leading-6 text-red-50/85">
              Impact: {threat.impact}
            </div>
            <div className="mt-3 rounded-2xl border border-emerald-400/20 bg-emerald-400/10 p-3 text-sm leading-6 text-emerald-50/85">
              Control: {threat.control}
            </div>
            <TagGroup title="Affected tools" values={safeArray(threat.affectedTools)} tone={threat.tier} />
          </div>
        ))}
      </div>
    </SectionShell>
  );
}

function ActionPlanSection({ section }: { section: RiskCockpitSpec["sections"][number] }) {
  return (
    <SectionShell title={section.title} subtitle={section.subtitle} icon={<TerminalSquare className="h-5 w-5" />}>
      <div className="space-y-3">
        {safeArray(section.actions).map((item) => (
          <div key={`${item.priority}-${item.title}`} className="rounded-3xl border border-white/10 bg-black/20 p-4">
            <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
              <div>
                <div className="mb-2 inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.05] px-2 py-1 text-xs text-slate-300">
                  <GitBranch className="h-3.5 w-3.5" />
                  {item.priority} - {item.owner} - Effort: {item.effort || "Medium"}
                </div>
                <h3 className="text-base font-semibold text-white">{item.title}</h3>
                <p className="mt-2 text-sm leading-6 text-slate-300">{item.outcome}</p>
              </div>
            </div>
          </div>
        ))}
      </div>
    </SectionShell>
  );
}

function AttackPathSection({ section }: { section: RiskCockpitSpec["sections"][number] }) {
  return (
    <SectionShell title={section.title} subtitle={section.subtitle} icon={<GitBranch className="h-5 w-5" />}>
      <div className="grid gap-4 lg:grid-cols-2">
        {safeArray(section.attackPaths).map((path) => (
          <div key={path.id} className="rounded-3xl border border-white/10 bg-black/20 p-4">
            <div className="flex items-start justify-between gap-3">
              <div>
                <h3 className="text-base font-semibold text-white">{path.title}</h3>
                <p className="mt-1 text-xs text-slate-400">
                  {path.entryPoint} to {path.target}
                </p>
              </div>
              <TierPill tier={path.tier} />
            </div>

            <div className="mt-4 space-y-3">
              {safeArray(path.steps).map((step, index) => (
                <div key={`${path.id}-${index}`} className="flex gap-3">
                  <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-cyan-400/20 text-xs font-semibold text-cyan-100">
                    {index + 1}
                  </div>
                  <div className="rounded-2xl border border-white/10 bg-white/[0.04] p-3 text-sm leading-6 text-slate-300">
                    {step}
                  </div>
                </div>
              ))}
            </div>

            <div className="mt-4 rounded-2xl border border-red-400/20 bg-red-400/10 p-3 text-sm leading-6 text-red-50/85">
              Impact: {path.impact}
            </div>

            <TagGroup title="Blocked by" values={safeArray(path.blockedBy)} tone="Low" />
          </div>
        ))}
      </div>
    </SectionShell>
  );
}

function SimulationLabSection({ section }: { section: RiskCockpitSpec["sections"][number] }) {
  const simulations = safeArray(section.simulations);
  const [selectedId, setSelectedId] = useState(simulations[0]?.id || "");
  const [hasRun, setHasRun] = useState(false);
  const selected = simulations.find((simulation) => simulation.id === selectedId) || simulations[0];

  if (!selected) return null;

  return (
    <SectionShell title={section.title} subtitle={section.subtitle} icon={<Fingerprint className="h-5 w-5" />}>
      <div className="grid gap-4 lg:grid-cols-[0.8fr_1.2fr]">
        <div className="space-y-3">
          {simulations.map((simulation) => (
            <button
              key={simulation.id}
              onClick={() => {
                setSelectedId(simulation.id);
                setHasRun(false);
              }}
              className={classNames(
                "w-full rounded-3xl border p-4 text-left transition hover:bg-white/[0.07]",
                selected.id === simulation.id
                  ? "border-cyan-400/50 bg-cyan-400/10"
                  : "border-white/10 bg-black/20"
              )}
            >
              <div className="flex items-start justify-between gap-3">
                <div>
                  <h3 className="text-sm font-semibold text-white">{simulation.title}</h3>
                  <p className="mt-1 text-xs text-slate-400">{simulation.toolName}</p>
                </div>
                <TierPill tier={simulation.tier} />
              </div>
            </button>
          ))}
        </div>

        <div className="rounded-3xl border border-white/10 bg-black/20 p-4">
          <div className="flex flex-col justify-between gap-3 md:flex-row md:items-start">
            <div>
              <h3 className="text-base font-semibold text-white">{selected.title}</h3>
              <p className="mt-1 text-sm text-slate-400">{selected.toolName}</p>
            </div>
            <button
              onClick={() => setHasRun(true)}
              className="inline-flex items-center justify-center gap-2 rounded-full bg-cyan-300 px-4 py-2 text-xs font-semibold text-slate-950"
            >
              <Play className="h-3.5 w-3.5" />
              Run simulation
            </button>
          </div>

          <div className="mt-4 rounded-2xl border border-yellow-400/20 bg-yellow-400/10 p-3">
            <p className="text-xs uppercase tracking-[0.16em] text-yellow-200">Injected content</p>
            <p className="mt-2 text-sm leading-6 text-yellow-50/90">{selected.maliciousInput}</p>
          </div>

          {hasRun ? (
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              <div className="rounded-2xl border border-red-400/20 bg-red-400/10 p-3">
                <p className="text-xs uppercase tracking-[0.16em] text-red-200">Without cockpit</p>
                <p className="mt-2 text-sm leading-6 text-red-50/90">{selected.unsafeOutcome}</p>
              </div>
              <div className="rounded-2xl border border-emerald-400/20 bg-emerald-400/10 p-3">
                <p className="text-xs uppercase tracking-[0.16em] text-emerald-200">With cockpit</p>
                <p className="mt-2 text-sm leading-6 text-emerald-50/90">{selected.guardedOutcome}</p>
              </div>
            </div>
          ) : null}

          <TagGroup title="Controls triggered" values={safeArray(selected.controlsTriggered)} tone="Low" />
        </div>
      </div>
    </SectionShell>
  );
}

function EvidenceTimelineSection({ section }: { section: RiskCockpitSpec["sections"][number] }) {
  return (
    <SectionShell title={section.title} subtitle={section.subtitle} icon={<Clock3 className="h-5 w-5" />}>
      <div className="space-y-3">
        {safeArray(section.evidence).map((item, index) => (
          <div key={`${item.time}-${index}`} className="grid gap-3 md:grid-cols-[110px_1fr]">
            <div className="rounded-2xl border border-white/10 bg-white/[0.04] p-3 text-sm text-slate-300">
              {item.time}
            </div>
            <div className="rounded-3xl border border-white/10 bg-black/20 p-4">
              <div className="flex flex-wrap items-center gap-2">
                <TierPill tier={item.tier} />
                <span className="rounded-full border border-white/10 bg-white/[0.05] px-2 py-1 text-xs text-slate-300">
                  {item.source}
                </span>
              </div>
              <h3 className="mt-3 text-sm font-semibold text-white">{item.event}</h3>
              <p className="mt-2 text-sm leading-6 text-slate-300">{item.summary}</p>
            </div>
          </div>
        ))}
      </div>
    </SectionShell>
  );
}

function ControlRoadmapSection({ section }: { section: RiskCockpitSpec["sections"][number] }) {
  return (
    <SectionShell title={section.title} subtitle={section.subtitle} icon={<ShieldCheck className="h-5 w-5" />}>
      <div className="grid gap-4 lg:grid-cols-4">
        {safeArray(section.controls).map((control) => (
          <div key={`${control.phase}-${control.title}`} className="rounded-3xl border border-white/10 bg-black/20 p-4">
            <div className="mb-3 flex items-center justify-between gap-2">
              <span className="rounded-full border border-white/10 bg-white/[0.05] px-2 py-1 text-xs text-slate-300">
                {control.phase}
              </span>
              <TierPill tier={control.impact} />
            </div>
            <h3 className="text-sm font-semibold text-white">{control.title}</h3>
            <p className="mt-2 text-xs text-slate-400">
              Owner: {control.owner} - Effort: {control.effort}
            </p>
            <p className="mt-2 text-xs text-cyan-100">Status: {control.status}</p>
            <div className="mt-3 space-y-2">
              {safeArray(control.tasks).map((task) => (
                <div key={task} className="rounded-2xl bg-white/[0.04] p-2 text-xs leading-5 text-slate-300">
                  {task}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </SectionShell>
  );
}

function ComplianceMapSection({ section }: { section: RiskCockpitSpec["sections"][number] }) {
  return (
    <SectionShell title={section.title} subtitle={section.subtitle} icon={<FileWarning className="h-5 w-5" />}>
      <div className="grid gap-4 lg:grid-cols-2">
        {safeArray(section.compliance).map((item) => (
          <div key={`${item.framework}-${item.control}`} className="rounded-3xl border border-white/10 bg-black/20 p-4">
            <div className="flex flex-wrap items-center gap-2">
              <TierPill tier={item.tier} />
              <span className="rounded-full border border-white/10 bg-white/[0.05] px-2 py-1 text-xs text-slate-300">
                {item.framework}
              </span>
              <span
                className={classNames(
                  "rounded-full border px-2 py-1 text-xs",
                  item.coverage === "Strong"
                    ? "border-emerald-400/30 bg-emerald-400/10 text-emerald-100"
                    : item.coverage === "Partial"
                      ? "border-yellow-400/30 bg-yellow-400/10 text-yellow-100"
                      : "border-red-400/30 bg-red-400/10 text-red-100"
                )}
              >
                {item.coverage}
              </span>
            </div>
            <h3 className="mt-3 text-sm font-semibold text-white">{item.control}</h3>
            <p className="mt-2 text-sm leading-6 text-slate-300">Gap: {item.gap}</p>
            <p className="mt-2 text-sm leading-6 text-cyan-50/80">Evidence: {item.evidence}</p>
          </div>
        ))}
      </div>
    </SectionShell>
  );
}

function DecisionDiffSection({ section }: { section: RiskCockpitSpec["sections"][number] }) {
  return (
    <SectionShell title={section.title} subtitle={section.subtitle} icon={<Eye className="h-5 w-5" />}>
      <div className="space-y-4">
        {safeArray(section.decisions).map((item) => (
          <div key={item.scenario} className="rounded-3xl border border-white/10 bg-black/20 p-4">
            <div className="mb-3 flex flex-wrap items-center gap-2">
              <TierPill tier={item.tier} />
              <span className="rounded-full border border-cyan-400/20 bg-cyan-400/10 px-2 py-1 text-xs text-cyan-100">
                {item.userDecision}
              </span>
            </div>
            <h3 className="text-base font-semibold text-white">{item.scenario}</h3>
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              <div className="rounded-2xl border border-red-400/20 bg-red-400/10 p-3 text-sm leading-6 text-red-50/90">
                <p className="mb-1 text-xs uppercase tracking-[0.16em] text-red-200">Without cockpit</p>
                {item.withoutCockpit}
              </div>
              <div className="rounded-2xl border border-emerald-400/20 bg-emerald-400/10 p-3 text-sm leading-6 text-emerald-50/90">
                <p className="mb-1 text-xs uppercase tracking-[0.16em] text-emerald-200">With cockpit</p>
                {item.withCockpit}
              </div>
            </div>
          </div>
        ))}
      </div>
    </SectionShell>
  );
}

function RiskRegisterSection({ section }: { section: RiskCockpitSpec["sections"][number] }) {
  return (
    <SectionShell title={section.title} subtitle={section.subtitle} icon={<AlertTriangle className="h-5 w-5" />}>
      <div className="overflow-x-auto rounded-3xl border border-white/10 bg-black/20">
        <table className="min-w-full text-left text-sm">
          <thead className="border-b border-white/10 bg-white/[0.04] text-xs uppercase tracking-[0.16em] text-slate-500">
            <tr>
              <th className="px-4 py-3">Risk</th>
              <th className="px-4 py-3">Score</th>
              <th className="px-4 py-3">Likelihood</th>
              <th className="px-4 py-3">Impact</th>
              <th className="px-4 py-3">Owner</th>
              <th className="px-4 py-3">Next action</th>
            </tr>
          </thead>
          <tbody>
            {safeArray(section.risks).map((risk) => (
              <tr key={risk.id} className="border-b border-white/10 last:border-0">
                <td className="px-4 py-4">
                  <p className="font-semibold text-white">{risk.risk}</p>
                  <p className="mt-1 text-xs text-slate-400">{safeArray(risk.affectedTools).join(", ")}</p>
                </td>
                <td className="px-4 py-4">
                  <span className="text-lg font-semibold" style={{ color: riskColors[getTierFromNumber(risk.score)] }}>
                    {risk.score}
                  </span>
                </td>
                <td className="px-4 py-4 text-slate-300">{risk.likelihood}</td>
                <td className="px-4 py-4 text-slate-300">{risk.impact}</td>
                <td className="px-4 py-4 text-slate-300">{risk.owner}</td>
                <td className="px-4 py-4 text-slate-300">{risk.nextAction}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </SectionShell>
  );
}

function ArchitectureMapSection({ section }: { section: RiskCockpitSpec["sections"][number] }) {
  const nodes = safeArray(section.nodes);
  const edges = safeArray(section.edges);

  return (
    <SectionShell title={section.title} subtitle={section.subtitle} icon={<Network className="h-5 w-5" />}>
      <div className="grid gap-4 lg:grid-cols-[1fr_0.7fr]">
        <div className="rounded-3xl border border-white/10 bg-black/20 p-4">
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {nodes.map((node) => (
              <div key={node.id} className="rounded-3xl border border-white/10 bg-white/[0.04] p-4">
                <div className="mb-2 flex items-center justify-between gap-2">
                  <span className="rounded-full border border-white/10 bg-black/25 px-2 py-1 text-xs text-slate-300">
                    {node.kind}
                  </span>
                  <TierPill tier={node.tier} />
                </div>
                <h3 className="text-sm font-semibold text-white">{node.label}</h3>
                <p className="mt-2 text-xs leading-5 text-slate-400">{node.note}</p>
              </div>
            ))}
          </div>
        </div>

        <div className="rounded-3xl border border-white/10 bg-black/20 p-4">
          <h3 className="text-sm font-semibold text-white">Generated connections</h3>
          <div className="mt-3 space-y-2">
            {edges.map((edge, index) => (
              <div key={`${edge.from}-${edge.to}-${index}`} className="rounded-2xl border border-white/10 bg-white/[0.04] p-3">
                <div className="flex items-center gap-2 text-xs text-slate-300">
                  <span>{edge.from}</span>
                  <span className="text-cyan-300">to</span>
                  <span>{edge.to}</span>
                </div>
                <div className="mt-2 flex items-center justify-between gap-2">
                  <p className="text-sm text-white">{edge.label}</p>
                  <TierPill tier={edge.tier} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </SectionShell>
  );
}

function InfoBox({
  icon,
  label,
  value
}: {
  icon: ReactNode;
  label: string;
  value: string;
}) {
  return (
    <div className="rounded-2xl border border-white/10 bg-white/[0.04] p-3">
      <p className="flex items-center gap-2 text-xs uppercase tracking-[0.16em] text-slate-500">
        {icon}
        {label}
      </p>
      <p className="mt-2 text-sm leading-6 text-slate-200">{value}</p>
    </div>
  );
}

function TagGroup({
  title,
  values,
  tone
}: {
  title: string;
  values: string[];
  tone: RiskTier;
}) {
  if (!values.length) return null;

  return (
    <div className="mt-4">
      <p className="text-xs uppercase tracking-[0.16em] text-slate-500">{title}</p>
      <div className="mt-2 flex flex-wrap gap-2">
        {values.map((value) => (
          <span
            key={value}
            className="rounded-full px-2 py-1 text-xs font-medium"
            style={{ background: `${riskColors[tone]}22`, color: riskColors[tone] }}
          >
            {value}
          </span>
        ))}
      </div>
    </div>
  );
}

function TierPill({ tier }: { tier: RiskTier }) {
  return (
    <span
      className="inline-flex items-center gap-1 rounded-full px-2 py-1 text-xs font-semibold"
      style={{ background: `${riskColors[tier]}22`, color: riskColors[tier] }}
    >
      {getTierIcon(tier)}
      {tier}
    </span>
  );
}
