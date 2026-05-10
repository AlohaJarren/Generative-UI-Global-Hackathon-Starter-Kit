"use client";

import { useMemo, useState, useEffect } from "react";
import {
  AlertTriangle,
  Ban,
  CheckCircle2,
  Clipboard,
  Clock3,
  FileCheck2,
  Fingerprint,
  GitBranch,
  LockKeyhole,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Target,
  XCircle,
  Zap
} from "lucide-react";

type RiskTier = "Critical" | "High" | "Medium" | "Low";
type Decision = "Approve" | "Quarantine" | "Deny";

type DecisionEvent = {
  id: string;
  title: string;
  toolName: string;
  action: string;
  tier: RiskTier;
  reason: string;
  recommendedDecision?: Decision;
  decision: Decision;
  decidedAt: string;
  evidenceNeeded?: string[];
};

type RemediationTask = {
  id: string;
  title: string;
  owner: string;
  sla: string;
  status: "Ready" | "In Progress" | "Blocked";
  impact: string;
  riskDelta: number;
};

type DecisionPackage = {
  event: DecisionEvent;
  headline: string;
  operationalOutcome: string;
  businessImpact: string;
  beforeCockpit: string;
  afterCockpit: string;
  riskDelta: number;
  policyDelta: string[];
  controlsTriggered: string[];
  remediationTasks: RemediationTask[];
  auditPacket: Record<string, unknown>;
};

const riskColors: Record<RiskTier, string> = {
  Critical: "#ef4444",
  High: "#f97316",
  Medium: "#eab308",
  Low: "#22c55e"
};

const decisionStyles: Record<Decision, string> = {
  Approve: "border-emerald-400/40 bg-emerald-400/10 text-emerald-100",
  Quarantine: "border-orange-400/40 bg-orange-400/10 text-orange-100",
  Deny: "border-red-400/40 bg-red-400/10 text-red-100"
};

function safeArray<T>(value: T[] | undefined): T[] {
  return Array.isArray(value) ? value : [];
}

function classNames(...classes: Array<string | false | undefined>) {
  return classes.filter(Boolean).join(" ");
}

function getDecisionIcon(decision: Decision) {
  if (decision === "Approve") return <CheckCircle2 className="h-4 w-4" />;
  if (decision === "Quarantine") return <Ban className="h-4 w-4" />;
  return <XCircle className="h-4 w-4" />;
}

function getTierWeight(tier: RiskTier) {
  if (tier === "Critical") return 95;
  if (tier === "High") return 75;
  if (tier === "Medium") return 45;
  return 20;
}

function inferToolFamily(event: DecisionEvent) {
  const text = `${event.toolName} ${event.action}`.toLowerCase();

  if (text.includes("github") || text.includes("workflow") || text.includes("terminal") || text.includes("command")) {
    return "code_execution";
  }

  if (text.includes("identity") || text.includes("okta") || text.includes("user") || text.includes("mfa") || text.includes("role")) {
    return "identity";
  }

  if (text.includes("slack") || text.includes("post") || text.includes("message")) {
    return "communication";
  }

  if (text.includes("notion") || text.includes("database") || text.includes("comment") || text.includes("page")) {
    return "business_data";
  }

  if (text.includes("refund") || text.includes("payment") || text.includes("charge")) {
    return "finance";
  }

  return "general";
}

function buildTasks(event: DecisionEvent): RemediationTask[] {
  const family = inferToolFamily(event);
  const isCritical = event.tier === "Critical";
  const decision = event.decision;

  const baseOwner =
    family === "identity"
      ? "Security IAM"
      : family === "code_execution"
        ? "Platform Engineering"
        : family === "communication"
          ? "Community Ops"
          : family === "finance"
            ? "Revenue Operations"
            : "Security Governance";

  if (decision === "Approve") {
    return [
      {
        id: `${event.id}-approve-1`,
        title: `Enable guarded ${event.action} for ${event.toolName}`,
        owner: baseOwner,
        sla: isCritical ? "Same day" : "24 hours",
        status: "Ready",
        impact: "Allows the agent to proceed only under the approved boundary.",
        riskDelta: 12
      },
      {
        id: `${event.id}-approve-2`,
        title: "Attach audit evidence and approval reason to the run record",
        owner: "Security Governance",
        sla: "Immediate",
        status: "Ready",
        impact: "Creates a defensible record of why the action was allowed.",
        riskDelta: 8
      },
      {
        id: `${event.id}-approve-3`,
        title: "Monitor the next 3 tool calls for scope drift",
        owner: "AgentOps",
        sla: "Next session",
        status: "In Progress",
        impact: "Catches follow-up actions that exceed the original approval.",
        riskDelta: 10
      }
    ];
  }

  if (decision === "Quarantine") {
    return [
      {
        id: `${event.id}-quarantine-1`,
        title: `Convert ${event.toolName} to read-only mode`,
        owner: baseOwner,
        sla: isCritical ? "Immediate" : "24 hours",
        status: "Ready",
        impact: "Preserves useful context retrieval while blocking writes and side effects.",
        riskDelta: 28
      },
      {
        id: `${event.id}-quarantine-2`,
        title: `Create allowlist for safe ${event.action} alternatives`,
        owner: "Platform Security",
        sla: "48 hours",
        status: "In Progress",
        impact: "Defines which actions can run without reopening broad access.",
        riskDelta: 18
      },
      {
        id: `${event.id}-quarantine-3`,
        title: "Run prompt-injection simulation before reapproval",
        owner: "Red Team",
        sla: "72 hours",
        status: "Ready",
        impact: "Validates that untrusted tool output cannot trigger the action.",
        riskDelta: 22
      },
      {
        id: `${event.id}-quarantine-4`,
        title: "Require owner sign-off for reactivation",
        owner: baseOwner,
        sla: "Before re-enable",
        status: "Blocked",
        impact: "Prevents silent reactivation of risky capabilities.",
        riskDelta: 15
      }
    ];
  }

  return [
    {
      id: `${event.id}-deny-1`,
      title: `Block ${event.action} from ${event.toolName}`,
      owner: baseOwner,
      sla: "Immediate",
      status: "Ready",
      impact: "Removes the dangerous path from the agent's available action set.",
      riskDelta: 35
    },
    {
      id: `${event.id}-deny-2`,
      title: "Create replacement workflow with human-owned execution",
      owner: "Security Governance",
      sla: "48 hours",
      status: "In Progress",
      impact: "Keeps the business workflow alive without giving the agent unsafe authority.",
      riskDelta: 20
    },
    {
      id: `${event.id}-deny-3`,
      title: "Search recent audit events for similar attempted actions",
      owner: "Detection Engineering",
      sla: "24 hours",
      status: "Ready",
      impact: "Finds whether this was an isolated request or a pattern.",
      riskDelta: 18
    },
    {
      id: `${event.id}-deny-4`,
      title: "Add policy rule to block future requests by default",
      owner: "Platform Security",
      sla: "Same day",
      status: "Ready",
      impact: "Turns one decision into a persistent control.",
      riskDelta: 24
    }
  ];
}

function buildDecisionPackage(event: DecisionEvent): DecisionPackage {
  const tierWeight = getTierWeight(event.tier);
  const tasks = buildTasks(event);
  const totalTaskDelta = tasks.reduce((sum, task) => sum + task.riskDelta, 0);

  const riskDelta =
    event.decision === "Approve"
      ? Math.min(30, Math.round(totalTaskDelta * 0.55))
      : event.decision === "Quarantine"
        ? Math.min(75, Math.round(totalTaskDelta * 0.85))
        : Math.min(95, Math.round(totalTaskDelta * 0.95));

  const family = inferToolFamily(event);

  const familyControl =
    family === "code_execution"
      ? "command allowlist, workflow approval, sandboxed execution"
      : family === "identity"
        ? "break-glass approval, role separation, identity audit trail"
        : family === "communication"
          ? "post approval, channel allowlist, retrieval sanitization"
          : family === "finance"
            ? "amount threshold, dual approval, transaction audit"
            : family === "business_data"
              ? "field redaction, write approval, row-level minimization"
              : "scope reduction, audit logging, human approval";

  const headline =
    event.decision === "Approve"
      ? `Approved ${event.action}, but only under a guarded execution boundary.`
      : event.decision === "Quarantine"
        ? `Quarantined ${event.action} until missing controls are implemented.`
        : `Denied ${event.action} and converted the request into a safer manual workflow.`;

  const operationalOutcome =
    event.decision === "Approve"
      ? `The agent can continue the workflow, but the approval is bound to this action, this tool, and this recorded reason.`
      : event.decision === "Quarantine"
        ? `The agent keeps read-only visibility, but side effects are frozen until the remediation tasks are completed.`
        : `The agent cannot execute this action. The cockpit creates replacement work so the business process does not stall.`;

  const businessImpact =
    event.decision === "Approve"
      ? `Business velocity is preserved while the approval record reduces ambiguity during review.`
      : event.decision === "Quarantine"
        ? `The organization avoids a risky automation failure while still preserving enough access for investigation and planning.`
        : `The organization prevents a high-impact agent action and creates a safer path for a human-owned process.`;

  const beforeCockpit =
    event.decision === "Approve"
      ? `Without the cockpit, this approval might become an informal "yes" with no scope, evidence, or follow-up monitoring.`
      : event.decision === "Quarantine"
        ? `Without the cockpit, teams often choose between full access and no access, leaving no middle path.`
        : `Without the cockpit, a denial can become a dead end with no follow-up work, no owner, and no durable policy update.`;

  const afterCockpit =
    event.decision === "Approve"
      ? `With the cockpit, approval becomes a bounded, auditable action with monitoring and rollback expectations.`
      : event.decision === "Quarantine"
        ? `With the cockpit, quarantine becomes an actionable remediation lane with owners, SLAs, and reapproval criteria.`
        : `With the cockpit, denial becomes a control update, an audit event, and a safer replacement workflow.`;

  const policyDelta =
    event.decision === "Approve"
      ? [
          `Allow ${event.action} for ${event.toolName} only for the approved request context.`,
          "Require a reason, requester, affected data class, and rollback note before execution.",
          "Log the next related tool calls as post-approval monitoring evidence."
        ]
      : event.decision === "Quarantine"
        ? [
            `Move ${event.toolName} into read-only or observation mode.`,
            `Block ${event.action} until these controls exist: ${familyControl}.`,
            "Require reapproval after remediation evidence is attached."
          ]
        : [
            `Deny ${event.action} for ${event.toolName} by default.`,
            "Route future requests to a human-owned manual workflow.",
            "Add this action to the global blocked-actions policy until a safe implementation is approved."
          ];

  const controlsTriggered =
    event.decision === "Approve"
      ? ["bounded approval", "audit packet", "post-action monitoring", "rollback expectation"]
      : event.decision === "Quarantine"
        ? ["read-only fallback", "write freeze", "reapproval gate", "red-team simulation"]
        : ["hard block", "policy update", "manual workflow fallback", "retroactive audit search"];

  const auditPacket = {
    decision_id: event.id,
    decided_at: event.decidedAt,
    tool: event.toolName,
    action: event.action,
    risk_tier: event.tier,
    tier_weight: tierWeight,
    decision: event.decision,
    reason: event.reason,
    evidence_needed: safeArray(event.evidenceNeeded),
    controls_triggered: controlsTriggered,
    policy_delta: policyDelta,
    remediation_tasks: tasks.map((task) => ({
      id: task.id,
      title: task.title,
      owner: task.owner,
      sla: task.sla,
      status: task.status,
      risk_delta: task.riskDelta
    })),
    estimated_risk_reduction: riskDelta
  };

  return {
    event,
    headline,
    operationalOutcome,
    businessImpact,
    beforeCockpit,
    afterCockpit,
    riskDelta,
    policyDelta,
    controlsTriggered,
    remediationTasks: tasks,
    auditPacket
  };
}

export function DecisionImpactCenter() {
  const [events, setEvents] = useState<DecisionEvent[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [copyStatus, setCopyStatus] = useState("");

  useEffect(() => {
    function handleDecision(event: Event) {
      const customEvent = event as CustomEvent<DecisionEvent>;
      const detail = customEvent.detail;

      if (!detail?.id || !detail?.decision) return;

      setEvents((current) => {
        const withoutDuplicate = current.filter(
          (item) => !(item.id === detail.id && item.decision === detail.decision)
        );
        return [detail, ...withoutDuplicate].slice(0, 12);
      });

      setActiveId(detail.id);
    }

    window.addEventListener("mcp-risk-decision", handleDecision);
    return () => window.removeEventListener("mcp-risk-decision", handleDecision);
  }, []);

  const packages = useMemo(() => events.map(buildDecisionPackage), [events]);
  const activePackage = packages.find((item) => item.event.id === activeId) || packages[0];

  const totals = useMemo(() => {
    return packages.reduce(
      (acc, item) => {
        acc.riskReduction += item.riskDelta;
        acc.tasks += item.remediationTasks.length;
        acc.auditEvents += 1;
        acc[item.event.decision] += 1;
        return acc;
      },
      {
        riskReduction: 0,
        tasks: 0,
        auditEvents: 0,
        Approve: 0,
        Quarantine: 0,
        Deny: 0
      } as Record<string, number>
    );
  }, [packages]);

  async function copyAuditPacket() {
    if (!activePackage) return;

    try {
      await navigator.clipboard.writeText(JSON.stringify(activePackage.auditPacket, null, 2));
      setCopyStatus("Copied audit packet");
      window.setTimeout(() => setCopyStatus(""), 1800);
    } catch {
      setCopyStatus("Copy failed");
      window.setTimeout(() => setCopyStatus(""), 1800);
    }
  }

  return (
    <section className="rounded-[2rem] border border-cyan-400/20 bg-cyan-400/10 p-5 shadow-xl shadow-cyan-950/30">
      <div className="flex flex-col justify-between gap-5 lg:flex-row lg:items-start">
        <div>
          <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-cyan-300/30 bg-cyan-300/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.2em] text-cyan-100">
            <Sparkles className="h-3.5 w-3.5" />
            Decision Impact Engine
          </div>
          <h2 className="text-2xl font-semibold text-white">
            Every approval decision now creates operational security work.
          </h2>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-cyan-50/85">
            Approve, Quarantine, and Deny are no longer empty UI buttons. Each decision becomes an
            audit event, a policy change, a remediation path, and a measurable risk reduction story.
          </p>
        </div>

        <div className="grid min-w-[280px] grid-cols-2 gap-3">
          <ImpactMetric label="Risk reduced" value={`${totals.riskReduction}`} detail="control points" />
          <ImpactMetric label="Tasks created" value={`${totals.tasks}`} detail="owned work" />
          <ImpactMetric label="Audit events" value={`${totals.auditEvents}`} detail="evidence packets" />
          <ImpactMetric label="Decisions" value={`${events.length}`} detail="human gates" />
        </div>
      </div>

      {!activePackage ? (
        <div className="mt-5 rounded-3xl border border-white/10 bg-slate-950/40 p-5">
          <h3 className="flex items-center gap-2 text-base font-semibold text-white">
            <Target className="h-5 w-5 text-cyan-300" />
            Waiting for a decision
          </h3>
          <p className="mt-2 text-sm leading-6 text-slate-300">
            Generate an approval queue, then click Approve, Quarantine, or Deny. The cockpit will
            turn that click into concrete remediation work, policy deltas, and audit evidence.
          </p>
        </div>
      ) : (
        <div className="mt-5 grid gap-4 xl:grid-cols-[0.85fr_1.15fr]">
          <div className="space-y-3">
            {packages.map((item) => (
              <button
                key={`${item.event.id}-${item.event.decision}`}
                onClick={() => setActiveId(item.event.id)}
                className={classNames(
                  "w-full rounded-3xl border p-4 text-left transition hover:bg-white/[0.07]",
                  activePackage.event.id === item.event.id
                    ? "border-cyan-400/50 bg-cyan-400/10"
                    : "border-white/10 bg-slate-950/35"
                )}
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={classNames("inline-flex items-center gap-1 rounded-full border px-2 py-1 text-xs", decisionStyles[item.event.decision])}>
                        {getDecisionIcon(item.event.decision)}
                        {item.event.decision}
                      </span>
                      <span
                        className="rounded-full px-2 py-1 text-xs font-semibold"
                        style={{
                          background: `${riskColors[item.event.tier]}22`,
                          color: riskColors[item.event.tier]
                        }}
                      >
                        {item.event.tier}
                      </span>
                    </div>
                    <h3 className="mt-3 text-sm font-semibold text-white">{item.event.title}</h3>
                    <p className="mt-1 text-xs text-slate-400">
                      {item.event.toolName} - {item.event.action}
                    </p>
                  </div>
                  <div className="text-right">
                    <p className="text-xl font-semibold text-cyan-100">{item.riskDelta}</p>
                    <p className="text-xs text-slate-500">risk delta</p>
                  </div>
                </div>
              </button>
            ))}
          </div>

          <div className="grid gap-4">
            <div className="rounded-3xl border border-white/10 bg-slate-950/40 p-5">
              <div className="flex flex-col justify-between gap-4 md:flex-row md:items-start">
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className={classNames("inline-flex items-center gap-1 rounded-full border px-2 py-1 text-xs", decisionStyles[activePackage.event.decision])}>
                      {getDecisionIcon(activePackage.event.decision)}
                      {activePackage.event.decision}
                    </span>
                    <span
                      className="rounded-full px-2 py-1 text-xs font-semibold"
                      style={{
                        background: `${riskColors[activePackage.event.tier]}22`,
                        color: riskColors[activePackage.event.tier]
                      }}
                    >
                      {activePackage.event.tier}
                    </span>
                  </div>
                  <h3 className="mt-3 text-xl font-semibold text-white">{activePackage.headline}</h3>
                  <p className="mt-2 text-sm leading-6 text-slate-300">
                    {activePackage.operationalOutcome}
                  </p>
                </div>

                <button
                  onClick={copyAuditPacket}
                  className="inline-flex shrink-0 items-center justify-center gap-2 rounded-full bg-cyan-300 px-4 py-2 text-xs font-semibold text-slate-950"
                >
                  <Clipboard className="h-3.5 w-3.5" />
                  {copyStatus || "Copy audit packet"}
                </button>
              </div>

              <div className="mt-5 grid gap-3 md:grid-cols-2">
                <BeforeAfterCard
                  tone="bad"
                  title="Before cockpit"
                  text={activePackage.beforeCockpit}
                />
                <BeforeAfterCard
                  tone="good"
                  title="After cockpit"
                  text={activePackage.afterCockpit}
                />
              </div>

              <div className="mt-4 rounded-2xl border border-cyan-400/20 bg-cyan-400/10 p-3">
                <p className="text-xs uppercase tracking-[0.16em] text-cyan-200">Business impact</p>
                <p className="mt-2 text-sm leading-6 text-cyan-50/90">
                  {activePackage.businessImpact}
                </p>
              </div>
            </div>

            <div className="rounded-3xl border border-white/10 bg-slate-950/40 p-5">
              <h3 className="flex items-center gap-2 text-base font-semibold text-white">
                <GitBranch className="h-5 w-5 text-cyan-300" />
                Adaptive remediation roadmap
              </h3>
              <div className="mt-4 grid gap-3 md:grid-cols-2">
                {activePackage.remediationTasks.map((task) => (
                  <div key={task.id} className="rounded-2xl border border-white/10 bg-white/[0.04] p-4">
                    <div className="flex items-center justify-between gap-2">
                      <span className="rounded-full border border-white/10 bg-black/25 px-2 py-1 text-xs text-slate-300">
                        {task.status}
                      </span>
                      <span className="rounded-full border border-cyan-400/20 bg-cyan-400/10 px-2 py-1 text-xs text-cyan-100">
                        -{task.riskDelta} risk
                      </span>
                    </div>
                    <h4 className="mt-3 text-sm font-semibold text-white">{task.title}</h4>
                    <p className="mt-2 text-xs text-slate-400">
                      Owner: {task.owner} - SLA: {task.sla}
                    </p>
                    <p className="mt-2 text-sm leading-6 text-slate-300">{task.impact}</p>
                  </div>
                ))}
              </div>
            </div>

            <div className="grid gap-4 lg:grid-cols-2">
              <div className="rounded-3xl border border-white/10 bg-slate-950/40 p-5">
                <h3 className="flex items-center gap-2 text-base font-semibold text-white">
                  <LockKeyhole className="h-5 w-5 text-cyan-300" />
                  Policy delta
                </h3>
                <div className="mt-4 space-y-2">
                  {activePackage.policyDelta.map((item) => (
                    <div key={item} className="rounded-2xl border border-white/10 bg-white/[0.04] p-3 text-sm leading-6 text-slate-300">
                      {item}
                    </div>
                  ))}
                </div>
              </div>

              <div className="rounded-3xl border border-white/10 bg-slate-950/40 p-5">
                <h3 className="flex items-center gap-2 text-base font-semibold text-white">
                  <FileCheck2 className="h-5 w-5 text-cyan-300" />
                  Controls triggered
                </h3>
                <div className="mt-4 flex flex-wrap gap-2">
                  {activePackage.controlsTriggered.map((item) => (
                    <span key={item} className="rounded-full border border-emerald-400/20 bg-emerald-400/10 px-3 py-2 text-xs text-emerald-100">
                      {item}
                    </span>
                  ))}
                </div>

                <pre className="mt-4 max-h-64 overflow-auto rounded-2xl border border-white/10 bg-black/30 p-3 text-xs leading-5 text-cyan-50">
                  {JSON.stringify(activePackage.auditPacket, null, 2)}
                </pre>
              </div>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

function ImpactMetric({
  label,
  value,
  detail
}: {
  label: string;
  value: string;
  detail: string;
}) {
  return (
    <div className="rounded-2xl border border-white/10 bg-slate-950/40 p-4">
      <p className="text-xs uppercase tracking-[0.16em] text-cyan-200/70">{label}</p>
      <div className="mt-2 flex items-end justify-between gap-3">
        <span className="text-3xl font-semibold text-white">{value}</span>
        <span className="text-xs text-slate-400">{detail}</span>
      </div>
    </div>
  );
}

function BeforeAfterCard({
  tone,
  title,
  text
}: {
  tone: "bad" | "good";
  title: string;
  text: string;
}) {
  return (
    <div
      className={classNames(
        "rounded-2xl border p-3",
        tone === "bad"
          ? "border-red-400/20 bg-red-400/10"
          : "border-emerald-400/20 bg-emerald-400/10"
      )}
    >
      <p
        className={classNames(
          "text-xs uppercase tracking-[0.16em]",
          tone === "bad" ? "text-red-200" : "text-emerald-200"
        )}
      >
        {title}
      </p>
      <p
        className={classNames(
          "mt-2 text-sm leading-6",
          tone === "bad" ? "text-red-50/90" : "text-emerald-50/90"
        )}
      >
        {text}
      </p>
    </div>
  );
}
