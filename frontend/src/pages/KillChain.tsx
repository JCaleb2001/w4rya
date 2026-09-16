import { useMemo } from "react";
import { Link, useSearchParams } from "react-router-dom";
import {
  AttackEvent,
  useGetAttacksQuery,
  useVisibilityAwarePolling,
} from "../api";

const POLL_MS = 20000;

const SEVERITY_RANK: Record<string, number> = {
  low: 0, medium: 1, high: 2, critical: 3,
};

const SEVERITY_STYLE: Record<string, string> = {
  low: "border-hax-border text-hax-muted bg-hax-elev",
  medium: "border-hax-warning/50 text-hax-warning bg-hax-warning/10",
  high: "border-hax-danger/60 text-hax-danger bg-hax-danger/10",
  critical: "border-hax-danger text-red-300 bg-hax-danger/20 hax-glow",
};

interface Step {
  time: string;
  tactic: string;
  technique: string;
  mitre: string | null;
  severity: string;
  service: string;
  dst_port: number;
  flow_id: string;
}

interface Chain {
  src_ip: string;
  steps: Step[];
  maxSeverity: string;
}

function buildChains(events: AttackEvent[]): Chain[] {
  const byIp = new Map<string, Step[]>();
  for (const ev of events) {
    const steps: Step[] =
      ev.rules.length > 0
        ? ev.rules.map((r) => ({
            time: ev.time,
            tactic: r.tactic,
            technique: r.technique,
            mitre: r.mitre,
            severity: r.severity,
            service: ev.service,
            dst_port: ev.dst_port,
            flow_id: ev.flow_id,
          }))
        : [{
            time: ev.time,
            tactic: ev.tactic,
            technique: ev.type === "flag_out" ? "Flag exfiltrated (no signature match)" : "Unclassified",
            mitre: null,
            severity: ev.severity,
            service: ev.service,
            dst_port: ev.dst_port,
            flow_id: ev.flow_id,
          }];
    const arr = byIp.get(ev.src_ip) ?? [];
    arr.push(...steps);
    byIp.set(ev.src_ip, arr);
  }
  const chains: Chain[] = [];
  for (const [src_ip, steps] of byIp) {
    steps.sort((a, b) => a.time.localeCompare(b.time));
    let maxSeverity = "low";
    for (const s of steps) {
      if ((SEVERITY_RANK[s.severity] ?? 0) > (SEVERITY_RANK[maxSeverity] ?? 0)) {
        maxSeverity = s.severity;
      }
    }
    chains.push({ src_ip, steps, maxSeverity });
  }
  chains.sort((a, b) => (SEVERITY_RANK[b.maxSeverity] ?? 0) - (SEVERITY_RANK[a.maxSeverity] ?? 0));
  return chains;
}

export function KillChain() {
  const [searchParams, setSearchParams] = useSearchParams();
  const fromTickParam = searchParams.get("from_tick");
  const toTickParam = searchParams.get("to_tick");
  const fromTick = fromTickParam ? Number(fromTickParam) : undefined;
  const toTick = toTickParam ? Number(toTickParam) : undefined;

  const pollMs = useVisibilityAwarePolling(POLL_MS);
  const { data, isLoading, isFetching, refetch } = useGetAttacksQuery(
    { from_tick: fromTick, to_tick: toTick, limit: 500 },
    { pollingInterval: pollMs, refetchOnMountOrArgChange: true }
  );

  const chains = useMemo(() => buildChains(data?.events ?? []), [data]);

  function setRange(ticks: number) {
    const cur = data?.current_tick ?? 0;
    const sp = new URLSearchParams(searchParams);
    sp.set("from_tick", String(Math.max(0, cur - ticks)));
    sp.set("to_tick", String(cur + 1));
    setSearchParams(sp);
  }

  if (isLoading || !data) {
    return (
      <div className="p-6 bg-hax-bg text-hax-text font-mono min-h-full text-hax-muted text-xs">
        <span className="text-hax-accent-bright">$</span> loading kill chain<span className="hax-cursor"></span>
      </div>
    );
  }

  return (
    <div className="p-6 bg-hax-bg text-hax-text font-mono min-h-full">
      <div className="flex items-center gap-4 mb-4 flex-wrap">
        <div className="text-xs uppercase tracking-[0.4em] text-hax-accent-bright">
          ▎kill chain
        </div>
        <span className="text-[10px] text-hax-dim">
          tick {data.from_tick} → {data.to_tick} · current {data.current_tick}
        </span>
        <span className="text-[10px] text-hax-muted ml-auto">
          {chains.length} attacker{chains.length === 1 ? "" : "s"} · {data.count} event{data.count === 1 ? "" : "s"}{" "}
          {isFetching && <span className="ml-2 text-hax-accent-bright">⟳</span>}
        </span>
      </div>

      <div className="bg-hax-surface border border-hax-border rounded-sm p-3 mb-4 flex items-center gap-3 flex-wrap text-xs">
        <span className="text-[10px] uppercase tracking-wider text-hax-muted">range</span>
        {[5, 10, 30, 60].map((n) => (
          <button key={n} onClick={() => setRange(n)} className="hax-btn text-[10px]" title={`last ${n} ticks`}>
            last {n}
          </button>
        ))}
        <button onClick={() => refetch()} className="hax-btn text-[10px] ml-auto">
          refresh
        </button>
      </div>

      {chains.length === 0 && (
        <div className="bg-hax-surface border border-hax-border rounded-sm py-10 text-center text-hax-dim text-xs">
          no attacker activity in range — try a wider tick window
        </div>
      )}

      <div className="flex flex-col gap-3">
        {chains.map((chain) => (
          <ChainRow key={chain.src_ip} chain={chain} />
        ))}
      </div>
    </div>
  );
}

function ChainRow({ chain }: { chain: Chain }) {
  return (
    <div className="bg-hax-surface border border-hax-border rounded-sm p-3">
      <div className="flex items-center gap-2 mb-2">
        <span className="text-hax-accent-bright font-bold">{chain.src_ip}</span>
        <span
          className={`px-1.5 py-0.5 rounded-sm border text-[9px] uppercase tracking-wider ${SEVERITY_STYLE[chain.maxSeverity] ?? SEVERITY_STYLE.low}`}
        >
          {chain.maxSeverity}
        </span>
        <span className="text-[10px] text-hax-dim ml-auto">
          {chain.steps.length} step{chain.steps.length === 1 ? "" : "s"}
        </span>
      </div>
      <div className="flex items-stretch gap-1 overflow-x-auto pb-1">
        {chain.steps.map((s, i) => (
          <div key={i} className="flex items-stretch gap-1 flex-shrink-0">
            <StepChip step={s} />
            {i < chain.steps.length - 1 && (
              <span className="text-hax-dim self-center px-0.5">→</span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function StepChip({ step }: { step: Step }) {
  const t = new Date(step.time);
  const timeStr = isNaN(t.getTime()) ? step.time : t.toLocaleTimeString();
  return (
    <Link
      to={`/flow/${step.flow_id}`}
      className={`flex flex-col justify-center px-2 py-1.5 rounded-sm border min-w-[150px] max-w-[190px] hover:brightness-125 transition-all ${SEVERITY_STYLE[step.severity] ?? SEVERITY_STYLE.low}`}
      title={step.technique}
    >
      <div className="text-[9px] uppercase tracking-wider opacity-70">{step.tactic}</div>
      <div className="text-[10px] truncate">{step.technique}</div>
      <div className="text-[9px] opacity-60 flex justify-between">
        <span>{step.service}:{step.dst_port}</span>
        <span>{timeStr}</span>
      </div>
      {step.mitre && <div className="text-[9px] opacity-50">{step.mitre}</div>}
    </Link>
  );
}
