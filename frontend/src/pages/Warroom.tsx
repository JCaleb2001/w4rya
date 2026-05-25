import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  AttackEvent,
  ServiceStats,
  useGetAttacksQuery,
  useGetMeQuery,
  useGetServicesStatsQuery,
  useGetTickInfoQuery,
} from "../api";

const REFRESH_MS = 10_000;

/**
 * Fullscreen TV view for a war-room wall display. No interactivity, big
 * fonts, auto-refresh. Pulls services stats + attack timeline and slices it
 * into 4 panels.
 */
export function Warroom() {
  const { data: me } = useGetMeQuery();
  const { data: services } = useGetServicesStatsQuery(5, {
    pollingInterval: REFRESH_MS,
  });
  const { data: attacks } = useGetAttacksQuery(
    { limit: 50 },
    { pollingInterval: REFRESH_MS }
  );
  const { data: tick } = useGetTickInfoQuery();

  const [now, setNow] = useState(new Date());
  useEffect(() => {
    const id = window.setInterval(() => setNow(new Date()), 1000);
    return () => window.clearInterval(id);
  }, []);

  const currentTick = attacks?.current_tick ?? 0;
  const tickProgressPct = computeTickProgressPct(tick, now);

  const leaks = (attacks?.events ?? []).filter(
    (e) => e.type === "flag_out" || e.type === "both"
  );
  const top = topAttackers(attacks?.events ?? []);

  if (!me?.user) {
    return null; // RequireAuth handles redirect
  }

  return (
    <div className="min-h-screen bg-hax-bg text-hax-text font-mono p-4 flex flex-col gap-4">
      <TopBar
        now={now}
        currentTick={currentTick}
        progress={tickProgressPct}
        eventCount={attacks?.count ?? 0}
        leakCount={leaks.length}
      />

      <div className="flex-1 grid grid-cols-2 grid-rows-2 gap-4 min-h-0">
        <Panel title="services" sub={`last 5 ticks`}>
          <ServicesGrid stats={services?.services ?? []} />
        </Panel>

        <Panel title="incoming attacks" sub={`last ${attacks?.events.length ?? 0}`}>
          <AttackFeed events={attacks?.events ?? []} />
        </Panel>

        <Panel title="top attackers" sub="by event count">
          <TopAttackers top={top} />
        </Panel>

        <Panel title="flag leaks" sub={`${leaks.length} this window`}>
          <LeaksFeed leaks={leaks} />
        </Panel>
      </div>

      <div className="flex items-center text-[10px] uppercase tracking-[0.25em] text-hax-dim">
        <span className="text-hax-accent-bright">$</span>
        <span className="ml-2">w4rya war-room</span>
        <span className="ml-auto">
          <Link to="/" className="hover:text-hax-accent-bright">
            ← exit
          </Link>
        </span>
      </div>
    </div>
  );
}

function computeTickProgressPct(
  tick: { startDate?: string; tickLength?: number } | undefined,
  now: Date
): number {
  if (!tick?.startDate || !tick?.tickLength) return 0;
  const start = new Date(tick.startDate).getTime();
  if (isNaN(start)) return 0;
  const ms = now.getTime() - start;
  if (ms <= 0) return 0;
  return Math.floor(((ms % Number(tick.tickLength)) / Number(tick.tickLength)) * 100);
}

function TopBar({
  now,
  currentTick,
  progress,
  eventCount,
  leakCount,
}: {
  now: Date;
  currentTick: number;
  progress: number;
  eventCount: number;
  leakCount: number;
}) {
  return (
    <div
      className="bg-hax-surface border border-hax-border rounded-sm px-6 py-3 flex items-center gap-8"
      style={{
        boxShadow:
          "0 0 24px -8px rgba(168, 85, 247, 0.45), inset 0 -1px 0 0 rgba(168, 85, 247, 0.4)",
      }}
    >
      <div className="flex items-center gap-3">
        <img
          src="/logo.png"
          alt="w4rya"
          className="h-10 w-10"
          style={{ filter: "drop-shadow(0 0 10px rgba(168, 85, 247, 0.65))" }}
        />
        <div>
          <div
            className="text-3xl tracking-[0.25em] font-bold"
            style={{ textShadow: "0 0 14px rgba(168, 85, 247, 0.55)" }}
          >
            W4RYA
          </div>
          <div className="text-[10px] uppercase tracking-[0.4em] text-hax-muted">
            war room
          </div>
        </div>
      </div>

      <Big label="tick" value={String(currentTick)} accent />
      <Big
        label="progress"
        value={`${progress}%`}
        sub={
          <div className="w-32 h-1 mt-1 bg-hax-elev rounded-sm overflow-hidden">
            <div
              className="h-full bg-hax-accent"
              style={{ width: `${progress}%` }}
            />
          </div>
        }
      />
      <Big label="events" value={String(eventCount)} />
      <Big
        label="leaks"
        value={String(leakCount)}
        danger={leakCount > 0}
      />

      <div className="ml-auto text-right">
        <div className="text-3xl font-bold text-hax-text">
          {now.toLocaleTimeString()}
        </div>
        <div className="text-[10px] uppercase tracking-[0.3em] text-hax-dim">
          {now.toISOString().slice(0, 10)}
        </div>
      </div>
    </div>
  );
}

function Big({
  label,
  value,
  sub,
  accent,
  danger,
}: {
  label: string;
  value: string;
  sub?: React.ReactNode;
  accent?: boolean;
  danger?: boolean;
}) {
  const cls = danger
    ? "text-hax-danger hax-glow"
    : accent
    ? "text-hax-accent-bright hax-glow"
    : "text-hax-text";
  return (
    <div className="flex flex-col">
      <div className="text-[10px] uppercase tracking-[0.3em] text-hax-muted">
        {label}
      </div>
      <div className={`text-3xl font-bold ${cls}`}>{value}</div>
      {sub}
    </div>
  );
}

function Panel({
  title,
  sub,
  children,
}: {
  title: string;
  sub?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="bg-hax-surface border border-hax-border rounded-sm flex flex-col min-h-0">
      <div className="px-4 py-2 border-b border-hax-border flex items-center">
        <span className="text-xs uppercase tracking-[0.3em] text-hax-accent-bright font-bold">
          ▎{title}
        </span>
        {sub && (
          <span className="ml-3 text-[10px] uppercase tracking-wider text-hax-dim">
            {sub}
          </span>
        )}
      </div>
      <div className="flex-1 overflow-auto p-3">{children}</div>
    </div>
  );
}

function ServicesGrid({ stats }: { stats: ServiceStats[] }) {
  if (stats.length === 0) {
    return (
      <div className="text-hax-dim text-sm text-center py-8">
        no services configured
      </div>
    );
  }
  return (
    <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-2">
      {stats.map((s) => {
        const danger = s.flag_out > 0;
        const warning = !danger && s.attacks > 0;
        const idle = s.flows === 0;
        const borderCls = danger
          ? "border-hax-danger bg-hax-danger/10"
          : warning
          ? "border-hax-warning/60 bg-hax-warning/10"
          : !idle
          ? "border-hax-accent-deep/50 bg-hax-elev"
          : "border-hax-border bg-hax-elev/40";
        return (
          <div
            key={s.name + ":" + s.port}
            className={`border ${borderCls} rounded-sm px-3 py-2`}
          >
            <div className="flex items-baseline">
              <span className="text-lg font-bold uppercase tracking-wide text-hax-text">
                {s.name}
              </span>
              <span className="ml-1 text-xs text-hax-dim">:{s.port}</span>
            </div>
            <div className="flex gap-3 mt-1 text-xs">
              <span className="text-hax-text">
                <span className="text-hax-dim">flows</span> {s.flows}
              </span>
              <span className="text-hax-warning">
                <span className="text-hax-dim">⚔</span> {s.attacks}
              </span>
              <span className={s.flag_out > 0 ? "text-hax-danger hax-glow" : "text-hax-dim"}>
                <span className="text-hax-dim">🚩</span> {s.flag_out}
              </span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function AttackFeed({ events }: { events: AttackEvent[] }) {
  if (events.length === 0) {
    return (
      <div className="text-hax-dim text-sm text-center py-8">
        ▎no attack events in current window
      </div>
    );
  }
  return (
    <ul className="flex flex-col gap-1 text-sm">
      {events.slice(0, 20).map((ev) => {
        const t = new Date(ev.time);
        const tStr = isNaN(t.getTime()) ? ev.time : t.toLocaleTimeString();
        const cls =
          ev.type === "flag_out" || ev.type === "both"
            ? "text-hax-danger"
            : "text-hax-warning";
        const glyph =
          ev.type === "both" ? "🚩+⚔" : ev.type === "flag_out" ? "🚩" : "⚔";
        return (
          <li
            key={ev.flow_id}
            className="flex items-center gap-2 border-b border-hax-border/50 pb-1"
          >
            <span className="text-hax-muted text-xs w-20">{tStr}</span>
            <span className={`${cls} text-xs w-12`}>{glyph}</span>
            <span className="text-hax-text text-xs flex-1 truncate">
              <span className="text-hax-dim">{ev.src_ip}</span>
              <span className="text-hax-muted"> → </span>
              <span className="text-hax-accent-bright">{ev.service}</span>
              {ev.rules[0] && (
                <span className="text-hax-dim ml-2">[{ev.rules[0].message}]</span>
              )}
            </span>
          </li>
        );
      })}
    </ul>
  );
}

function TopAttackers({ top }: { top: { ip: string; count: number; flags: number }[] }) {
  if (top.length === 0) {
    return (
      <div className="text-hax-dim text-sm text-center py-8">
        no attackers in current window
      </div>
    );
  }
  const max = Math.max(1, ...top.map((t) => t.count));
  return (
    <ul className="flex flex-col gap-2 text-sm">
      {top.slice(0, 10).map((a) => {
        const pct = Math.floor((a.count / max) * 100);
        return (
          <li key={a.ip} className="flex items-center gap-3">
            <span className="font-mono text-hax-text w-32 truncate">{a.ip}</span>
            <div className="flex-1 h-2 bg-hax-elev rounded-sm overflow-hidden relative">
              <div
                className="h-full bg-hax-accent"
                style={{ width: `${pct}%` }}
              />
            </div>
            <span className="text-hax-text w-12 text-right tabular-nums">⚔ {a.count}</span>
            {a.flags > 0 && (
              <span className="text-hax-danger hax-glow w-12 text-right tabular-nums">
                🚩 {a.flags}
              </span>
            )}
          </li>
        );
      })}
    </ul>
  );
}

function LeaksFeed({ leaks }: { leaks: AttackEvent[] }) {
  if (leaks.length === 0) {
    return (
      <div className="text-hax-success text-sm text-center py-8 uppercase tracking-wider">
        ✓ no flag leaks
      </div>
    );
  }
  return (
    <ul className="flex flex-col gap-2 text-sm">
      {leaks.slice(0, 12).map((ev) => {
        const t = new Date(ev.time);
        const tStr = isNaN(t.getTime()) ? ev.time : t.toLocaleTimeString();
        return (
          <li
            key={ev.flow_id}
            className="border border-hax-danger/40 bg-hax-danger/10 rounded-sm px-2 py-1"
            style={{ boxShadow: "0 0 12px -8px rgba(239,68,68,0.6)" }}
          >
            <div className="flex items-baseline">
              <span className="text-hax-danger text-base hax-glow">🚩</span>
              <span className="text-hax-text text-sm ml-2 font-bold">
                {ev.service}
              </span>
              <span className="text-hax-dim text-xs ml-1">
                :{ev.dst_port}
              </span>
              <span className="text-hax-muted text-xs ml-auto">{tStr}</span>
            </div>
            <div className="text-xs text-hax-muted truncate">
              from {ev.src_ip} · {ev.flag_out_count} flag{ev.flag_out_count === 1 ? "" : "s"}
            </div>
          </li>
        );
      })}
    </ul>
  );
}

function topAttackers(events: AttackEvent[]) {
  const by: Record<string, { ip: string; count: number; flags: number }> = {};
  for (const ev of events) {
    const k = ev.src_ip;
    if (!by[k]) by[k] = { ip: k, count: 0, flags: 0 };
    by[k].count += 1;
    by[k].flags += ev.flag_out_count ?? 0;
  }
  return Object.values(by).sort((a, b) => b.count - a.count);
}
