import { Link, useSearchParams } from "react-router-dom";
import {
  AttackEvent,
  useGetAttacksQuery,
  useGetServicesQuery,
} from "../api";

const POLL_MS = 20000;

export function Attacks() {
  const [searchParams, setSearchParams] = useSearchParams();
  const { data: services } = useGetServicesQuery();

  const service = searchParams.get("service") ?? "";
  const fromTickParam = searchParams.get("from_tick");
  const toTickParam = searchParams.get("to_tick");

  const fromTick = fromTickParam ? Number(fromTickParam) : undefined;
  const toTick = toTickParam ? Number(toTickParam) : undefined;

  const { data, isLoading, isFetching, refetch } = useGetAttacksQuery(
    { from_tick: fromTick, to_tick: toTick, service: service || undefined },
    { pollingInterval: POLL_MS, refetchOnMountOrArgChange: true }
  );

  function setParam(k: string, v?: string | number | null) {
    const sp = new URLSearchParams(searchParams);
    if (v === null || v === undefined || v === "") sp.delete(k);
    else sp.set(k, String(v));
    setSearchParams(sp);
  }

  function setRange(ticks: number) {
    const cur = data?.current_tick ?? 0;
    setParam("from_tick", Math.max(0, cur - ticks));
    setParam("to_tick", cur + 1);
  }

  if (isLoading || !data) {
    return (
      <div className="p-6 bg-hax-bg text-hax-text font-mono min-h-full text-hax-muted text-xs">
        <span className="text-hax-accent-bright">$</span> loading attacks<span className="hax-cursor"></span>
      </div>
    );
  }

  return (
    <div className="p-6 bg-hax-bg text-hax-text font-mono min-h-full">
      <div className="flex items-center gap-4 mb-4 flex-wrap">
        <div className="text-xs uppercase tracking-[0.4em] text-hax-accent-bright">
          ▎attacks timeline
        </div>
        <span className="text-[10px] text-hax-dim">
          tick {data.from_tick} → {data.to_tick} · current {data.current_tick}
        </span>
        <span className="text-[10px] text-hax-muted ml-auto">
          {data.count} event{data.count === 1 ? "" : "s"}{" "}
          {isFetching && <span className="ml-2 text-hax-accent-bright">⟳</span>}
        </span>
      </div>

      <div className="bg-hax-surface border border-hax-border rounded-sm p-3 mb-4 flex items-center gap-3 flex-wrap text-xs">
        <span className="text-[10px] uppercase tracking-wider text-hax-muted">range</span>
        {[5, 10, 30, 60].map((n) => (
          <button
            key={n}
            onClick={() => setRange(n)}
            className="hax-btn text-[10px]"
            title={`last ${n} ticks`}
          >
            last {n}
          </button>
        ))}
        <span className="text-[10px] uppercase tracking-wider text-hax-muted ml-3">
          service
        </span>
        <select
          value={service}
          onChange={(e) => setParam("service", e.target.value || null)}
          className="text-xs"
        >
          <option value="">all</option>
          {(services ?? []).map((s) => (
            <option key={s.name + ":" + s.port} value={s.name}>
              {s.name}
            </option>
          ))}
        </select>
        <button onClick={() => refetch()} className="hax-btn text-[10px] ml-auto">
          refresh
        </button>
      </div>

      <div className="bg-hax-surface border border-hax-border rounded-sm overflow-hidden">
        <table className="w-full text-xs">
          <thead>
            <tr className="text-hax-muted uppercase tracking-wider text-[10px] bg-hax-elev">
              <th className="text-left py-2 px-3 w-32">time</th>
              <th className="text-left py-2 px-3 w-20">type</th>
              <th className="text-left py-2 px-3 w-40">attacker</th>
              <th className="text-left py-2 px-3 w-32">service</th>
              <th className="text-left py-2 px-3">detail</th>
              <th className="text-left py-2 px-3 w-16">flow</th>
            </tr>
          </thead>
          <tbody>
            {data.events.length === 0 && (
              <tr>
                <td colSpan={6} className="py-8 text-center text-hax-dim text-xs">
                  no events in range — try a wider tick window or check that
                  Suricata is running
                </td>
              </tr>
            )}
            {data.events.map((ev) => (
              <AttackRow key={ev.flow_id} ev={ev} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function AttackRow({ ev }: { ev: AttackEvent }) {
  const t = new Date(ev.time);
  const timeStr = isNaN(t.getTime()) ? ev.time : t.toLocaleTimeString();

  const typeChip =
    ev.type === "both" ? (
      <span className="px-1.5 py-0.5 rounded-sm bg-hax-danger/20 border border-hax-danger text-red-300 uppercase tracking-wider text-[9px]">
        🚩+⚔
      </span>
    ) : ev.type === "flag_out" ? (
      <span className="px-1.5 py-0.5 rounded-sm bg-hax-danger/20 border border-hax-danger text-red-300 uppercase tracking-wider text-[9px]">
        🚩 leak
      </span>
    ) : (
      <span className="px-1.5 py-0.5 rounded-sm bg-hax-warning/20 border border-hax-warning/60 text-hax-warning uppercase tracking-wider text-[9px]">
        ⚔ alert
      </span>
    );

  return (
    <tr className="border-t border-hax-border hover:bg-hax-elev">
      <td className="py-1.5 px-3 text-hax-muted">{timeStr}</td>
      <td className="py-1.5 px-3">{typeChip}</td>
      <td className="py-1.5 px-3 text-hax-text">
        {ev.src_ip}
        <span className="text-hax-dim">:{ev.src_port}</span>
      </td>
      <td className="py-1.5 px-3 text-hax-accent-bright">
        {ev.service}
        <span className="text-hax-dim">:{ev.dst_port}</span>
      </td>
      <td className="py-1.5 px-3 text-hax-text">
        {ev.rules.length > 0 && (
          <div className="flex flex-col gap-0.5">
            {ev.rules.map((r, i) => (
              <div key={i}>
                <span
                  className={
                    r.action === "blocked" || r.action === "drop"
                      ? "text-hax-danger"
                      : "text-hax-warning"
                  }
                >
                  [{r.action}]
                </span>{" "}
                <span className="text-hax-text">{r.message}</span>
                <span className="text-hax-dim ml-1">#{r.id}</span>
              </div>
            ))}
          </div>
        )}
        {ev.flag_out_count > 0 && (
          <div className="text-hax-danger">
            {ev.flag_out_count} flag{ev.flag_out_count === 1 ? "" : "s"} leaked
          </div>
        )}
      </td>
      <td className="py-1.5 px-3">
        <Link
          to={`/flow/${ev.flow_id}`}
          className="hax-btn text-[10px] inline-block"
        >
          open →
        </Link>
      </td>
    </tr>
  );
}
