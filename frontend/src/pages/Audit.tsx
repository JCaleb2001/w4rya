import { useMemo, useState } from "react";
import {
  AuditEvent,
  AuditQuery,
  hasRole,
  useGetAuditActorsQuery,
  useGetAuditQuery,
  useGetMeQuery,
} from "../api";
import { API_BASE_PATH } from "../const";

const ACTION_PREFIXES = [
  { value: "", label: "any" },
  { value: "auth.", label: "auth.*" },
  { value: "config.", label: "config.*" },
  { value: "rules.", label: "rules.*" },
  { value: "suricata.", label: "suricata.*" },
  { value: "attack.", label: "attack.*" },
];

const TIME_PRESETS = [
  { value: 0, label: "all" },
  { value: 15, label: "last 15m" },
  { value: 60, label: "last 1h" },
  { value: 60 * 6, label: "last 6h" },
  { value: 60 * 24, label: "last 24h" },
];

export function Audit() {
  const { data: me } = useGetMeQuery();
  const allowed = hasRole(me?.role, "admin");

  const [actor, setActor] = useState<string>("");
  const [actionPrefix, setActionPrefix] = useState<string>("");
  const [minutesBack, setMinutesBack] = useState<number>(0);

  const fromIso = useMemo(() => {
    if (!minutesBack) return undefined;
    return new Date(Date.now() - minutesBack * 60_000).toISOString();
  }, [minutesBack]);

  const query: AuditQuery = {
    limit: 500,
    actor: actor || undefined,
    action: actionPrefix || undefined,
    from: fromIso,
  };

  const { data, isLoading } = useGetAuditQuery(query, {
    skip: !allowed,
    pollingInterval: 30000,
  });
  const { data: actors } = useGetAuditActorsQuery(undefined, { skip: !allowed });

  if (!allowed) {
    return (
      <div className="p-6 bg-hax-bg text-hax-text font-mono min-h-full text-hax-danger text-xs uppercase tracking-wider">
        ▎access denied — admin only.{" "}
        <span className="text-hax-muted normal-case tracking-normal">
          your role: {me?.role ?? "unknown"}
        </span>
      </div>
    );
  }

  function exportHref(): string {
    const sp = new URLSearchParams();
    if (actor) sp.set("actor", actor);
    if (actionPrefix) sp.set("action", actionPrefix);
    if (fromIso) sp.set("from", fromIso);
    sp.set("limit", "10000");
    return `${API_BASE_PATH}/audit/export.csv?${sp.toString()}`;
  }

  return (
    <div className="p-6 bg-hax-bg text-hax-text font-mono min-h-full">
      <div className="flex items-center gap-4 mb-4 flex-wrap">
        <div className="text-xs uppercase tracking-[0.4em] text-hax-accent-bright">
          ▎audit log
        </div>
        <span className="text-[10px] text-hax-muted ml-auto">
          {data?.count ?? 0} entries
        </span>
      </div>

      <div className="bg-hax-surface border border-hax-border rounded-sm p-3 mb-4 flex items-center gap-3 flex-wrap text-xs">
        <span className="text-[10px] uppercase tracking-wider text-hax-muted">
          actor
        </span>
        <select
          value={actor}
          onChange={(e) => setActor(e.target.value)}
          className="text-xs"
        >
          <option value="">any</option>
          {(actors ?? []).map((a) => (
            <option key={a} value={a}>
              {a}
            </option>
          ))}
        </select>

        <span className="text-[10px] uppercase tracking-wider text-hax-muted ml-3">
          action
        </span>
        <select
          value={actionPrefix}
          onChange={(e) => setActionPrefix(e.target.value)}
          className="text-xs"
        >
          {ACTION_PREFIXES.map((a) => (
            <option key={a.value} value={a.value}>
              {a.label}
            </option>
          ))}
        </select>

        <span className="text-[10px] uppercase tracking-wider text-hax-muted ml-3">
          range
        </span>
        {TIME_PRESETS.map((p) => (
          <button
            key={p.value}
            onClick={() => setMinutesBack(p.value)}
            className={`hax-btn text-[10px] ${
              minutesBack === p.value ? "hax-btn-primary" : ""
            }`}
          >
            {p.label}
          </button>
        ))}

        <a
          href={exportHref()}
          className="hax-btn text-[10px] ml-auto"
          title="download CSV with current filters (cap 10k rows)"
        >
          ↓ export csv
        </a>
      </div>

      {isLoading || !data ? (
        <div className="text-hax-muted text-xs">
          <span className="text-hax-accent-bright">$</span> loading
          <span className="hax-cursor"></span>
        </div>
      ) : (
        <div className="bg-hax-surface border border-hax-border rounded-sm overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-hax-muted uppercase tracking-wider text-[10px] bg-hax-elev">
                <th className="text-left py-2 px-3 w-40">when</th>
                <th className="text-left py-2 px-3 w-32">actor</th>
                <th className="text-left py-2 px-3 w-44">action</th>
                <th className="text-left py-2 px-3 w-48">target</th>
                <th className="text-left py-2 px-3">details</th>
              </tr>
            </thead>
            <tbody>
              {data.events.length === 0 && (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-hax-dim text-xs">
                    no entries match the current filters
                  </td>
                </tr>
              )}
              {data.events.map((ev) => (
                <AuditRow key={ev.id} ev={ev} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function AuditRow({ ev }: { ev: AuditEvent }) {
  const when = new Date(ev.when);
  const whenStr = isNaN(when.getTime()) ? ev.when : when.toLocaleString();
  const actionColor = ev.action.startsWith("auth")
    ? "text-hax-accent-bright"
    : ev.action.startsWith("rules") || ev.action.startsWith("suricata")
    ? "text-hax-warning"
    : ev.action.startsWith("attack")
    ? "text-hax-danger"
    : "text-hax-text";
  return (
    <tr className="border-t border-hax-border hover:bg-hax-elev">
      <td className="py-1.5 px-3 text-hax-muted">{whenStr}</td>
      <td className="py-1.5 px-3 text-hax-accent-bright">@{ev.actor}</td>
      <td className={`py-1.5 px-3 ${actionColor}`}>{ev.action}</td>
      <td className="py-1.5 px-3 text-hax-text truncate max-w-xs">
        {ev.target ?? <span className="text-hax-dim">—</span>}
      </td>
      <td className="py-1.5 px-3 text-hax-muted text-[10px] truncate max-w-md">
        {ev.details ? JSON.stringify(ev.details) : ""}
      </td>
    </tr>
  );
}
