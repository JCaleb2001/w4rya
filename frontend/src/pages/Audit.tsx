import { AuditEvent, useGetAuditQuery, useGetMeQuery, hasRole } from "../api";

export function Audit() {
  const { data: me } = useGetMeQuery();
  const allowed = hasRole(me?.role, "admin");

  const { data, isLoading } = useGetAuditQuery(300, {
    skip: !allowed,
    pollingInterval: 30000,
  });

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

  if (isLoading || !data) {
    return (
      <div className="p-6 bg-hax-bg text-hax-text font-mono min-h-full text-hax-muted text-xs">
        <span className="text-hax-accent-bright">$</span> loading audit log
        <span className="hax-cursor"></span>
      </div>
    );
  }

  return (
    <div className="p-6 bg-hax-bg text-hax-text font-mono min-h-full">
      <div className="flex items-center gap-4 mb-4 flex-wrap">
        <div className="text-xs uppercase tracking-[0.4em] text-hax-accent-bright">
          ▎audit log
        </div>
        <span className="text-[10px] text-hax-muted ml-auto">
          {data.count} entries
        </span>
      </div>
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
                  no audit entries yet
                </td>
              </tr>
            )}
            {data.events.map((ev) => (
              <AuditRow key={ev.id} ev={ev} />
            ))}
          </tbody>
        </table>
      </div>
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
