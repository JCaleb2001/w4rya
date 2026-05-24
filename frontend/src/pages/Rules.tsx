import { useState } from "react";
import {
  Rule,
  RuleTemplate,
  useAddRuleMutation,
  useDeleteRuleMutation,
  useGetRulesQuery,
  useUpdateRuleMutation,
} from "../api";

export function Rules() {
  const { data, isLoading, refetch } = useGetRulesQuery();
  const [editingSid, setEditingSid] = useState<number | null>(null);
  const [creating, setCreating] = useState<string | null>(null); // raw seed text

  if (isLoading || !data) {
    return (
      <div className="p-6 bg-hax-bg text-hax-text font-mono min-h-full text-hax-muted text-xs">
        <span className="text-hax-accent-bright">$</span> loading rules<span className="hax-cursor"></span>
      </div>
    );
  }

  return (
    <div className="p-6 bg-hax-bg text-hax-text font-mono min-h-full">
      <div className="flex items-center gap-4 mb-4 flex-wrap">
        <div className="text-xs uppercase tracking-[0.4em] text-hax-accent-bright">
          ▎suricata rules
        </div>
        <span className="text-[10px] text-hax-dim">{data.file}</span>
        <span className="text-[10px] text-hax-muted ml-auto">
          {data.rules.length} rule{data.rules.length === 1 ? "" : "s"}
        </span>
        <button onClick={() => refetch()} className="hax-btn text-[10px]">
          refresh
        </button>
        <button
          onClick={() => {
            setCreating("");
            setEditingSid(null);
          }}
          className="hax-btn hax-btn-primary text-xs"
        >
          + new rule
        </button>
      </div>

      <div className="text-[10px] uppercase tracking-wider text-hax-warning border border-hax-warning/30 bg-hax-warning/5 px-3 py-2 mb-4 rounded-sm normal-case">
        ⚠ rules are saved to disk on every change. suricata needs to be reloaded for them to take effect:{" "}
        <code className="text-hax-warning">
          docker compose -f docker-compose-suricata.yml restart suricata
        </code>
      </div>

      <TemplatesBar
        templates={data.templates}
        onPick={(t) => {
          setCreating(t.raw);
          setEditingSid(null);
        }}
      />

      {creating !== null && (
        <NewRuleCard
          seed={creating}
          onCancel={() => setCreating(null)}
          onSaved={() => setCreating(null)}
        />
      )}

      <div className="bg-hax-surface border border-hax-border rounded-sm overflow-hidden">
        <table className="w-full text-xs">
          <thead>
            <tr className="text-hax-muted uppercase tracking-wider text-[10px] bg-hax-elev">
              <th className="text-left py-2 px-3 w-12">on</th>
              <th className="text-left py-2 px-3 w-24">sid</th>
              <th className="text-left py-2 px-3 w-20">action</th>
              <th className="text-left py-2 px-3">msg</th>
              <th className="text-left py-2 px-3 w-44">actions</th>
            </tr>
          </thead>
          <tbody>
            {data.rules.length === 0 && (
              <tr>
                <td colSpan={5} className="py-8 text-center text-hax-dim text-xs">
                  no rules yet — pick a template above or click + new rule
                </td>
              </tr>
            )}
            {data.rules.map((r) => (
              <RuleRow
                key={r.sid + ":" + (r.line_no ?? 0)}
                rule={r}
                expanded={editingSid === r.sid}
                onToggleExpand={() =>
                  setEditingSid((prev) => (prev === r.sid ? null : r.sid))
                }
              />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function TemplatesBar({
  templates,
  onPick,
}: {
  templates: RuleTemplate[];
  onPick: (t: RuleTemplate) => void;
}) {
  const [open, setOpen] = useState(false);
  return (
    <div className="mb-4 relative">
      <button
        onClick={() => setOpen((o) => !o)}
        className="hax-btn text-xs"
      >
        templates ▾
      </button>
      {open && (
        <div
          className="absolute z-10 mt-1 w-[36rem] bg-hax-surface border border-hax-border rounded-sm shadow-lg p-2"
          style={{ boxShadow: "0 0 24px -10px rgba(168,85,247,0.4)" }}
        >
          {templates.map((t) => (
            <button
              key={t.name}
              onClick={() => {
                onPick(t);
                setOpen(false);
              }}
              className="w-full text-left px-2 py-1.5 rounded-sm hover:bg-hax-elev"
            >
              <div className="text-xs text-hax-accent-bright">{t.name}</div>
              <div className="text-[10px] text-hax-dim font-mono truncate">{t.raw}</div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function NewRuleCard({
  seed,
  onCancel,
  onSaved,
}: {
  seed: string;
  onCancel: () => void;
  onSaved: () => void;
}) {
  const [raw, setRaw] = useState(seed);
  const [add, { isLoading, error }] = useAddRuleMutation();
  return (
    <div className="mb-4 bg-hax-surface border border-hax-accent/40 rounded-sm p-4"
      style={{ boxShadow: "0 0 18px -10px rgba(168,85,247,0.45)" }}>
      <div className="flex items-center mb-2">
        <div className="text-[10px] uppercase tracking-[0.25em] text-hax-accent-bright">
          ▎new rule
        </div>
        <span className="ml-3 text-[10px] text-hax-dim">
          omit sid: and one will be auto-assigned (≥ 1,000,000)
        </span>
      </div>
      <textarea
        autoFocus
        value={raw}
        onChange={(e) => setRaw(e.target.value)}
        rows={4}
        spellCheck={false}
        className="w-full text-xs font-mono"
        placeholder='alert http any any -> any any (msg:"example"; content:"..."; rev:1;)'
      />
      {error && (
        <div className="mt-2 text-xs text-hax-danger border border-hax-danger/40 bg-hax-danger/10 px-2 py-1 rounded-sm">
          ! {String((error as any)?.data?.error ?? "save failed")}
        </div>
      )}
      <div className="flex gap-2 mt-3">
        <button
          disabled={isLoading || !raw.trim()}
          onClick={async () => {
            try {
              await add({ raw, enabled: true }).unwrap();
              onSaved();
            } catch {}
          }}
          className="hax-btn hax-btn-primary disabled:opacity-50"
        >
          {isLoading ? "saving…" : "save →"}
        </button>
        <button onClick={onCancel} className="hax-btn">
          cancel
        </button>
      </div>
    </div>
  );
}

function RuleRow({
  rule,
  expanded,
  onToggleExpand,
}: {
  rule: Rule;
  expanded: boolean;
  onToggleExpand: () => void;
}) {
  const [update] = useUpdateRuleMutation();
  const [del, { isLoading: deleting }] = useDeleteRuleMutation();
  const [draft, setDraft] = useState(rule.raw);

  const actionColor =
    rule.action === "drop" || rule.action === "reject"
      ? "text-hax-danger"
      : rule.action === "alert"
      ? "text-hax-accent-bright"
      : "text-hax-muted";

  return (
    <>
      <tr
        className={`border-t border-hax-border ${
          !rule.enabled ? "opacity-60" : ""
        } hover:bg-hax-elev`}
      >
        <td className="py-2 px-3">
          <button
            onClick={() => update({ sid: rule.sid, enabled: !rule.enabled })}
            className={`w-7 h-4 rounded-sm border transition-colors ${
              rule.enabled
                ? "bg-hax-accent border-hax-accent"
                : "bg-hax-bg border-hax-border"
            }`}
            title={rule.enabled ? "disable" : "enable"}
          >
            <div
              className={`w-3 h-3 rounded-sm bg-hax-bg transition-transform ${
                rule.enabled ? "translate-x-3" : "translate-x-0.5"
              }`}
            />
          </button>
        </td>
        <td className="py-2 px-3 font-mono text-hax-text">{rule.sid}</td>
        <td className={`py-2 px-3 uppercase tracking-wider font-bold ${actionColor}`}>
          {rule.action ?? "?"}
        </td>
        <td className="py-2 px-3">
          <div className="text-hax-text truncate max-w-2xl">
            {rule.msg ?? <span className="text-hax-dim italic">{rule.parsed ? "(no msg)" : "(unparsed)"}</span>}
          </div>
        </td>
        <td className="py-2 px-3 flex gap-2">
          <button onClick={onToggleExpand} className="hax-btn text-[10px]">
            {expanded ? "close" : "edit"}
          </button>
          <button
            onClick={() => {
              if (confirm(`delete rule sid=${rule.sid}?`)) del(rule.sid);
            }}
            disabled={deleting}
            className="hax-btn text-[10px] text-hax-danger hover:border-hax-danger"
          >
            {deleting ? "…" : "delete"}
          </button>
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={5} className="bg-hax-bg p-3 border-t border-hax-accent/30">
            <div className="text-[10px] uppercase tracking-wider text-hax-muted mb-1">
              raw rule
            </div>
            <textarea
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              rows={3}
              spellCheck={false}
              className="w-full text-xs font-mono"
            />
            <div className="mt-2 flex gap-2">
              <button
                onClick={async () => {
                  try {
                    await update({ sid: rule.sid, raw: draft }).unwrap();
                    onToggleExpand();
                  } catch {}
                }}
                className="hax-btn hax-btn-primary"
              >
                save →
              </button>
              <button onClick={onToggleExpand} className="hax-btn">
                cancel
              </button>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
