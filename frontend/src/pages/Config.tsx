import { useEffect, useState } from "react";
import {
  useGetConfigQuery,
  useUpdateConfigMutation,
  useGetConfigServicesQuery,
  useUpdateConfigServicesMutation,
  useGetConfigTeamsQuery,
  useUpdateConfigTeamsMutation,
  useCanRole,
  useMyRole,
  GameConfig,
  Team,
} from "../api";
import { Service } from "../types";

const TABS = ["game", "services", "teams"] as const;
type Tab = (typeof TABS)[number];

export function Config() {
  const [tab, setTab] = useState<Tab>("game");
  const canEdit = useCanRole("admin");
  const role = useMyRole();
  return (
    <div className="p-6 bg-hax-bg text-hax-text font-mono min-h-full">
      <div className="flex items-center gap-4 mb-6">
        <div className="text-xs uppercase tracking-[0.4em] text-hax-accent-bright">
          ▎config
        </div>
        <div className="flex gap-2">
          {TABS.map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`hax-btn ${t === tab ? "hax-btn-primary" : ""}`}
            >
              {t}
            </button>
          ))}
        </div>
      </div>
      {!canEdit && (
        <div className="mb-4 max-w-3xl text-[10px] uppercase tracking-wider text-hax-warning border border-hax-warning/40 bg-hax-warning/5 px-3 py-2 rounded-sm normal-case">
          ⚠ read-only — your role is{" "}
          <span className="font-bold">{role ?? "?"}</span>; saving requires{" "}
          <span className="font-bold">admin</span>.
        </div>
      )}
      {tab === "game" && <GameForm canEdit={canEdit} />}
      {tab === "services" && <ServicesEditor canEdit={canEdit} />}
      {tab === "teams" && <TeamsEditor canEdit={canEdit} />}
    </div>
  );
}

function GameForm({ canEdit }: { canEdit: boolean }) {
  const { data, isLoading } = useGetConfigQuery();
  const [update, { isLoading: saving, error, isSuccess }] = useUpdateConfigMutation();
  const [form, setForm] = useState<Partial<GameConfig>>({});

  useEffect(() => {
    if (data) setForm(data);
  }, [data]);

  if (isLoading || !data) return <Loading />;

  function set<K extends keyof GameConfig>(k: K, v: GameConfig[K]) {
    setForm((p) => ({ ...p, [k]: v }));
  }

  async function save() {
    try {
      await update(form).unwrap();
    } catch {
      /* error is in `error` prop */
    }
  }

  const RESTART = "⚠ restart assembler to fully apply";
  // rules_autoreload is a boolean managed by the /rules page toggle; not
  // shown in this text-input form.
  const labels: Partial<Record<
    keyof GameConfig,
    { label: string; note?: string; type?: string }
  >> = {
    flag_regex: { label: "flag regex", note: RESTART },
    tick_length: { label: "tick length (ms)", type: "number" },
    start_date: { label: "tick start (iso8601 utc)" },
    flag_lifetime: { label: "flag lifetime (ticks)", type: "number" },
    vm_ip: { label: "our team vm ip" },
    team_id: { label: "our team id" },
    visualizer_url: { label: "visualizer url (optional)" },
    bpf: { label: "bpf filter (optional)", note: RESTART },
  };

  return (
    <div
      className="max-w-2xl bg-hax-surface border border-hax-border rounded-sm p-6 flex flex-col gap-4"
      style={{ boxShadow: "0 0 24px -16px rgba(168, 85, 247, 0.4)" }}
    >
      <div className="text-xs uppercase tracking-[0.25em] text-hax-muted border-b border-hax-border pb-2">
        ▎game
      </div>
      {(Object.keys(labels) as (keyof GameConfig)[]).map((k) => {
        const meta = labels[k]!;
        return (
          <label key={k} className="flex flex-col gap-1">
            <span className="text-[10px] uppercase tracking-[0.2em] text-hax-muted">
              <span className="text-hax-accent-bright">$</span> {meta.label}
              {meta.note && (
                <span className="ml-2 text-hax-warning normal-case tracking-normal">
                  {meta.note}
                </span>
              )}
            </span>
            <input
              type={meta.type ?? "text"}
              value={(form[k] ?? "") as string | number}
              onChange={(e) => {
                const v =
                  meta.type === "number"
                    ? Number(e.target.value)
                    : e.target.value;
                set(k, v as any);
              }}
              className="text-sm"
              spellCheck={false}
              readOnly={!canEdit}
            />
          </label>
        );
      })}

      <ErrorOrSuccess error={error} ok={isSuccess && !saving} />

      <button
        onClick={save}
        disabled={saving || !canEdit}
        title={!canEdit ? "requires admin role" : undefined}
        className="hax-btn hax-btn-primary self-start mt-2 disabled:opacity-40 disabled:cursor-not-allowed"
      >
        {saving ? "saving…" : "save →"}
      </button>
    </div>
  );
}

function ServicesEditor({ canEdit }: { canEdit: boolean }) {
  const { data, isLoading } = useGetConfigServicesQuery();
  const [update, { isLoading: saving, error, isSuccess }] = useUpdateConfigServicesMutation();
  const [rows, setRows] = useState<Service[]>([]);

  useEffect(() => {
    if (data) setRows(data);
  }, [data]);

  if (isLoading) return <Loading />;

  function patch(i: number, p: Partial<Service>) {
    setRows((rs) => rs.map((r, idx) => (idx === i ? { ...r, ...p } : r)));
  }
  function add() {
    setRows((rs) => [...rs, { name: "", ip: "", port: 0 }]);
  }
  function remove(i: number) {
    setRows((rs) => rs.filter((_, idx) => idx !== i));
  }
  async function save() {
    try {
      await update(rows).unwrap();
    } catch {}
  }

  return (
    <div className="max-w-4xl bg-hax-surface border border-hax-border rounded-sm p-6 flex flex-col gap-4">
      <div className="flex items-center">
        <div className="text-xs uppercase tracking-[0.25em] text-hax-muted">
          ▎services
        </div>
        <span className="text-[10px] text-hax-dim ml-3 normal-case">
          map (ip, port) → name. used everywhere a flow is tagged with its service.
        </span>
        {canEdit && (
          <button onClick={add} className="hax-btn ml-auto">
            + add
          </button>
        )}
      </div>
      <table className="w-full text-xs">
        <thead>
          <tr className="text-hax-muted uppercase tracking-wider text-[10px]">
            <th className="text-left py-1 pr-2">name</th>
            <th className="text-left py-1 pr-2">ip</th>
            <th className="text-left py-1 pr-2">port</th>
            <th className="text-left py-1 pr-2">notes</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 && (
            <tr>
              <td colSpan={5} className="py-3 text-hax-dim text-center">
                no services yet{canEdit ? ' — click "+ add"' : ""}
              </td>
            </tr>
          )}
          {rows.map((r, i) => (
            <tr key={i} className="border-t border-hax-border">
              <td className="py-1 pr-2">
                <input
                  value={r.name}
                  onChange={(e) => patch(i, { name: e.target.value })}
                  className="text-xs w-full"
                  readOnly={!canEdit}
                />
              </td>
              <td className="py-1 pr-2">
                <input
                  value={r.ip}
                  onChange={(e) => patch(i, { ip: e.target.value })}
                  className="text-xs w-full"
                  spellCheck={false}
                  readOnly={!canEdit}
                />
              </td>
              <td className="py-1 pr-2">
                <input
                  type="number"
                  value={r.port}
                  onChange={(e) => patch(i, { port: Number(e.target.value) })}
                  className="text-xs w-20"
                  readOnly={!canEdit}
                />
              </td>
              <td className="py-1 pr-2">
                <input
                  value={(r as any).notes ?? ""}
                  onChange={(e) =>
                    patch(i, { notes: e.target.value } as any)
                  }
                  className="text-xs w-full"
                  readOnly={!canEdit}
                />
              </td>
              <td className="py-1">
                {canEdit && (
                  <button
                    onClick={() => remove(i)}
                    className="text-hax-danger text-[10px] uppercase tracking-wider hover:hax-glow"
                  >
                    remove
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <ErrorOrSuccess error={error} ok={isSuccess && !saving} />
      <button
        onClick={save}
        disabled={saving || !canEdit}
        title={!canEdit ? "requires admin role" : undefined}
        className="hax-btn hax-btn-primary self-start disabled:opacity-40 disabled:cursor-not-allowed"
      >
        {saving ? "saving…" : "save →"}
      </button>
    </div>
  );
}

function TeamsEditor({ canEdit }: { canEdit: boolean }) {
  const { data, isLoading } = useGetConfigTeamsQuery();
  const [update, { isLoading: saving, error, isSuccess }] = useUpdateConfigTeamsMutation();
  const [rows, setRows] = useState<Team[]>([]);

  useEffect(() => {
    if (data) setRows(data);
  }, [data]);

  if (isLoading) return <Loading />;

  function patch(i: number, p: Partial<Team>) {
    setRows((rs) => rs.map((r, idx) => (idx === i ? { ...r, ...p } : r)));
  }
  function add() {
    setRows((rs) => [...rs, { name: "", ip: "", notes: "" }]);
  }
  function remove(i: number) {
    setRows((rs) => rs.filter((_, idx) => idx !== i));
  }
  async function save() {
    try {
      await update(rows).unwrap();
    } catch {}
  }

  return (
    <div className="max-w-3xl bg-hax-surface border border-hax-border rounded-sm p-6 flex flex-col gap-4">
      <div className="flex items-center">
        <div className="text-xs uppercase tracking-[0.25em] text-hax-muted">
          ▎teams
        </div>
        <span className="text-[10px] text-hax-dim ml-3 normal-case">
          enemy teams. used by the exploit-replay feature (test a flow against everyone).
        </span>
        {canEdit && (
          <button onClick={add} className="hax-btn ml-auto">
            + add
          </button>
        )}
      </div>
      <table className="w-full text-xs">
        <thead>
          <tr className="text-hax-muted uppercase tracking-wider text-[10px]">
            <th className="text-left py-1 pr-2">name</th>
            <th className="text-left py-1 pr-2">ip</th>
            <th className="text-left py-1 pr-2">notes</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 && (
            <tr>
              <td colSpan={4} className="py-3 text-hax-dim text-center">
                no teams yet{canEdit ? ' — click "+ add"' : ""}
              </td>
            </tr>
          )}
          {rows.map((r, i) => (
            <tr key={i} className="border-t border-hax-border">
              <td className="py-1 pr-2">
                <input
                  value={r.name}
                  onChange={(e) => patch(i, { name: e.target.value })}
                  className="text-xs w-full"
                  readOnly={!canEdit}
                />
              </td>
              <td className="py-1 pr-2">
                <input
                  value={r.ip}
                  onChange={(e) => patch(i, { ip: e.target.value })}
                  className="text-xs w-full"
                  spellCheck={false}
                  readOnly={!canEdit}
                />
              </td>
              <td className="py-1 pr-2">
                <input
                  value={r.notes ?? ""}
                  onChange={(e) => patch(i, { notes: e.target.value })}
                  className="text-xs w-full"
                  readOnly={!canEdit}
                />
              </td>
              <td className="py-1">
                {canEdit && (
                  <button
                    onClick={() => remove(i)}
                    className="text-hax-danger text-[10px] uppercase tracking-wider hover:hax-glow"
                  >
                    remove
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <ErrorOrSuccess error={error} ok={isSuccess && !saving} />
      <button
        onClick={save}
        disabled={saving || !canEdit}
        title={!canEdit ? "requires admin role" : undefined}
        className="hax-btn hax-btn-primary self-start disabled:opacity-40 disabled:cursor-not-allowed"
      >
        {saving ? "saving…" : "save →"}
      </button>
    </div>
  );
}

function Loading() {
  return (
    <div className="text-hax-muted text-xs uppercase tracking-wider">
      <span className="text-hax-accent-bright">$</span> loading
      <span className="hax-cursor"></span>
    </div>
  );
}

function ErrorOrSuccess({ error, ok }: { error: any; ok: boolean }) {
  if (error) {
    return (
      <div className="text-xs text-hax-danger border border-hax-danger/40 bg-hax-danger/10 px-3 py-2 rounded-sm font-mono uppercase tracking-wider">
        ! save failed: {String(error?.data?.error ?? error?.status ?? "unknown")}
      </div>
    );
  }
  if (ok) {
    return (
      <div className="text-xs text-hax-success border border-hax-success/40 bg-hax-success/10 px-3 py-2 rounded-sm font-mono uppercase tracking-wider">
        ✓ saved
      </div>
    );
  }
  return null;
}
