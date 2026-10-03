import { useState } from "react";
import { useApplyVulnboxPresetMutation } from "../api";
import { CheckStatus, Job, PreflightResult, PresetInfo, PresetResult } from "../types";
import { BTN, BTN_PRIMARY, Card, ErrorLine, JobLine, OkLine, errorText } from "./Card";

const LABELS: Record<string, string> = {
  key: "ssh key",
  reachable: "host reachable",
  ssh_auth: "ssh login",
  services_path: "services path",
  git: "git on the box",
  docker: "docker on the box",
};

const MARK: Record<CheckStatus, { icon: string; cls: string }> = {
  ok: { icon: "✓", cls: "text-hax-success" },
  fail: { icon: "✗", cls: "text-hax-danger" },
  skipped: { icon: "–", cls: "text-hax-dim" },
};

/**
 * Step 2 — read-only checklist. It creates nothing on the vulnbox, so it is
 * safe to run at any time. Also hosts the game presets: named bundles of
 * /config values (round length, flag format, ...) for a specific game.
 */
export function PreflightCard({
  job,
  presets,
  canOperate,
  canAdmin,
  busy,
  onRun,
}: {
  job?: Job<PreflightResult>;
  presets: PresetInfo[];
  canOperate: boolean;
  canAdmin: boolean;
  busy: boolean;
  onRun: () => void;
}) {
  const checks = job?.state === "done" ? job.result?.checks ?? [] : [];

  return (
    <Card step={2} title="preflight" when="once the box is up">
      <p className="text-[10px] text-hax-dim leading-relaxed">
        Read-only: checks in order, stopping at the first broken link, so the
        message names the real problem. Changes nothing on the box.
      </p>

      <div className="flex flex-wrap items-center gap-2">
        <button
          onClick={onRun}
          disabled={!canOperate || busy}
          title={!canOperate ? "requires operator role" : busy ? "a job is running" : undefined}
          className={BTN_PRIMARY}
        >
          run preflight →
        </button>
        <JobLine job={job} />
      </div>

      {checks.length > 0 && (
        <ul className="flex flex-col gap-1 text-xs">
          {checks.map((c) => (
            <li key={c.name} className="flex gap-2 min-w-0">
              <span className={`${MARK[c.status].cls} w-3 shrink-0`}>{MARK[c.status].icon}</span>
              <span className="text-hax-text w-36 shrink-0">{LABELS[c.name] ?? c.name}</span>
              <span className="text-hax-muted break-words min-w-0">{c.detail}</span>
            </li>
          ))}
        </ul>
      )}

      {presets.length > 0 && <PresetPicker presets={presets} canAdmin={canAdmin} />}
    </Card>
  );
}

function PresetPicker({ presets, canAdmin }: { presets: PresetInfo[]; canAdmin: boolean }) {
  const [apply, { isLoading: applying }] = useApplyVulnboxPresetMutation();
  const [selectedId, setSelectedId] = useState(presets[0].id);
  const [result, setResult] = useState<PresetResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const selected = presets.find((p) => p.id === selectedId) ?? presets[0];

  async function onApply() {
    const list = Object.entries(selected.values)
      .map(([k, v]) => `  ${k} = ${v}`)
      .join("\n");
    if (
      !window.confirm(
        `apply the "${selected.name}" preset to /config?\n\n${list}\n\n` +
          "if it sets a start time in the future, ticks read negative until then."
      )
    )
      return;
    setError(null);
    setResult(null);
    try {
      setResult(await apply(selected.id).unwrap());
    } catch (err) {
      setError(errorText(err, "could not apply the preset"));
    }
  }

  return (
    <div className="border-t border-hax-border pt-3 flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[10px] uppercase tracking-[0.2em] text-hax-muted">
          <span className="text-hax-accent-bright">$</span> game preset
        </span>
        <select
          value={selected.id}
          onChange={(e) => setSelectedId(e.target.value)}
          className="text-xs"
        >
          {presets.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
        </select>
        <button
          onClick={onApply}
          disabled={!canAdmin || applying}
          title={!canAdmin ? "requires admin role" : undefined}
          className={BTN}
        >
          {applying ? "applying…" : "apply"}
        </button>
        {selected.applied && (
          <span className="text-[10px] text-hax-dim">✓ applied in /config</span>
        )}
      </div>

      {error && <ErrorLine text={error} />}
      {result && (
        <>
          <OkLine text={`"${selected.name}" applied to /config`} />
          {Object.keys(result.env).length > 0 && (
            <>
              <div className="text-[10px] text-hax-warning">
                ⚠ the assembler reads these from .env at boot — set the same lines
                (./install.sh or edit .env) and restart it:
              </div>
              <pre className="text-[10px] text-hax-muted bg-hax-elev border border-hax-border rounded-sm px-3 py-2 overflow-x-auto">
                {Object.entries(result.env)
                  .map(([k, v]) => `${k}=${v}`)
                  .join("\n")}
              </pre>
            </>
          )}
        </>
      )}
    </div>
  );
}
