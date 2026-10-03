import { useState } from "react";
import { useSeedVulnboxDefaultsMutation } from "../api";
import { CheckStatus, Job, PreflightResult, SeedResult } from "../types";
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
 * safe to run at any time. Also hosts the "ECSC 2026 defaults" button.
 */
export function PreflightCard({
  job,
  defaults,
  canOperate,
  canAdmin,
  busy,
  onRun,
}: {
  job?: Job<PreflightResult>;
  defaults: { values: Record<string, string | number>; applied: boolean };
  canOperate: boolean;
  canAdmin: boolean;
  busy: boolean;
  onRun: () => void;
}) {
  const [seed, { isLoading: seeding }] = useSeedVulnboxDefaultsMutation();
  const [seeded, setSeeded] = useState<SeedResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function onSeed() {
    const list = Object.entries(defaults.values)
      .map(([k, v]) => `  ${k} = ${v}`)
      .join("\n");
    if (
      !window.confirm(
        `apply the ECSC 2026 values to /config?\n\n${list}\n\n` +
          "ticks count from the game start, so they read negative until then."
      )
    )
      return;
    setError(null);
    try {
      setSeeded(await seed().unwrap());
    } catch (err) {
      setError(errorText(err, "could not apply the defaults"));
    }
  }

  const checks = job?.state === "done" ? job.result?.checks ?? [] : [];

  return (
    <Card step={2} title="preflight" when="10:30 – 11:00">
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

      <div className="border-t border-hax-border pt-3 flex flex-wrap items-center gap-2">
        <button
          onClick={onSeed}
          disabled={!canAdmin || seeding}
          title={!canAdmin ? "requires admin role" : undefined}
          className={BTN}
        >
          {seeding ? "applying…" : "ECSC 2026 defaults"}
        </button>
        <span className="text-[10px] text-hax-dim">
          {defaults.applied ? "✓ applied in /config" : "tick 60s · flag lifetime 5 · flag regex · start time"}
        </span>
      </div>

      {error && <ErrorLine text={error} />}
      {seeded && (
        <>
          <OkLine text="applied to /config" />
          <div className="text-[10px] text-hax-warning">
            ⚠ the assembler reads these from .env at boot — set the same lines
            (./install.sh or edit .env) and restart it:
          </div>
          <pre className="text-[10px] text-hax-muted bg-hax-elev border border-hax-border rounded-sm px-3 py-2 overflow-x-auto">
            {Object.entries(seeded.env)
              .map(([k, v]) => `${k}=${v}`)
              .join("\n")}
          </pre>
        </>
      )}
    </Card>
  );
}
