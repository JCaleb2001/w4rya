import { BackupStatus, Job, BackupResult, LocalStatus } from "../types";
import { BTN_PRIMARY, Card, ErrorLine, JobLine } from "./Card";

const STATUS: Record<BackupStatus, { label: string; cls: string }> = {
  created: { label: "baseline", cls: "text-hax-accent-bright" },
  updated: { label: "new snapshot", cls: "text-hax-success" },
  unchanged: { label: "unchanged", cls: "text-hax-muted" },
  error: { label: "error", cls: "text-hax-danger" },
};

const LOCAL_CLS: Record<LocalStatus, string> = {
  cloned: "text-hax-success",
  pulled: "text-hax-success",
  "up to date": "text-hax-muted",
  error: "text-hax-danger",
  skipped: "text-hax-dim",
};

/**
 * Step 4 — git baseline + snapshots of every service. The first run is the
 * baseline: take it in the 11:00–12:00 window, before other teams can reach
 * the box. Repos live outside the service dirs on the vulnbox (no .git in a
 * served directory), and are mirrored to ./vulnbox-data/backups/ here.
 */
export function BackupCard({
  job,
  canOperate,
  busy,
  onRun,
}: {
  job?: Job<BackupResult>;
  canOperate: boolean;
  busy: boolean;
  onRun: () => void;
}) {
  const result = job?.state === "done" ? job.result : null;
  const everRan = Boolean(job && job.state !== "running");

  return (
    <Card step={4} title="backup" when="11:00 – 12:00">
      <p className="text-[10px] text-hax-dim leading-relaxed">
        First run = baseline (the original code). Later runs commit only what
        changed. Local copies: <code className="text-hax-muted">./vulnbox-data/backups/</code>
      </p>

      <div className="flex flex-wrap items-center gap-2">
        <button
          onClick={onRun}
          disabled={!canOperate || busy}
          title={!canOperate ? "requires operator role" : busy ? "a job is running" : undefined}
          className={BTN_PRIMARY}
        >
          {everRan ? "snapshot now →" : "take baseline →"}
        </button>
        <JobLine job={job} />
      </div>

      {result?.fatal && <ErrorLine text={result.fatal} />}

      {result && result.services.length > 0 && (
        <table className="w-full text-xs">
          <thead>
            <tr className="text-hax-muted uppercase tracking-wider text-[10px]">
              <th className="text-left py-1 pr-2">service</th>
              <th className="text-left py-1 pr-2">vulnbox</th>
              <th className="text-left py-1 pr-2">commit</th>
              <th className="text-right py-1 pr-2">files</th>
              <th className="text-left py-1">local copy</th>
            </tr>
          </thead>
          <tbody>
            {result.services.map((s) => (
              <tr key={s.name} className="border-t border-hax-border align-top">
                <td className="py-1 pr-2 text-hax-text">{s.name}</td>
                <td className={`py-1 pr-2 ${STATUS[s.status].cls}`} title={s.detail || undefined}>
                  {STATUS[s.status].label}
                </td>
                <td className="py-1 pr-2 text-hax-muted">{s.commit || "—"}</td>
                <td className="py-1 pr-2 text-right text-hax-muted">
                  {s.files}
                  {s.skipped.length > 0 && (
                    <span
                      className="ml-1 text-hax-warning"
                      title={s.skipped.map((f) => `${f.path} (${f.bytes} B)`).join("\n")}
                    >
                      +{s.skipped.length} skipped
                    </span>
                  )}
                </td>
                <td className={`py-1 ${LOCAL_CLS[s.local]}`} title={s.local_detail || undefined}>
                  {s.local}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Card>
  );
}
