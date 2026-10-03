import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useCanRole, useMyRole, useVisibilityAwarePolling } from "../../api";
import { useGetVulnboxQuery, useStartVulnboxJobMutation } from "./api";
import { BackupCard } from "./components/BackupCard";
import { ErrorLine, errorText } from "./components/Card";
import { KeyCard } from "./components/KeyCard";
import { PreflightCard } from "./components/PreflightCard";
import { ReconCard } from "./components/ReconCard";
import { Job, JobKind } from "./types";

/**
 * /vulnbox — prepare and defend our own vulnbox, in the order a game needs
 * it: key → preflight → recon → backup. The backend is the security boundary
 * (403 with {required_role, your_role}); role checks here are UX only.
 */
export function VulnboxPage() {
  const canOperate = useCanRole("operator");
  const canAdmin = useCanRole("admin");
  const role = useMyRole();
  const poll = useVisibilityAwarePolling(2000);

  // Poll only while a job runs (and the tab is visible); one request covers
  // every card.
  const [pollMs, setPollMs] = useState(0);
  const { data, isLoading, isError } = useGetVulnboxQuery(undefined, {
    pollingInterval: pollMs,
  });
  const busy = data?.jobs.current?.state === "running";
  useEffect(() => setPollMs(busy ? poll : 0), [busy, poll]);

  const [startJob] = useStartVulnboxJobMutation();
  const [jobError, setJobError] = useState<string | null>(null);

  async function run(kind: JobKind) {
    setJobError(null);
    try {
      await startJob(kind).unwrap();
    } catch (err) {
      setJobError(errorText(err, `could not start ${kind}`));
    }
  }

  if (isLoading) {
    return (
      <div className="p-6 bg-hax-bg text-hax-text font-mono min-h-full text-hax-muted text-xs">
        <span className="text-hax-accent-bright">$</span> loading vulnbox
        <span className="hax-cursor"></span>
      </div>
    );
  }
  if (isError || !data) {
    return (
      <div className="p-6 bg-hax-bg text-hax-text font-mono min-h-full">
        <ErrorLine text="could not load /vulnbox — is the api up?" />
      </div>
    );
  }

  const { target, key, jobs, presets } = data;

  return (
    <div className="p-6 bg-hax-bg text-hax-text font-mono min-h-full">
      <div className="flex items-center gap-4 mb-4 flex-wrap">
        <div className="text-xs uppercase tracking-[0.4em] text-hax-accent-bright">
          ▎vulnbox
        </div>
        {target.host && (
          <div className="text-[10px] tracking-[0.2em] text-hax-dim">
            {target.user}@{target.host}:{target.port} · {target.services_path}
          </div>
        )}
      </div>

      {!canOperate && (
        <div className="mb-4 max-w-3xl text-[10px] uppercase tracking-wider text-hax-warning border border-hax-warning/40 bg-hax-warning/5 px-3 py-2 rounded-sm normal-case">
          ⚠ read-only — your role is <span className="font-bold">{role ?? "?"}</span>;
          running jobs requires <span className="font-bold">operator</span>, keys
          and /config changes require <span className="font-bold">admin</span>.
        </div>
      )}

      {target.error && (
        <div className="mb-4 max-w-3xl text-xs text-hax-warning border border-hax-warning/40 bg-hax-warning/5 px-3 py-2 rounded-sm">
          ⚠ {target.error} —{" "}
          <Link to="/config" className="underline text-hax-accent-bright">
            open /config
          </Link>
        </div>
      )}

      {jobError && (
        <div className="mb-4 max-w-3xl">
          <ErrorLine text={jobError} />
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <KeyCard status={key} canAdmin={canAdmin} busy={busy} />
        <PreflightCard
          job={activeOr(jobs.current, "preflight", jobs.last.preflight)}
          presets={presets}
          canOperate={canOperate}
          canAdmin={canAdmin}
          busy={busy}
          onRun={() => run("preflight")}
        />
        <ReconCard
          job={activeOr(jobs.current, "recon", jobs.last.recon)}
          servicePorts={target.service_ports}
          canOperate={canOperate}
          canAdmin={canAdmin}
          busy={busy}
          onRun={() => run("recon")}
        />
        <BackupCard
          job={activeOr(jobs.current, "backup", jobs.last.backup)}
          canOperate={canOperate}
          busy={busy}
          onRun={() => run("backup")}
        />
      </div>
    </div>
  );
}

/** A card shows its own job while it runs, otherwise its last result. */
function activeOr<R>(
  current: Job<unknown> | null,
  kind: JobKind,
  last: Job<R> | undefined
): Job<R> | undefined {
  if (current && current.kind === kind && current.state === "running") {
    return current as Job<R>;
  }
  return last;
}
