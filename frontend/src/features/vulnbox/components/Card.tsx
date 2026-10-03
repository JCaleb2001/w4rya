import { ReactNode } from "react";
import { Job } from "../types";

/** Shared frame for the four vulnbox cards — same surface/border/header
 *  treatment as the Config page's panels. */
export function Card({
  step,
  title,
  when,
  children,
}: {
  step: number;
  title: string;
  /** Which phase of a game this card belongs to, e.g. "before the game". */
  when: string;
  children: ReactNode;
}) {
  return (
    <section className="bg-hax-surface border border-hax-border rounded-sm p-5 flex flex-col gap-3 min-w-0">
      <div className="flex items-baseline gap-3 border-b border-hax-border pb-2">
        <span className="text-xs uppercase tracking-[0.25em] text-hax-muted">
          ▎{step} · {title}
        </span>
        <span className="ml-auto text-[10px] uppercase tracking-[0.2em] text-hax-dim">
          {when}
        </span>
      </div>
      {children}
    </section>
  );
}

/** One line describing a job: running / finished / failed, by whom, when. */
export function JobLine({ job }: { job?: Job<unknown> }) {
  if (!job) {
    return <div className="text-[10px] text-hax-dim">never run</div>;
  }
  const when = new Date(job.finished_at ?? job.started_at).toLocaleTimeString();
  if (job.state === "running") {
    return (
      <div className="text-[10px] uppercase tracking-wider text-hax-accent-bright">
        <span className="text-hax-accent-bright">$</span> running — started by{" "}
        {job.started_by}
        <span className="hax-cursor"></span>
      </div>
    );
  }
  if (job.state === "error") {
    return <ErrorLine text={job.error ?? "failed"} />;
  }
  return (
    <div className="text-[10px] text-hax-dim">
      last run {when} by {job.started_by}
    </div>
  );
}

export function ErrorLine({ text }: { text: string }) {
  return (
    <div className="text-xs text-hax-danger border border-hax-danger/40 bg-hax-danger/10 px-3 py-2 rounded-sm">
      ! {text}
    </div>
  );
}

export function OkLine({ text }: { text: string }) {
  return (
    <div className="text-xs text-hax-success border border-hax-success/40 bg-hax-success/10 px-3 py-2 rounded-sm">
      ✓ {text}
    </div>
  );
}

/** Pull the backend's `{error}` message out of an RTK Query error. */
export function errorText(err: any, fallback: string): string {
  return err?.data?.error ?? fallback;
}

export const BTN = "hax-btn disabled:opacity-40 disabled:cursor-not-allowed";
export const BTN_PRIMARY = `${BTN} hax-btn-primary`;
