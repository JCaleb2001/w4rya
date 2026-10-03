import { useState } from "react";
import { useImportVulnboxServicesMutation } from "../api";
import { Job, ReconResult } from "../types";
import { BTN, BTN_PRIMARY, Card, ErrorLine, JobLine, OkLine, errorText } from "./Card";

/**
 * Step 3 — which services run on the vulnbox and on which ports. Service
 * ports (the configured vulnbox_service_ports ranges — the ports other teams
 * reach) can be imported into /config → services in one click; nothing
 * already there is deleted.
 */
export function ReconCard({
  job,
  servicePorts,
  canOperate,
  canAdmin,
  busy,
  onRun,
}: {
  job?: Job<ReconResult>;
  /** The vulnbox_service_ports setting; "" = every published port. */
  servicePorts: string;
  canOperate: boolean;
  canAdmin: boolean;
  busy: boolean;
  onRun: () => void;
}) {
  const [importServices, { isLoading: importing }] = useImportVulnboxServicesMutation();
  const [error, setError] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);

  const result = job?.state === "done" ? job.result : null;
  const importable = (result?.services ?? []).some((s) => s.service_ports.length > 0);

  async function onImport() {
    setError(null);
    setOk(null);
    try {
      const res = await importServices().unwrap();
      setOk(`imported into /config: ${res.added} added, ${res.updated} updated`);
    } catch (err) {
      setError(errorText(err, "could not import the services"));
    }
  }

  return (
    <Card step={3} title="recon" when="at game start">
      <p className="text-[10px] text-hax-dim leading-relaxed">
        Service ports:{" "}
        <span className="text-hax-muted">
          {servicePorts || "every published port"}
        </span>{" "}
        (vulnbox_service_ports in /config).
      </p>

      <div className="flex flex-wrap items-center gap-2">
        <button
          onClick={onRun}
          disabled={!canOperate || busy}
          title={!canOperate ? "requires operator role" : busy ? "a job is running" : undefined}
          className={BTN_PRIMARY}
        >
          run recon →
        </button>
        <button
          onClick={onImport}
          disabled={!canAdmin || !importable || importing}
          title={
            !canAdmin
              ? "requires admin role"
              : !importable
              ? "run recon first — needs a published service port"
              : undefined
          }
          className={BTN}
        >
          {importing ? "importing…" : "import into /config"}
        </button>
        <JobLine job={job} />
      </div>

      {result && result.services.length === 0 && (
        <div className="text-xs text-hax-dim">no service directories found</div>
      )}

      {result && result.services.length > 0 && (
        <table className="w-full text-xs">
          <thead>
            <tr className="text-hax-muted uppercase tracking-wider text-[10px]">
              <th className="text-left py-1 pr-2">service</th>
              <th className="text-left py-1 pr-2">service ports</th>
              <th className="text-left py-1 pr-2">other ports</th>
              <th className="text-right py-1">containers</th>
            </tr>
          </thead>
          <tbody>
            {result.services.map((s) => {
              const other = s.ports.filter((p) => !s.service_ports.includes(p));
              return (
                <tr key={s.name} className="border-t border-hax-border">
                  <td className="py-1 pr-2 text-hax-text">{s.name}</td>
                  <td className="py-1 pr-2 text-hax-accent-bright">
                    {s.service_ports.join(", ") || "—"}
                  </td>
                  <td className="py-1 pr-2 text-hax-muted">{other.join(", ") || "—"}</td>
                  <td
                    className="py-1 text-right text-hax-muted"
                    title={s.containers.map((c) => `${c.name} (${c.image})`).join("\n")}
                  >
                    {s.containers.length}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}

      {result && result.notes.length > 0 && (
        <ul className="text-[10px] text-hax-dim list-disc pl-4">
          {result.notes.map((n) => (
            <li key={n}>{n}</li>
          ))}
        </ul>
      )}

      {error && <ErrorLine text={error} />}
      {ok && <OkLine text={ok} />}
    </Card>
  );
}
