import { useState } from "react";
import { API_BASE_PATH } from "../../../const";
import { useCopy } from "../../../hooks/useCopy";
import {
  PRIVATE_KEY_PATH,
  useForgetVulnboxHostKeyMutation,
  useGenerateVulnboxKeyMutation,
} from "../api";
import { KeyStatus } from "../types";
import { BTN, BTN_PRIMARY, Card, ErrorLine, OkLine, errorText } from "./Card";

/**
 * Step 1 — the key the A/D platform installs on the vulnbox.
 * Only the public half is ever rendered: A/D games may record or share
 * screens, so the private half is a file download and nothing else.
 */
export function KeyCard({
  status,
  canAdmin,
  busy,
}: {
  status: KeyStatus;
  canAdmin: boolean;
  /** A job is running — key changes would break it mid-flight. */
  busy: boolean;
}) {
  const [generate, { isLoading: generating }] = useGenerateVulnboxKeyMutation();
  const [forget, { isLoading: forgetting }] = useForgetVulnboxHostKeyMutation();
  const [error, setError] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);
  const { statusText, copy } = useCopy({
    getText: async () => status.public_key ?? "",
  });

  async function run(action: () => Promise<unknown>, done: string, fallback: string) {
    setError(null);
    setOk(null);
    try {
      await action();
      setOk(done);
    } catch (err) {
      setError(errorText(err, fallback));
    }
  }

  function onRotate() {
    if (
      !window.confirm(
        "rotate the key? the key already on the vulnbox stops working: submit " +
          "the new public key to the platform and restart the box with it."
      )
    )
      return;
    run(() => generate({ rotate: true }).unwrap(), "new key generated", "could not rotate the key");
  }

  function onForget() {
    if (
      !window.confirm(
        "forget the pinned vulnbox host key? only do this if the box was " +
          "re-provisioned — the next connection trusts whatever key it presents."
      )
    )
      return;
    run(() => forget().unwrap(), "host key forgotten", "could not forget the host key");
  }

  return (
    <Card step={1} title="ssh key" when="before the game">
      <p className="text-[10px] text-hax-dim leading-relaxed">
        Submit the public key to the A/D platform; the vulnbox is provisioned
        with the keys submitted before the game.
      </p>

      {!status.exists && (
        <button
          onClick={() => run(() => generate({ rotate: false }).unwrap(), "key generated", "could not generate a key")}
          disabled={!canAdmin || generating}
          title={!canAdmin ? "requires admin role" : undefined}
          className={`${BTN_PRIMARY} self-start`}
        >
          {generating ? "generating…" : "generate key →"}
        </button>
      )}

      {status.exists && (
        <>
          <label className="flex flex-col gap-1">
            <span className="text-[10px] uppercase tracking-[0.2em] text-hax-muted">
              <span className="text-hax-accent-bright">$</span> public key
            </span>
            <textarea
              readOnly
              value={status.public_key ?? ""}
              rows={3}
              className="text-xs w-full resize-none break-all"
              spellCheck={false}
              onFocus={(e) => e.currentTarget.select()}
            />
          </label>
          <div className="text-[10px] text-hax-dim break-all">
            {status.fingerprint ?? "fingerprint unavailable"}
            {status.created_at && <> · created {new Date(status.created_at).toLocaleString()}</>}
          </div>
          <div className="flex flex-wrap gap-2">
            <button onClick={copy} className={BTN_PRIMARY}>
              {statusText === "Copy" ? "copy public key" : statusText.toLowerCase()}
            </button>
            {canAdmin && (
              <a
                href={`${API_BASE_PATH}${PRIVATE_KEY_PATH}`}
                className={BTN}
                title="download only — never shown on screen"
              >
                ↓ private key
              </a>
            )}
            <button
              onClick={onRotate}
              disabled={!canAdmin || busy || generating}
              title={!canAdmin ? "requires admin role" : busy ? "a job is running" : undefined}
              className={BTN}
            >
              rotate
            </button>
            <button
              onClick={onForget}
              disabled={!canAdmin || busy || forgetting}
              title={!canAdmin ? "requires admin role" : busy ? "a job is running" : undefined}
              className={BTN}
            >
              forget host key
            </button>
          </div>
        </>
      )}

      {error && <ErrorLine text={error} />}
      {ok && <OkLine text={ok} />}
    </Card>
  );
}
