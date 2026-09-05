import { FormEvent, useState } from "react";
import { useNavigate, Navigate } from "react-router-dom";
import { useCompleteSetupMutation, useGetSetupStatusQuery } from "../api";

/**
 * First-run wizard. Reachable only while zero accounts exist — once one does,
 * GET /setup/status flips to needs_setup:false and this page bounces to /login,
 * mirroring the backend's self-closing POST /setup.
 *
 * The account created here is always an admin: `viewer` (the default for every
 * later account) cannot reach /config or /audit, which would leave a fresh
 * install unusable.
 */
export function Setup() {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [completeSetup, { isLoading }] = useCompleteSetupMutation();
  const { data: status, isLoading: statusLoading } = useGetSetupStatusQuery();

  if (statusLoading) {
    return (
      <div className="min-h-screen bg-hax-bg text-hax-muted flex items-center justify-center font-mono text-xs uppercase tracking-[0.3em]">
        <span className="text-hax-accent-bright">$</span>&nbsp;checking install
        <span className="hax-cursor"></span>
      </div>
    );
  }
  if (status && !status.needs_setup) {
    return <Navigate to="/login" replace />;
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setErrorMsg(null);
    if (!username.trim() || !password) {
      setErrorMsg("username and password required");
      return;
    }
    if (password !== confirm) {
      setErrorMsg("passwords don't match");
      return;
    }
    try {
      await completeSetup({ username: username.trim(), password }).unwrap();
      // The API opens the session for us, so go straight in.
      navigate("/", { replace: true });
    } catch (err: any) {
      const detail = err?.data?.error;
      if (err?.status === 409) {
        setErrorMsg(detail ?? "setup already completed");
      } else if (err?.status === 429) {
        setErrorMsg("too many attempts; try again later");
      } else {
        setErrorMsg(detail ?? "could not create the account");
      }
    }
  }

  return (
    <div className="min-h-screen bg-hax-bg text-hax-text font-mono flex items-center justify-center p-6">
      <div className="w-full max-w-md flex flex-col items-center gap-8">
        <div className="flex flex-col items-center gap-3">
          <img
            src="/logo.png"
            alt="w4rya"
            className="h-20 w-20"
            style={{ filter: "drop-shadow(0 0 16px rgba(168, 85, 247, 0.65))" }}
          />
          <h1
            className="text-5xl font-bold tracking-[0.2em] text-hax-text"
            style={{ textShadow: "0 0 14px rgba(168, 85, 247, 0.55)" }}
          >
            W4RYA
          </h1>
          <p className="text-[10px] uppercase tracking-[0.4em] text-hax-accent-bright">
            &gt; first run — no accounts yet
          </p>
        </div>

        <form
          onSubmit={onSubmit}
          className="w-full bg-hax-surface border border-hax-border rounded-sm p-6 flex flex-col gap-4"
          style={{ boxShadow: "0 0 36px -16px rgba(168, 85, 247, 0.5)" }}
        >
          <div className="text-[10px] uppercase tracking-[0.25em] text-hax-muted border-b border-hax-border pb-2 mb-1">
            ▎create admin account
          </div>

          <p className="text-[11px] text-hax-muted leading-relaxed -mt-1">
            This install has no users. The account you create now gets the{" "}
            <span className="text-hax-accent-bright">admin</span> role and can add
            the rest of the team from the Users page.
          </p>

          <label className="flex flex-col gap-1.5">
            <span className="text-[10px] uppercase tracking-[0.2em] text-hax-muted">
              <span className="text-hax-accent-bright">$</span> user
            </span>
            <input
              type="text"
              autoComplete="username"
              autoFocus
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="text-sm"
              spellCheck={false}
            />
            <span className="text-[10px] text-hax-dim">letters, digits, - and _ (max 32)</span>
          </label>

          <label className="flex flex-col gap-1.5">
            <span className="text-[10px] uppercase tracking-[0.2em] text-hax-muted">
              <span className="text-hax-accent-bright">$</span> password
            </span>
            <input
              type="password"
              autoComplete="new-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="text-sm"
            />
            <span className="text-[10px] text-hax-dim">at least 8 characters</span>
          </label>

          <label className="flex flex-col gap-1.5">
            <span className="text-[10px] uppercase tracking-[0.2em] text-hax-muted">
              <span className="text-hax-accent-bright">$</span> confirm
            </span>
            <input
              type="password"
              autoComplete="new-password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              className="text-sm"
            />
          </label>

          {errorMsg && (
            <div className="text-xs text-hax-danger font-mono border border-hax-danger/40 bg-hax-danger/10 px-3 py-2 rounded-sm uppercase tracking-wider">
              ! {errorMsg}
            </div>
          )}

          <button
            type="submit"
            disabled={isLoading}
            className="hax-btn hax-btn-primary mt-2 py-2 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isLoading ? "creating…" : "create account →"}
          </button>
        </form>

        <div className="text-[10px] uppercase tracking-[0.3em] text-hax-dim text-center leading-relaxed">
          team-internal access only
          <br />
          <span className="text-hax-dim/70 tracking-[0.2em] normal-case">
            do not expose this instance to the internet
          </span>
        </div>
      </div>
    </div>
  );
}
