import { FormEvent, useState } from "react";
import { useNavigate, Navigate } from "react-router-dom";
import { useGetMeQuery, useLoginMutation } from "../api";

export function Login() {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [login, { isLoading }] = useLoginMutation();

  // If we're already authenticated, bounce to the home page.
  const { data: me } = useGetMeQuery();
  if (me?.user) {
    return <Navigate to="/" replace />;
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setErrorMsg(null);
    if (!username.trim() || !password) {
      setErrorMsg("username and password required");
      return;
    }
    try {
      await login({ username: username.trim(), password }).unwrap();
      navigate("/", { replace: true });
    } catch (err: any) {
      const status = err?.status;
      if (status === 401) setErrorMsg("invalid credentials");
      else if (status === 400) setErrorMsg("username and password required");
      else setErrorMsg("authentication failed");
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
            &gt; authentication required
          </p>
        </div>

        <form
          onSubmit={onSubmit}
          className="w-full bg-hax-surface border border-hax-border rounded-sm p-6 flex flex-col gap-4"
          style={{ boxShadow: "0 0 36px -16px rgba(168, 85, 247, 0.5)" }}
        >
          <div className="text-[10px] uppercase tracking-[0.25em] text-hax-muted border-b border-hax-border pb-2 mb-1">
            ▎secure shell
          </div>

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
          </label>

          <label className="flex flex-col gap-1.5">
            <span className="text-[10px] uppercase tracking-[0.2em] text-hax-muted">
              <span className="text-hax-accent-bright">$</span> password
            </span>
            <input
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
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
            {isLoading ? "authenticating…" : "authenticate →"}
          </button>
        </form>

        <div className="text-[10px] uppercase tracking-[0.3em] text-hax-dim">
          v0.1.0 // team-internal access only
        </div>
      </div>
    </div>
  );
}
