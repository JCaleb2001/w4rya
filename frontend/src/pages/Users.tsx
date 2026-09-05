import { FormEvent, useState } from "react";
import {
  Role,
  UserAccount,
  hasRole,
  useCreateUserMutation,
  useDeleteUserMutation,
  useGetMeQuery,
  useGetUsersQuery,
  useSetUserPasswordMutation,
  useSetUserRoleMutation,
} from "../api";

const ROLES: Role[] = ["viewer", "operator", "admin"];

const ROLE_HINT: Record<Role, string> = {
  viewer: "read-only: browse flows, read notes",
  operator: "+ suricata rules, block IP, star, replay exploits",
  admin: "+ config, audit log, user management",
};

/**
 * Admin-only account management. The backend is the enforcement boundary
 * (403 with {required_role, your_role}); everything here is UX so nobody
 * clicks into an error.
 */
export function Users() {
  const { data: me } = useGetMeQuery();
  const allowed = hasRole(me?.role, "admin");

  const { data: users, isLoading } = useGetUsersQuery(undefined, { skip: !allowed });
  const [createUser, { isLoading: creating }] = useCreateUserMutation();
  const [deleteUser] = useDeleteUserMutation();
  const [setUserRole] = useSetUserRoleMutation();
  const [setUserPassword] = useSetUserPasswordMutation();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("viewer");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [okMsg, setOkMsg] = useState<string | null>(null);

  if (!allowed) {
    return (
      <div className="p-6 bg-hax-bg text-hax-text font-mono min-h-full text-hax-danger text-xs uppercase tracking-wider">
        ▎access denied — admin only.{" "}
        <span className="text-hax-muted normal-case tracking-normal">
          your role: {me?.role ?? "unknown"}
        </span>
      </div>
    );
  }

  function report(err: any, fallback: string) {
    setOkMsg(null);
    setErrorMsg(err?.data?.error ?? fallback);
  }

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    setErrorMsg(null);
    setOkMsg(null);
    try {
      const created = await createUser({
        username: username.trim(),
        password,
        role,
      }).unwrap();
      setOkMsg(`created ${created.username} (${created.role})`);
      setUsername("");
      setPassword("");
      setRole("viewer");
    } catch (err: any) {
      report(err, "could not create the account");
    }
  }

  async function onDelete(u: UserAccount) {
    if (!window.confirm(`delete user "${u.username}"? this cannot be undone.`)) return;
    setErrorMsg(null);
    setOkMsg(null);
    try {
      await deleteUser(u.username).unwrap();
      setOkMsg(`deleted ${u.username}`);
    } catch (err: any) {
      report(err, "could not delete the account");
    }
  }

  async function onRoleChange(u: UserAccount, next: Role) {
    if (next === u.role) return;
    setErrorMsg(null);
    setOkMsg(null);
    try {
      await setUserRole({ username: u.username, role: next }).unwrap();
      setOkMsg(`${u.username} is now ${next}`);
    } catch (err: any) {
      report(err, "could not change the role");
    }
  }

  async function onResetPassword(u: UserAccount) {
    const next = window.prompt(`new password for "${u.username}" (min 8 chars):`);
    if (next === null) return;
    setErrorMsg(null);
    setOkMsg(null);
    try {
      await setUserPassword({ username: u.username, password: next }).unwrap();
      setOkMsg(`password rotated for ${u.username}`);
    } catch (err: any) {
      report(err, "could not rotate the password");
    }
  }

  return (
    <div className="p-6 bg-hax-bg text-hax-text font-mono min-h-full">
      <div className="flex items-center gap-4 mb-4 flex-wrap">
        <div className="text-xs uppercase tracking-[0.4em] text-hax-accent-bright">
          ▎users
        </div>
        <div className="text-[10px] uppercase tracking-[0.2em] text-hax-dim">
          {users ? `${users.length} account(s)` : ""}
        </div>
      </div>

      {errorMsg && (
        <div className="mb-4 text-xs text-hax-danger border border-hax-danger/40 bg-hax-danger/10 px-3 py-2 rounded-sm uppercase tracking-wider">
          ! {errorMsg}
        </div>
      )}
      {okMsg && (
        <div className="mb-4 text-xs text-hax-accent-bright border border-hax-border bg-hax-surface px-3 py-2 rounded-sm uppercase tracking-wider">
          ✓ {okMsg}
        </div>
      )}

      <form
        onSubmit={onCreate}
        className="bg-hax-surface border border-hax-border rounded-sm p-4 mb-6 flex flex-wrap gap-4 items-end"
      >
        <div className="text-[10px] uppercase tracking-[0.25em] text-hax-muted w-full border-b border-hax-border pb-2">
          ▎add account
        </div>

        <label className="flex flex-col gap-1.5">
          <span className="text-[10px] uppercase tracking-[0.2em] text-hax-muted">user</span>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="text-sm"
            spellCheck={false}
            autoComplete="off"
          />
        </label>

        <label className="flex flex-col gap-1.5">
          <span className="text-[10px] uppercase tracking-[0.2em] text-hax-muted">password</span>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="text-sm"
            autoComplete="new-password"
          />
        </label>

        <label className="flex flex-col gap-1.5">
          <span className="text-[10px] uppercase tracking-[0.2em] text-hax-muted">role</span>
          <select
            value={role}
            onChange={(e) => setRole(e.target.value as Role)}
            className="text-sm"
          >
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
        </label>

        <button
          type="submit"
          disabled={creating}
          className="hax-btn hax-btn-primary py-2 px-4 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {creating ? "creating…" : "add →"}
        </button>

        <div className="text-[10px] text-hax-dim w-full">{ROLE_HINT[role]}</div>
      </form>

      {isLoading && (
        <div className="text-xs text-hax-muted uppercase tracking-[0.3em]">loading…</div>
      )}

      <table className="w-full text-sm border border-hax-border">
        <thead>
          <tr className="bg-hax-surface text-[10px] uppercase tracking-[0.2em] text-hax-muted">
            <th className="text-left px-3 py-2 border-b border-hax-border">user</th>
            <th className="text-left px-3 py-2 border-b border-hax-border">role</th>
            <th className="text-right px-3 py-2 border-b border-hax-border">actions</th>
          </tr>
        </thead>
        <tbody>
          {(users ?? []).map((u) => {
            const isSelf = u.username === me?.user;
            return (
              <tr key={u.username} className="border-b border-hax-border/50">
                <td className="px-3 py-2">
                  {u.username}
                  {isSelf && (
                    <span className="ml-2 text-[10px] uppercase tracking-[0.2em] text-hax-dim">
                      you
                    </span>
                  )}
                </td>
                <td className="px-3 py-2">
                  <select
                    value={u.role}
                    onChange={(e) => onRoleChange(u, e.target.value as Role)}
                    className="text-xs"
                  >
                    {ROLES.map((r) => (
                      <option key={r} value={r}>
                        {r}
                      </option>
                    ))}
                  </select>
                </td>
                <td className="px-3 py-2 text-right whitespace-nowrap">
                  <button
                    type="button"
                    onClick={() => onResetPassword(u)}
                    className="hax-btn py-1 px-2 text-xs mr-2"
                  >
                    reset password
                  </button>
                  <button
                    type="button"
                    onClick={() => onDelete(u)}
                    disabled={isSelf}
                    title={isSelf ? "you cannot delete the account you are signed in as" : undefined}
                    className="hax-btn py-1 px-2 text-xs disabled:opacity-40 disabled:cursor-not-allowed"
                  >
                    delete
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>

      <p className="mt-4 text-[10px] text-hax-dim leading-relaxed">
        The last admin cannot be deleted or demoted — that would lock everyone out
        of /config and /audit. Passwords are stored as bcrypt hashes in
        auth/users.yaml; the CLI escape hatch is still{" "}
        <code className="text-hax-muted">
          docker compose run --rm api python /app/auth/add_user.py &lt;name&gt; --role admin
        </code>
        .
      </p>
    </div>
  );
}
