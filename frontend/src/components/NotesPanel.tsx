import { useState } from "react";
import {
  Note,
  useAddNoteMutation,
  useDeleteNoteMutation,
  useGetMeQuery,
  useGetNotesQuery,
} from "../api";

export function NotesPanel({ flowId }: { flowId: string }) {
  const { data: notes, isLoading } = useGetNotesQuery(flowId);
  const { data: me } = useGetMeQuery();
  const [add, { isLoading: posting, error }] = useAddNoteMutation();
  const [del] = useDeleteNoteMutation();
  const [body, setBody] = useState("");

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!body.trim()) return;
    try {
      await add({ flow_id: flowId, body }).unwrap();
      setBody("");
    } catch {}
  }

  return (
    <div
      className="bg-hax-surface border-l-4 border-hax-accent-deep/60 p-3 m-3 rounded-sm"
      style={{ boxShadow: "0 0 14px -10px rgba(168,85,247,0.35)" }}
    >
      <div className="flex items-center text-xs uppercase tracking-[0.25em] text-hax-accent-bright font-bold mb-2">
        ▎notes
        <span className="ml-2 text-[10px] text-hax-dim normal-case tracking-normal">
          team-visible scratch pad
        </span>
        {notes && (
          <span className="ml-auto text-[10px] text-hax-muted normal-case tracking-normal">
            {notes.length} note{notes.length === 1 ? "" : "s"}
          </span>
        )}
      </div>

      {isLoading && (
        <div className="text-hax-dim text-xs">loading…</div>
      )}

      {notes && notes.length > 0 && (
        <ul className="flex flex-col gap-2 mb-3">
          {notes.map((n) => (
            <NoteItem
              key={n.id}
              note={n}
              meCanDelete={!!me?.user && me.user === n.author}
              onDelete={() => del({ id: n.id, flow_id: flowId })}
            />
          ))}
        </ul>
      )}

      <form onSubmit={onSubmit} className="flex flex-col gap-2">
        <textarea
          value={body}
          onChange={(e) => setBody(e.target.value)}
          placeholder="add a note (visible to the team)…"
          rows={2}
          spellCheck={false}
          className="text-xs font-mono"
          maxLength={10_000}
        />
        {error && (
          <div className="text-xs text-hax-danger">
            ! {String((error as any)?.data?.error ?? "post failed")}
          </div>
        )}
        <button
          type="submit"
          disabled={posting || !body.trim()}
          className="hax-btn hax-btn-primary self-start disabled:opacity-50"
        >
          {posting ? "posting…" : "post note →"}
        </button>
      </form>
    </div>
  );
}

function NoteItem({
  note,
  meCanDelete,
  onDelete,
}: {
  note: Note;
  meCanDelete: boolean;
  onDelete: () => void;
}) {
  const when = new Date(note.created_at);
  const whenStr = isNaN(when.getTime())
    ? note.created_at
    : when.toLocaleString();
  return (
    <li className="bg-hax-bg border border-hax-border rounded-sm p-2 text-xs font-mono">
      <div className="flex items-baseline text-[10px] uppercase tracking-wider mb-1">
        <span className="text-hax-accent-bright">@{note.author}</span>
        <span className="ml-2 text-hax-dim">{whenStr}</span>
        {meCanDelete && (
          <button
            onClick={onDelete}
            className="ml-auto text-hax-danger hover:hax-glow"
            title="delete (only your own notes)"
          >
            ✕
          </button>
        )}
      </div>
      <div className="text-hax-text whitespace-pre-wrap break-words">
        {note.body}
      </div>
    </li>
  );
}
