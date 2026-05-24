import { useEffect } from "react";
import { Link } from "react-router-dom";
import { useAppDispatch, useAppSelector } from "../store";
import { dismissToast, Toast, ToastSeverity } from "../store/toasts";

const SEVERITY_STYLE: Record<ToastSeverity, string> = {
  info: "border-hax-accent/40 text-hax-accent-bright bg-hax-accent/10",
  success: "border-hax-success/40 text-hax-success bg-hax-success/10",
  warning: "border-hax-warning/40 text-hax-warning bg-hax-warning/10",
  danger: "border-hax-danger/60 text-red-300 bg-hax-danger/15",
};

const SEVERITY_GLYPH: Record<ToastSeverity, string> = {
  info: "▎",
  success: "✓",
  warning: "⚠",
  danger: "!",
};

export function Toasts() {
  const items = useAppSelector((s) => s.toasts.items);
  return (
    <div className="fixed bottom-4 right-4 z-[300] flex flex-col gap-2 max-w-md font-mono pointer-events-none">
      {items.map((t) => (
        <ToastItem key={t.id} toast={t} />
      ))}
    </div>
  );
}

function ToastItem({ toast }: { toast: Toast }) {
  const dispatch = useAppDispatch();

  useEffect(() => {
    const handle = window.setTimeout(
      () => dispatch(dismissToast(toast.id)),
      toast.ttl_ms
    );
    return () => window.clearTimeout(handle);
  }, [toast.id, toast.ttl_ms, dispatch]);

  const cls = SEVERITY_STYLE[toast.severity];
  const glyph = SEVERITY_GLYPH[toast.severity];

  return (
    <div
      className={`pointer-events-auto px-3 py-2 border rounded-sm text-xs ${cls} shadow-[0_0_24px_-12px_rgba(168,85,247,0.5)]`}
      style={{ minWidth: 280, animation: "hax-toast-in 200ms ease-out" }}
    >
      <div className="flex items-start gap-2">
        <div className="uppercase tracking-wider font-bold">{glyph}</div>
        <div className="flex-1">
          <div className="whitespace-pre-wrap break-words">{toast.message}</div>
          {toast.href && (
            <Link
              to={toast.href}
              onClick={() => dispatch(dismissToast(toast.id))}
              className="inline-block mt-1 underline text-hax-accent-bright text-[11px]"
            >
              {toast.href_label ?? "open →"}
            </Link>
          )}
        </div>
        <button
          onClick={() => dispatch(dismissToast(toast.id))}
          className="text-hax-muted hover:text-hax-text text-[10px] uppercase tracking-wider"
          title="dismiss"
        >
          ✕
        </button>
      </div>
    </div>
  );
}
