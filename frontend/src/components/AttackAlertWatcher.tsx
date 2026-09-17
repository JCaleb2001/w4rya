import { useEffect, useRef } from "react";
import { useGetAttacksQuery, useVisibilityAwarePolling } from "../api";
import { useAppDispatch } from "../store";
import { pushToast } from "../store/toasts";

const POLL_MS = 15000;

/**
 * Background watcher that polls the attack timeline for new Suricata
 * signature hits and dispatches a warning toast for each one we hadn't
 * seen before. Deliberately skips `flag_out` events — FlagLeakWatcher
 * already toasts those (danger) from the flow tag; toasting here too
 * would double-alert on the same flow.
 *
 * Mount once at the top of the protected app tree, next to FlagLeakWatcher.
 */
export function AttackAlertWatcher() {
  const dispatch = useAppDispatch();
  const seenRef = useRef<Set<string>>(new Set());
  const bootedRef = useRef<boolean>(false);

  const pollMs = useVisibilityAwarePolling(POLL_MS);
  const { data } = useGetAttacksQuery(
    { limit: 100 },
    { pollingInterval: pollMs, refetchOnMountOrArgChange: true }
  );

  useEffect(() => {
    if (!data) return;
    const events = data.events.filter((e) => e.type !== "flag_out");

    // First successful load: prime the seen-set without firing toasts for
    // historical alerts. We only want to alert on hits from now onwards.
    if (!bootedRef.current) {
      seenRef.current = new Set(events.map((e) => e.flow_id));
      bootedRef.current = true;
      return;
    }

    for (const event of events) {
      if (seenRef.current.has(event.flow_id)) continue;
      const names = event.rules.map((r) => r.message).filter(Boolean);
      const label = names.length > 0 ? names.join(", ") : "suricata alert";
      dispatch(
        pushToast({
          message: `${label} — ${event.src_ip} → ${event.dst_ip}:${event.dst_port} (${event.service})`,
          severity: "warning",
          ttl_ms: 12000,
          href: `/flow/${event.flow_id}`,
          href_label: "inspect flow →",
        })
      );
    }
    // Replace rather than accumulate: an event that scrolls out of this
    // polled window is older than every event still in it, so it can never
    // reappear later — remembering it forever would just leak memory over
    // a multi-hour session.
    seenRef.current = new Set(events.map((e) => e.flow_id));
  }, [data, dispatch]);

  return null;
}
