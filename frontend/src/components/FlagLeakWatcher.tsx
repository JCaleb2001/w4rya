import { useEffect, useRef } from "react";
import { useGetFlowsQuery } from "../api";
import { useAppDispatch } from "../store";
import { pushToast } from "../store/toasts";

const POLL_MS = 15000;
const FLAG_OUT_TAG = "flag-out";

/**
 * Background watcher that polls for new `flag-out` flows (= enemy stole a
 * flag from us) and dispatches a danger toast for each one we hadn't seen
 * before. Mount once at the top of the protected app tree.
 */
export function FlagLeakWatcher() {
  const dispatch = useAppDispatch();
  const seenRef = useRef<Set<string>>(new Set());
  const bootedRef = useRef<boolean>(false);

  const { data } = useGetFlowsQuery(
    { tags_include: [FLAG_OUT_TAG] },
    { pollingInterval: POLL_MS, refetchOnMountOrArgChange: true }
  );

  useEffect(() => {
    if (!data) return;

    // First successful load: prime the seen-set without firing toasts for
    // historical leaks. We only want to alert on flags that leak from now
    // onwards.
    if (!bootedRef.current) {
      data.forEach((f) => seenRef.current.add(f.id));
      bootedRef.current = true;
      return;
    }

    for (const flow of data) {
      if (seenRef.current.has(flow.id)) continue;
      seenRef.current.add(flow.id);
      const port = flow.dst_port;
      dispatch(
        pushToast({
          message: `flag leaked: ${flow.src_ip} → ${flow.dst_ip}:${port}`,
          severity: "danger",
          ttl_ms: 12000,
          href: `/flow/${flow.id}`,
          href_label: "inspect flow →",
        })
      );
    }
  }, [data, dispatch]);

  return null;
}
