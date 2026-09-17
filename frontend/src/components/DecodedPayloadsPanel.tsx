import { useState } from "react";
import { useGetFlowDecodedQuery, DecodedItem, DecodedLayer } from "../api";

/**
 * Shows anything decode.py's auto_decode()/find_embedded_encodings() found
 * in this flow's raw items — base64/hex/url/gzip/deflate, recursively.
 * Renders nothing when there's nothing decodable, so a flow with plain-text
 * traffic doesn't grow an empty panel.
 */
export function DecodedPayloadsPanel({ flowId }: { flowId: string }) {
  const { data, isLoading } = useGetFlowDecodedQuery(flowId);
  if (isLoading || !data || data.items.length === 0) return null;

  return (
    <div className="border border-hax-accent-deep/40 bg-hax-surface/60 rounded-sm px-3 py-2 my-2 font-mono">
      <div className="text-[10px] uppercase tracking-[0.25em] text-hax-muted mb-2">
        ▎decoded payloads ({data.items.length} item{data.items.length === 1 ? "" : "s"})
      </div>
      <div className="flex flex-col gap-2">
        {data.items.map((item) => (
          <DecodedItemBlock key={item.item_index} item={item} />
        ))}
      </div>
    </div>
  );
}

function DecodedItemBlock({ item }: { item: DecodedItem }) {
  const [open, setOpen] = useState(true);
  const count = item.whole.length + item.embedded.length;
  return (
    <div className="border border-hax-border rounded-sm">
      <button
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center gap-2 px-2 py-1 text-[10px] uppercase tracking-wider text-hax-muted hover:bg-hax-elev"
      >
        <span>{open ? "▾" : "▸"}</span>
        <span className={item.direction === "c" ? "text-hax-accent-bright" : "text-hax-text"}>
          item #{item.item_index} ({item.direction === "c" ? "client→server" : "server→client"})
        </span>
        <span className="text-hax-dim">{item.raw_size}B</span>
        <span className="ml-auto text-hax-dim">{count} decode{count === 1 ? "" : "s"}</span>
      </button>
      {open && (
        <div className="px-2 py-2 flex flex-col gap-2">
          {item.whole.length > 0 && <LayerChain label="whole payload" layers={item.whole} />}
          {item.embedded.map((e, i) => (
            <div key={i}>
              <div className="text-[9px] text-hax-dim mb-1">
                embedded @offset {e.offset}: <code className="text-hax-muted">{e.match.slice(0, 60)}{e.match.length > 60 ? "…" : ""}</code>
              </div>
              <LayerChain label="decoded" layers={e.layers} />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function LayerChain({ label, layers }: { label: string; layers: DecodedLayer[] }) {
  return (
    <div>
      <div className="text-[9px] uppercase tracking-wider text-hax-dim mb-1">
        {label}: {layers.map((l) => l.encoding).join(" → ")}
      </div>
      <pre className="text-xs text-hax-text bg-hax-bg p-2 rounded-sm border border-hax-border overflow-auto max-h-48 whitespace-pre-wrap">
        {layers[layers.length - 1].preview}
        {layers[layers.length - 1].truncated && (
          <span className="text-hax-dim"> …(truncated)</span>
        )}
      </pre>
    </div>
  );
}
