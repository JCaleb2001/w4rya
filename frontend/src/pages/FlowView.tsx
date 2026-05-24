import { useSearchParams, Link, useParams, useNavigate } from "react-router-dom";
import React, { ChangeEvent, useDeferredValue, useEffect, useState } from "react";
import { useHotkeys } from "react-hotkeys-hook";
import { FlowData, FullFlow } from "../types";
import { Buffer } from "buffer";
import {
  TEXT_FILTER_KEY,
  MAX_LENGTH_FOR_HIGHLIGHT,
  API_BASE_PATH,
  REPR_ID_KEY,
  FIRST_DIFF_KEY,
  SECOND_DIFF_KEY,
} from "../const";
import {
  ArrowCircleLeftIcon,
  ArrowCircleRightIcon,
  ArrowCircleUpIcon,
  ArrowCircleDownIcon,
  DownloadIcon,
  LightningBoltIcon,
} from "@heroicons/react/solid";
import { format } from "date-fns";

import { hexy } from "hexy";
import { useCopy } from "../hooks/useCopy";
import { RadioGroup } from "../components/RadioGroup";
import { ExploitModal } from "../components/ExploitModal";
import { useBlockIpMutation } from "../api";
import {
  useGetFlowQuery,
  useGetServicesQuery,
  useLazyToFullPythonRequestQuery,
  useLazyToPwnToolsQuery,
  useToSinglePythonRequestQuery,
  useGetFlagRegexQuery,
} from "../api";
import { getTickStuff } from "../tick";
import escapeStringRegexp from "escape-string-regexp";

const SECONDARY_NAVBAR_HEIGHT = 50;

function CopyButton({ copyText }: { copyText?: string }) {
  const { statusText, copy, copyState } = useCopy({
    getText: async () => copyText ?? "",
  });
  return (
    <>
      {copyText && (
        <button
          className="p-2 text-xs uppercase tracking-wider text-hax-accent-bright hover:text-hax-accent hover:hax-glow font-mono"
          onClick={copy}
          disabled={!copyText}
        >
          {statusText}
        </button>
      )}
    </>
  );
}

function FlowContainer({
  copyText,
  children,
}: {
  copyText?: string;
  children: React.ReactNode;
}) {
  return (
    <div className=" pb-5 flex flex-col">
      <div className="ml-auto">
        <CopyButton copyText={copyText}></CopyButton>
      </div>
      <pre className="p-5 overflow-auto">{children}</pre>
    </div>
  );
}

function HexFlow({ flow }: { flow: FlowData }) {
  const hex = hexy(Buffer.from(flow.b64, "base64"), { format: "twos" });
  return <FlowContainer copyText={hex}>{hex}</FlowContainer>;
}
function highlightText(flowText: string, search_string: string, flag_string: string) {
  if (flowText.length > MAX_LENGTH_FOR_HIGHLIGHT || (flag_string === "" && search_string === "")) {
    return flowText
  }
  try {
    const searchClasses = "bg-hax-accent/30 text-hax-accent-bright rounded-sm px-0.5";
    const flagClasses = "bg-hax-danger/30 text-red-300 rounded-sm px-0.5 font-bold";

    // Matches are stored as `[start index, end index]`.
    // For some reason tsc compiler (during build) thinks that `x.index` can be undefined (no, it can't).
    // I wasn't able to find a workaround for it so @ts-ignore it is...
    // Other way would be `x.index ?? 0` but that seems like it is doing something more than fixing typescript issues.
    // @ts-ignore
    const flagMatches: [number, number][] = (
      flag_string === ""
        ? []
        // @ts-ignore
        : [...flowText.matchAll(new RegExp(flag_string, "g"))].map(x => [x.index, x.index + x[0].length])
    );
    // @ts-ignore
    const searchMatches: [number, number][] = (
      search_string === ""
        ? []
        // @ts-ignore
        : [...flowText.matchAll(new RegExp(search_string, "gi"))].map(x => [x.index, x.index + x[0].length])
    );

    let parts = [];
    let currentIndex = 0, flagMatchIndex = 0, searchMatchIndex = 0;
    while (true) {
      // Pick next match
      let isSearchMatch = null;
      if (flagMatchIndex < flagMatches.length && searchMatchIndex < searchMatches.length) {
        isSearchMatch = searchMatches[searchMatchIndex][0] <= flagMatches[flagMatchIndex][0];
      } else if (searchMatchIndex < searchMatches.length) {
        isSearchMatch = true;
      } else if (flagMatchIndex < flagMatches.length) {
        isSearchMatch = false;
      }
      let match = (
        isSearchMatch === null
          ? null
          : isSearchMatch ? searchMatches[searchMatchIndex] : flagMatches[flagMatchIndex]
      );

      // Produce element for remaining text if there is no match
      if (match === null) {
        parts.push(<span key={currentIndex}>{flowText.slice(currentIndex)}</span>);
        break;
      }

      // Produce element for part between previous and next/current match
      if (currentIndex != match[0]) {
        parts.push(<span key={currentIndex}>{flowText.slice(currentIndex, match[0])}</span>);
      }

      // Produce element for current match
      parts.push(<span key={match[0]} className={isSearchMatch ? searchClasses : flagClasses}>{flowText.slice(match[0], match[1])}</span>);

      // Advance position to end of match
      currentIndex = match[1];

      // Advance "pointers" for flag matches
      while (flagMatchIndex < flagMatches.length && flagMatches[flagMatchIndex][1] <= currentIndex) flagMatchIndex++;
      // If current match ends in the middle of next match, we cut that overlaping part out
      if (flagMatchIndex < flagMatches.length && flagMatches[flagMatchIndex][0] < currentIndex) flagMatches[flagMatchIndex][0] = currentIndex;
      // Do the same also for search matches
      while (searchMatchIndex < searchMatches.length && searchMatches[searchMatchIndex][1] <= currentIndex) searchMatchIndex++;
      if (searchMatchIndex < searchMatches.length && searchMatches[searchMatchIndex][0] < currentIndex) searchMatches[searchMatchIndex][0] = currentIndex;
    }

    return <span>{parts}</span>;
  } catch (error) {
    console.log(error);
    return flowText;
  }
}

function TextFlow({ flow }: { flow: FlowData }) {
  let [searchParams] = useSearchParams();
  const text_filter = searchParams.get(TEXT_FILTER_KEY);
  const { data: flag_regex } = useGetFlagRegexQuery();
  const text = highlightText(flow.data, text_filter ?? "", flag_regex ?? "");

  return <FlowContainer copyText={flow.data}>{text}</FlowContainer>;
}

function WebFlow({ flow }: { flow: FlowData }) {
  const data = flow.data;
  const [header, ...rest] = data.split("\r\n\r\n");
  const http_content = rest.join("\r\n\r\n");

  const Hack = "iframe" as any;
  return (
    <FlowContainer>
      <pre>{header}</pre>
      <div className="border border-hax-border rounded-sm bg-hax-surface">
        <Hack
          srcDoc={http_content}
          sandbox=""
          height={300}
          csp="default-src none" // there is a warning here but it actually works, not supported in firefox though :(
        ></Hack>
      </div>
    </FlowContainer>
  );
}

function PythonRequestFlow({
  full_flow,
  flow,
  item_index,
}: {
  full_flow: FullFlow;
  flow: FlowData;
  item_index: number,
}) {
  const { data } = useToSinglePythonRequestQuery({
    body: flow.b64,
    id: full_flow.id,
    item_index,
    tokenize: true,
  });

  return <FlowContainer copyText={data}>{data}</FlowContainer>;
}

interface FlowProps {
  full_flow: FullFlow;
  flow: FlowData;
  flow_item_index: number;
  delta_time: number;
  id: string;
}

function detectType(flow: FlowData) {
  const firstLine = flow.data.split("\n")[0];
  if (firstLine.includes("HTTP")) {
    return "Web";
  }

  return "Plain";
}

function getFlowBody(flow: FlowData, flowType: string) {
  if (flowType == "Web") {
    const contentType = flow.data.match(/Content-Type: ([^\s;]+)/im)?.[1];
    if (contentType) {
      const body = Buffer.from(flow.b64, "base64").subarray(flow.data.indexOf("\r\n\r\n") + 4);
      return [contentType, body]
    }
  }
  return null
}

function Flow({ full_flow, flow, flow_item_index, delta_time, id }: FlowProps) {
  const formatted_time = format(new Date(flow.time), "HH:mm:ss:SSS");
  const displayOptions = flow.from === "s"
    ? ["Plain", "Hex", "Web"]
    : ["Plain", "Hex", "PythonRequest"];

  // Basic type detection, currently unused
  const [displayOption, setDisplayOption] = useState("Plain");

  const flowType = detectType(flow);
  const flowBody = getFlowBody(flow, flowType);

  return (
    <div className="text-mono" id={id}>
      <div
        className="sticky shadow-md bg-hax-surface overflow-auto py-1 border-y border-hax-border"
        style={{ top: SECONDARY_NAVBAR_HEIGHT }}
      >
        <div className="flex items-center h-7 gap-2 px-2">
          <div className="w-6">
            {flow.from === "s" ? (
              <ArrowCircleLeftIcon className="fill-hax-success" />
            ) : (
              <ArrowCircleRightIcon className="fill-hax-danger" />
            )}
          </div>
          <div className="font-mono text-xs" style={{ width: 200 }}>
            <span className="text-hax-text">{formatted_time}</span>
            <span className="text-hax-muted pl-3">+{delta_time}ms</span>
          </div>
          <button
            className="hax-btn"
            onClick={async () => {
              window.open(
                "https://gchq.github.io/CyberChef/#input=" +
                encodeURIComponent(flow.b64)
              );
            }}
          >
            Open in CC
          </button>
          {flowType == "Web" && flowBody && (
            <button
              className="hax-btn"
              onClick={async () => {
                window.open(
                  "https://gchq.github.io/CyberChef/#input=" +
                  encodeURIComponent(flowBody[1].toString("base64"))
                );
              }}
            >
              Open body in CC
            </button>
          )}
          <button
            className="hax-btn"
            onClick={async () => {
              const blob = new Blob([Buffer.from(flow.b64, "base64")], {
                type: "application/octet-stream",
              });
              const url = window.URL.createObjectURL(blob);
              const a = document.createElement("a");
              a.style.display = "none";
              a.href = url;
              a.download = "w4rya-dl-" + id + ".dat";
              document.body.appendChild(a);
              a.click();
              window.URL.revokeObjectURL(url);
              a.remove();
            }}
          >
            Download
          </button>
          {flowType == "Web" && flowBody && (
            <button
              className="hax-btn"
              onClick={async () => {
                const blob = new Blob([flowBody[1]], {
                  type: flowBody[0].toString(),
                });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.style.display = "none";
                a.href = url;
                a.download = "w4rya-dl-" + id + ".dat";
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                a.remove();
              }}
            >
              Download body
            </button>
          )}
          <RadioGroup
            options={displayOptions}
            value={displayOption}
            onChange={setDisplayOption}
            className="flex gap-1.5 mr-4 ml-auto"
          />
        </div>
      </div>
      <div
        className={
          flow.from === "s"
            ? "border-l-4 border-hax-success/60 bg-hax-surface/40"
            : "border-l-4 border-hax-danger/60 bg-hax-surface/40"
        }
      >
        {displayOption === "Hex" && <HexFlow flow={flow}></HexFlow>}
        {displayOption === "Plain" && <TextFlow flow={flow}></TextFlow>}
        {displayOption === "Web" && <WebFlow flow={flow}></WebFlow>}
        {displayOption === "PythonRequest" && (
          <PythonRequestFlow
            flow={flow}
            full_flow={full_flow}
            item_index={flow_item_index}
          ></PythonRequestFlow>
        )}
      </div>
    </div>
  );
}

// Helper function to format the IP for display. If the IP contains ":",
// assume it is an ipv6 address and surround it in square brackets
function formatIP(ip: string) {
  return ip.includes(":") ? `[${ip}]` : ip;
}

function BlockIpButton({ ip }: { ip: string }) {
  const [block, { isLoading, isSuccess, error, reset }] = useBlockIpMutation();
  return (
    <button
      onClick={async () => {
        if (!confirm(`Add a Suricata DROP rule for ${ip}?`)) return;
        try {
          await block(ip).unwrap();
          setTimeout(() => reset(), 3000);
        } catch {}
      }}
      disabled={isLoading}
      title={`drop ip ${ip} via suricata`}
      className={`ml-2 hax-btn text-[10px] ${
        isSuccess
          ? "border-hax-success text-hax-success"
          : error
          ? "border-hax-danger text-hax-danger"
          : ""
      } disabled:opacity-50`}
    >
      {isLoading ? "…" : isSuccess ? "✓ blocked" : error ? "! err" : "block"}
    </button>
  );
}

function FlowOverview({ flow }: { flow: FullFlow }) {
  let [searchParams, setSearchParams] = useSearchParams();
  const { unixTimeToTick } = getTickStuff();
  const { data: services } = useGetServicesQuery();
  const service = services?.find((s) => s.ip === flow.dst_ip && s.port === flow.dst_port)?.name ?? "unknown";
  return (
    <div>
      {flow.signatures?.length > 0 ? (
        <div className="bg-hax-surface border-l-4 border-hax-accent p-3 m-3 rounded-sm" style={{ boxShadow: '0 0 18px -8px rgba(168,85,247,0.5)' }}>
          <div className="text-xs uppercase tracking-[0.25em] text-hax-accent-bright font-bold mb-2">▎suricata</div>
          <div className="pl-2 text-sm font-mono">
            {flow.signatures.map((sig) => {
              return (
                <div className="py-1 border-t border-hax-border first:border-t-0">
                  <div className="flex">
                    <div className="text-hax-muted w-24">message</div>
                    <div className="font-bold text-hax-text">{sig.message}</div>
                  </div>
                  <div className="flex">
                    <div className="text-hax-muted w-24">rule id</div>
                    <div className="font-bold text-hax-accent-bright">{sig.id}</div>
                  </div>
                  <div className="flex">
                    <div className="text-hax-muted w-24">action</div>
                    <div
                      className={
                        sig.action === "blocked"
                          ? "font-bold text-hax-danger uppercase tracking-wider"
                          : "font-bold text-hax-success uppercase tracking-wider"
                      }
                    >
                      {sig.action}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      ) : undefined}
      <div className="bg-hax-surface border-l-4 border-hax-warning/70 p-3 m-3 rounded-sm">
        <div className="text-xs uppercase tracking-[0.25em] text-hax-warning font-bold mb-2">▎meta</div>
        <div className="pl-2 text-sm font-mono">
          <div>
            Source:&nbsp;
            <a className="font-bold" href={`${API_BASE_PATH}/download/?file=${flow.filename}`}>
              {flow.filename}
              <DownloadIcon className="inline-flex items-baseline w-5 h-5" />
            </a>
          </div>
          <div>
            Tags:&nbsp;
            <span className="font-bold">[{flow.tags.join(", ")}]</span>
          </div>
          <div>
            Tick:&nbsp;
            <span className="font-bold">{unixTimeToTick(flow.time)}</span>
          </div>
          <div>
            Service:&nbsp;
            <span className="font-bold">{service}</span>
          </div>
          <div>
            Flags:&nbsp;
            <span className="font-bold">
              [{flow.flags.map((query, i) => (
                <span>
                  {i > 0 ? ", " : ""}
                  <button className="font-bold"
                    onClick={() => {
                      searchParams.set(TEXT_FILTER_KEY, escapeStringRegexp(query));
                      setSearchParams(searchParams);
                    }}
                  >
                    {query}
                  </button>
                </span>
              ))}]
            </span>
          </div>
          <div>
            Flagids:&nbsp;
            <span className="font-bold">
              [{flow.flagids.map((query, i) => (
                <span>
                  {i > 0 ? ", " : ""}
                  <button className="font-bold"
                    onClick={() => {
                      searchParams.set(TEXT_FILTER_KEY, escapeStringRegexp(query));
                      setSearchParams(searchParams);
                    }}
                  >
                    {query}
                  </button>
                </span>
              ))}]
            </span>
          </div>
          <div>
            Source - Target (Duration):&nbsp;
            <div className="inline-flex items-center gap-1">
              <div>
                <span>{formatIP(flow.src_ip)}</span>:
                <span className="font-bold">{flow.src_port}</span>
              </div>
              <BlockIpButton ip={flow.src_ip} />
              <span>-</span>
              <div>
                <span>{formatIP(flow.dst_ip)}</span>:
                <span className="font-bold">{flow.dst_port}</span>
              </div>
              <span className="italic">({flow.duration} ms)</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export function FlowView() {
  let [searchParams, setSearchParams] = useSearchParams();
  const params = useParams();
  const navigate = useNavigate();

  const id = params.id;

  const [reprId, setReprId] = useState(parseInt(searchParams.get(REPR_ID_KEY) ?? "0"));

  const { data: flow, isError, isLoading } = useGetFlowQuery(id!, { skip: id === undefined });

  const [triggerPwnToolsQuery] = useLazyToPwnToolsQuery();
  const [triggerFullPythonRequestQuery] = useLazyToFullPythonRequestQuery();

  async function copyAsPwn() {
    if (flow?.id) {
      const { data } = await triggerPwnToolsQuery(flow?.id);
      console.log(data);
      return data || "";
    }
    return "";
  }

  const { statusText: pwnCopyStatusText, copy: copyPwn } = useCopy({
    getText: copyAsPwn,
    copyStateToText: {
      copied: "Copied",
      default: "Copy as pwntools",
      failed: "Failed",
      copying: "Generating payload",
    },
  });

  async function copyAsRequests() {
    if (flow?.id) {
      const { data } = await triggerFullPythonRequestQuery(flow?.id);
      return data || "";
    }
    return "";
  }

  const { statusText: requestsCopyStatusText, copy: copyRequests } = useCopy({
    getText: copyAsRequests,
    copyStateToText: {
      copied: "Copied",
      default: "Copy as requests",
      failed: "Failed",
      copying: "Generating payload",
    },
  });

  // TODO: account for user scrolling - update currentFlow accordingly
  const [currentFlow, setCurrentFlow] = useState<number>(-1);
  const [exploitOpen, setExploitOpen] = useState(false);

  // reset scroll on flow switch
  useHotkeys('j', () => setCurrentFlow(0))
  useHotkeys('k', () => setCurrentFlow(0))

  useHotkeys('h', () => {
    // we do this for the scroll to top
    if (currentFlow === 0) {
      // document.getElementById(`${id}-${currentFlow}`)?.scrollIntoView(true)
      let el = document.querySelector("main > div > div:nth-child(2)")
      if (el) el.scrollIntoView()
    }
    setCurrentFlow(fi => Math.max(0, fi - 1))
  }, [currentFlow]);
  useHotkeys('l', () => {
    // if (currentFlow === (flow?.flow?.length ?? 1)-1) {
    //   document.getElementById(`${id}-${currentFlow}`)?.scrollIntoView(true)
    // }
    setCurrentFlow(fi => Math.min((flow?.flow?.length ?? 1)-1, fi + 1))
  }, [currentFlow, flow?.flow?.length]);

  useEffect(
    () => {
      if (currentFlow < 0) {
        return
      }
      document.getElementById(`${id}-${currentFlow}`)?.scrollIntoView(true)
    },
    [currentFlow]
  )

  useHotkeys("m", () => {
    setReprId(ri => (ri + 1) % (flow?.flow.length ?? 1))
  }, [reprId, flow?.flow.length]);

  // when the reprId changes, we update the url
  useEffect(
    () => {
      if (reprId === 0) {
        searchParams.delete(REPR_ID_KEY)
        setSearchParams(searchParams)
        return
      }
      searchParams.set(REPR_ID_KEY, reprId.toString());
      setSearchParams(searchParams)
    },
    [reprId]
  )

  // if the flow doesn't have the representation we're looking for, we fallback to raw
  useEffect(
    () => {
      if (flow?.flow.length == undefined || flow?.flow.length === 0) {
        return
      }
      if ((flow?.flow.length - 1) < reprId) {
        setReprId(0)
      }
    },
    [flow?.flow.length]
  )

  if (isError) {
    return <div>Error while fetching flow</div>;
  }

  if (isLoading || flow == undefined) {
    return <div>Loading...</div>;
  }

  return (
    <div>
      <div
        className="sticky shadow-md top-0 bg-hax-surface overflow-auto border-b border-hax-border flex"
        style={{ height: SECONDARY_NAVBAR_HEIGHT, zIndex: 100 }}
      >
        {(flow?.child_id != null || flow?.parent_id != null) ? (
          <div className="flex items-center p-2 gap-2">
            <button
              className="hax-btn flex items-center gap-1 disabled:opacity-30 disabled:cursor-not-allowed"
              key={"parent" + flow.parent_id}
              disabled={flow?.parent_id === null}
              onMouseDown={(e) => {
                if (e.button === 1) { // handle opening in new tab
                  window.open(`/flow/${flow.parent_id}?${searchParams}`, "_blank")
                } else if (e.button === 0) {
                  navigate(`/flow/${flow.parent_id}?${searchParams}`)
                }
              }}
            >
              <ArrowCircleUpIcon className="w-4 h-4"></ArrowCircleUpIcon> Parent
            </button>
            <button
              className="hax-btn flex items-center gap-1 disabled:opacity-30 disabled:cursor-not-allowed"
              key={"child" + flow.child_id}
              disabled={flow?.child_id === null}
              onMouseDown={(e) => {
                if (e.button === 1) { // handle opening in new tab
                  window.open(`/flow/${flow.child_id}?${searchParams}`, "_blank")
                } else if (e.button === 0) {
                  navigate(`/flow/${flow.child_id}?${searchParams}`)
                }
              }}
            >
              <ArrowCircleDownIcon className="w-4 h-4"></ArrowCircleDownIcon> Child
            </button>
          </div>
        ) : undefined}
        <div className="flex items-center p-2 gap-2 ml-auto">
          <p className="my-auto text-xs uppercase tracking-wider text-hax-muted">
            decoders <abbr title={"Number of decoders available for this flow: " + flow?.flow.length} className="text-hax-accent-bright">({flow?.flow.length})</abbr>:
          </p>
          <select
            id="repr-select"
            value={reprId}
            className="text-xs"
            onChange={(e) => {
              const target = e.target as HTMLSelectElement;
              const newreprid = parseInt(target.value);
              setReprId(newreprid);
            }}
          >
            {flow?.flow.map((e, i) => <option key={id + "reprselect" + i} value={i}>{e["type"]}</option>)}
          </select>
          {reprId > 0 ? <button
            className="hax-btn hax-btn-primary"
            title="Diff this representation with the base"
            onClick={(e) => {
              searchParams.set(FIRST_DIFF_KEY, `${id}`);
              searchParams.set(SECOND_DIFF_KEY, `${id}:${reprId}`);
              navigate(`/diff/${id ?? ""}?${searchParams}`, { replace: true });
            }}
          >
            <LightningBoltIcon className="h-4 w-4"></LightningBoltIcon>
          </button> : undefined}
          <button
            className="hax-btn hax-btn-primary"
            onClick={copyPwn}
          >
            {pwnCopyStatusText}
          </button>

          <button
            className="hax-btn hax-btn-primary"
            onClick={copyRequests}
          >
            {requestsCopyStatusText}
          </button>

          <button
            className="hax-btn hax-btn-primary"
            onClick={() => setExploitOpen(true)}
            title="Replay this flow against configured enemy teams"
          >
            ▶ test exploit
          </button>
        </div>
      </div>

      {exploitOpen && id && (
        <ExploitModal flowId={id} onClose={() => setExploitOpen(false)} />
      )}

      {flow ? <FlowOverview flow={flow}></FlowOverview> : undefined}
      {flow?.flow[(reprId < flow?.flow.length) ? reprId : 0].flow.map((flow_data, i, a) => {
        const delta_time = a[i].time - (a[i - 1]?.time ?? a[i].time);
        return (
          <Flow
            flow={flow_data}
            flow_item_index={i}
            delta_time={delta_time}
            full_flow={flow}
            key={flow.id + "-" + i}
            id={flow.id + "-" + i}
          ></Flow>
        );
      })}
    </div>
  );
}
