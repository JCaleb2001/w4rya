import {
  useSearchParams,
  Link,
  useParams,
  useNavigate,
} from "react-router-dom";
import { useState, useRef, useEffect } from "react";
import { useHotkeys } from 'react-hotkeys-hook';
import { FetchBaseQueryError } from '@reduxjs/toolkit/query'
import { Flow } from "../types";
import {
  SERVICE_FILTER_KEY,
  SERVICES_FILTER_KEY,
  TEXT_FILTER_KEY,
  START_FILTER_KEY,
  END_FILTER_KEY,
  FLOW_LIST_REFETCH_INTERVAL_MS,
  FORCE_REFETCH_ON_STAR,
} from "../const";
import { useAppSelector, useAppDispatch } from "../store";
import { toggleFilterTag, toggleTagIntersectMode } from "../store/filter";

import { HeartIcon, FilterIcon, LinkIcon } from "@heroicons/react/solid";
import { HeartIcon as EmptyHeartIcon } from "@heroicons/react/outline";

import classes from "./FlowList.module.css";
import { format } from "date-fns";
import useDebounce from "../hooks/useDebounce";
import { Virtuoso, VirtuosoHandle } from "react-virtuoso";
import classNames from "classnames";
import { Tag } from "./Tag";
import {
  useGetFlowsQuery,
  useGetServicesQuery,
  useGetServicesStatsQuery,
  useGetTagsQuery,
  useStarFlowMutation,
  useVisibilityAwarePolling,
} from "../api";

export function FlowList() {
  let [searchParams, setSearchParams] = useSearchParams();
  let params = useParams();

  // we add a local variable to prevent racing with the browser location API
  let openedFlowID = params.id

  const { data: availableTags } = useGetTagsQuery();
  const { data: services } = useGetServicesQuery();
  // Per-service stats over last 5 ticks. Polls every 15s when visible; reused
  // as a tag pressure indicator on each chip below.
  const servicesPoll = useVisibilityAwarePolling(15000);
  const { data: serviceStats } = useGetServicesStatsQuery(5, {
    pollingInterval: servicesPoll,
  });

  const filterFlags = useAppSelector((state) => state.filter.filterFlags);
  const filterFlagids = useAppSelector((state) => state.filter.filterFlagids);
  const includeTags = useAppSelector((state) => state.filter.includeTags);
  const excludeTags = useAppSelector((state) => state.filter.excludeTags);
  const tagIntersectionMode = useAppSelector((state) => state.filter.tagIntersectionMode);

  const dispatch = useAppDispatch();

  const [starFlow] = useStarFlowMutation();

  const [flowIndex, setFlowIndex] = useState<number>(0);

  const virtuoso = useRef<VirtuosoHandle>(null);

  // Multi-select services. Read from ?services=a,b,c with legacy fallback to
  // ?service=a (the old single-select dropdown that used to live in Header).
  const services_param = searchParams.get(SERVICES_FILTER_KEY);
  const legacy_service = searchParams.get(SERVICE_FILTER_KEY);
  const selected_service_names =
    services_param
      ? services_param.split(",").map((s) => s.trim()).filter(Boolean)
      : (legacy_service ? [legacy_service] : []);

  function toggleService(name: string) {
    const sp = new URLSearchParams(searchParams);
    sp.delete(SERVICE_FILTER_KEY); // drop legacy
    const cur = new Set(selected_service_names);
    if (cur.has(name)) cur.delete(name);
    else cur.add(name);
    if (cur.size === 0) sp.delete(SERVICES_FILTER_KEY);
    else sp.set(SERVICES_FILTER_KEY, [...cur].join(","));
    setSearchParams(sp);
  }

  function selectAllServices() {
    if (!services) return;
    const sp = new URLSearchParams(searchParams);
    sp.delete(SERVICE_FILTER_KEY);
    sp.set(SERVICES_FILTER_KEY, services.map((s) => s.name).join(","));
    setSearchParams(sp);
  }
  function clearServices() {
    const sp = new URLSearchParams(searchParams);
    sp.delete(SERVICE_FILTER_KEY);
    sp.delete(SERVICES_FILTER_KEY);
    setSearchParams(sp);
  }

  const text_filter = searchParams.get(TEXT_FILTER_KEY) ?? undefined;
  const from_filter = searchParams.get(START_FILTER_KEY) ?? undefined;
  const to_filter = searchParams.get(END_FILTER_KEY) ?? undefined;

  const debounced_text_filter = useDebounce(text_filter, 300);

  const {
    data: flowData, error: flowQueryError,
    isLoading, isFetching, refetch,
    startedTimeStamp, fulfilledTimeStamp,
  } = useGetFlowsQuery(
    {
      regex_insensitive: debounced_text_filter,
      service_names: selected_service_names.length > 0 ? selected_service_names : undefined,
      time_from: from_filter ? new Date(parseInt(from_filter)).toISOString() : undefined,
      time_to: to_filter ? new Date(parseInt(to_filter)).toISOString() : undefined,
      tags_include: includeTags,
      tags_exclude: excludeTags,
      tag_intersection_mode: tagIntersectionMode,
      flags: filterFlags,
      flagids: filterFlagids,
    },
    {
      refetchOnMountOrArgChange: true,
      pollingInterval: FLOW_LIST_REFETCH_INTERVAL_MS,
    }
  );

  interface FlowQueryError { error: string }
  const isFetchBaseQueryError = (error: unknown): error is FetchBaseQueryError =>
    typeof error === 'object' && error != null && 'status' in error
  const isFlowQueryError = (error: unknown): error is FlowQueryError =>
    typeof error === 'object' && error != null && 'error' in error
  const flowQueryErrorMessage = isFetchBaseQueryError(flowQueryError)
    && isFlowQueryError(flowQueryError.data)
    ? flowQueryError.data.error : null;

  let searchMessage = null;
  if(isFetching)
    searchMessage = "Searching...";
  else if(flowQueryErrorMessage)
    searchMessage = `Error: ${flowQueryErrorMessage}`;
  else if(startedTimeStamp && fulfilledTimeStamp)
    searchMessage = `Search took ${fulfilledTimeStamp - startedTimeStamp}ms`

  // TODO: fix the below transformation - move it to server
  // Diederik gives you a beer once it has been fixed
  const transformedFlowData = flowData?.map((flow) => ({
    ...flow,
    service_tag:
      services?.find((s) => s.ip === flow.dst_ip && s.port === flow.dst_port)
        ?.name ?? "unknown",
  }));

  const onHeartHandler = async (flow: Flow) => {
    await starFlow({ id: flow.id, star: !flow.tags.includes("starred") });
    if(FORCE_REFETCH_ON_STAR) refetch();
  };

  const navigate = useNavigate();

  useEffect(() => {
      virtuoso?.current?.scrollIntoView({
        index: flowIndex,
        behavior: 'auto',
        done: () => {
          if (transformedFlowData && transformedFlowData[flowIndex ?? 0]) {
            let idAtIndex = transformedFlowData[flowIndex ?? 0].id;
            // if the current flow ID at the index indeed did change (ie because of keyboard navigation), we need to update the URL as well as local ID
            if (idAtIndex !== openedFlowID) {
              navigate(`/flow/${idAtIndex}?${searchParams}`)
              openedFlowID = idAtIndex
            }
          }
        },
      })
    },
    [flowIndex]
  )

  // TODO: there must be a better way to do this
  // this gets called on every refetch, we dont want to iterate all flows on every refetch
  // so because performance, we hack this by checking if the transformedFlowData length changed
  const [transformedFlowDataLength, setTransformedFlowDataLength] = useState<number>(0);
  useEffect(
    () => {
      if (transformedFlowData && transformedFlowDataLength != transformedFlowData?.length) {
        setTransformedFlowDataLength(transformedFlowData?.length)

        for (let i = 0; i < transformedFlowData?.length; i++) {
          if (transformedFlowData[i].id === openedFlowID) {
            if (i !== flowIndex) {
              setFlowIndex(i)
            }
            return
          }
        }
        setFlowIndex(0)
      }
    },
    [transformedFlowData]
  )

  useHotkeys('x', async () => {
    if(transformedFlowData) {
      let flow = transformedFlowData[flowIndex ?? 0]
      await onHeartHandler(flow);
    }
  })

  useHotkeys('j', () => setFlowIndex(fi => Math.min((transformedFlowData?.length ?? 1)-1, fi + 1)), [transformedFlowData?.length]);
  useHotkeys('w', () => {
    if(transformedFlowData) {
      let idAtIndex = transformedFlowData[flowIndex ?? 0].id;
      if (idAtIndex != openedFlowID) {
        let flowids = flowData?.map((flow, idx) => ([flow.id, idx]))
        if (flowids) {
          let found = flowids.filter((el)=>(el[0] == openedFlowID))
          if (found.length > 0) {
            let n = Number(found[0][1])
            setFlowIndex(n)
          }
        }
      }
    }
  }
  );
  useHotkeys('k', () => setFlowIndex(fi => Math.max(0, fi - 1)));
  useHotkeys('i', () => {
    setShowFilters(true)
    if ((availableTags ?? []).includes("flag-in")) {
      dispatch(toggleFilterTag("flag-in"))
    }
  }, [availableTags]);
  useHotkeys('o', () => {
    setShowFilters(true)
    if ((availableTags ?? []).includes("flag-out")) {
      dispatch(toggleFilterTag("flag-out"))
    }
  }, [availableTags]);
  useHotkeys('t', () => {
    setShowFilters(true)
    if ((availableTags ?? []).includes("starred")) {
      dispatch(toggleFilterTag("starred"))
    }
  }, [availableTags]);
  useHotkeys('r', () => refetch());

  const [showFilters, setShowFilters] = useState(false);

  return (
    <div className="flex flex-col h-full bg-hax-surface text-hax-text">
      <div className="bg-hax-surface border-b border-hax-border flex flex-col">
        <div className="p-2 flex items-center" style={{ height: 50 }}>
          <button
            className="flex gap-1.5 items-center text-xs uppercase tracking-wider text-hax-muted hover:text-hax-accent-bright transition-colors"
            onClick={() => setShowFilters(!showFilters)}
          >
            {<FilterIcon height={16} className="text-hax-accent"></FilterIcon>}
            {showFilters ? "Close" : "Open"} filters
          </button>
          {/* Maybe we want to use a search button instead of live search */}
          {false && (
            <button className="ml-auto items-center hax-btn hax-btn-primary">
              Search
            </button>
          )}
        </div>
        {showFilters && (
          <div className="border-t border-hax-border p-2 bg-hax-bg/60 flex flex-col gap-3">
            {/* services multi-select */}
            <div>
              <div className="flex items-center mb-1.5">
                <p className="text-[10px] uppercase tracking-[0.2em] font-bold text-hax-muted">
                  ▎services
                </p>
                <span className="ml-2 text-[10px] text-hax-dim normal-case">
                  {selected_service_names.length === 0
                    ? "(all)"
                    : `(${selected_service_names.length} selected)`}
                </span>
                <button
                  onClick={selectAllServices}
                  className="ml-auto hax-btn text-[10px]"
                >
                  all
                </button>
                <button onClick={clearServices} className="ml-1 hax-btn text-[10px]">
                  none
                </button>
              </div>
              {(!services || services.length === 0) ? (
                <div className="text-[10px] text-hax-dim">
                  no services configured — add in{" "}
                  <Link to="/config" className="underline text-hax-accent-bright">
                    /config → services
                  </Link>
                </div>
              ) : (
                <div className="flex gap-1.5 flex-wrap">
                  {services.map((s) => {
                    const active = selected_service_names.includes(s.name);
                    const stats = serviceStats?.services.find(
                      (st) => st.name === s.name && st.ip === s.ip && st.port === s.port
                    );
                    const danger = (stats?.flag_out ?? 0) > 0;
                    const warning = (stats?.attacks ?? 0) > 0;
                    const idle = (stats?.flows ?? 0) === 0;

                    // Pressure border: red > amber > violet > dim
                    let borderCls =
                      "bg-hax-elev border-hax-border text-hax-muted hover:border-hax-accent-deep hover:text-hax-text";
                    if (active) {
                      borderCls =
                        "bg-hax-accent-deep/30 border-hax-accent text-hax-accent-bright shadow-[0_0_8px_-3px_rgba(168,85,247,0.6)]";
                    } else if (danger) {
                      borderCls =
                        "bg-hax-danger/10 border-hax-danger text-red-300 hover:bg-hax-danger/20 shadow-[0_0_8px_-3px_rgba(239,68,68,0.6)]";
                    } else if (warning) {
                      borderCls =
                        "bg-hax-warning/10 border-hax-warning/60 text-hax-warning hover:border-hax-warning";
                    } else if (!idle) {
                      borderCls =
                        "bg-hax-elev border-hax-accent-deep/40 text-hax-text hover:border-hax-accent";
                    }

                    return (
                      <button
                        key={s.name + ":" + s.port}
                        onClick={() => toggleService(s.name)}
                        className={`px-2 py-0.5 rounded-sm text-[10px] font-mono uppercase tracking-wider border transition-all ${borderCls}`}
                        title={
                          stats
                            ? `${s.ip}:${s.port}\nlast 5 ticks:\n  ${stats.flows} flows\n  ${stats.attacks} attacks\n  ${stats.flag_in} flag-in, ${stats.flag_out} flag-out`
                            : `${s.ip}:${s.port}`
                        }
                      >
                        {s.name}
                        <span className="ml-1 text-hax-dim">:{s.port}</span>
                        {stats && stats.flows > 0 && (
                          <span className="ml-1.5 text-hax-text">
                            {stats.flows}f
                          </span>
                        )}
                        {stats && stats.attacks > 0 && (
                          <span className="ml-1 text-hax-warning" title={`${stats.attacks} attacks`}>
                            ⚔{stats.attacks}
                          </span>
                        )}
                        {stats && stats.flag_out > 0 && (
                          <span
                            className="ml-1 text-hax-danger hax-glow"
                            title={`${stats.flag_out} flags leaked`}
                          >
                            🚩{stats.flag_out}
                          </span>
                        )}
                      </button>
                    );
                  })}
                </div>
              )}
            </div>

            {/* tags intersection */}
            <div>
              <div className="flex items-center mb-1.5">
                <p className="text-[10px] uppercase tracking-[0.2em] font-bold text-hax-muted">
                  ▎tag intersection
                </p>
                <button
                  className="ml-auto hax-btn text-[10px]"
                  onClick={() => dispatch(toggleTagIntersectMode())}
                >
                  mode:&nbsp;<span className="text-hax-accent-bright">{tagIntersectionMode}</span>
                </button>
              </div>
              <div className="flex gap-1.5 flex-wrap">
                {(availableTags ?? []).map((tag) => (
                  <Tag
                    key={tag}
                    tag={tag}
                    disabled={!includeTags.includes(tag)}
                    excluded={excludeTags.includes(tag)}
                    onClick={() => dispatch(toggleFilterTag(tag))}
                  ></Tag>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
      { searchMessage && (
        <div className="px-3 py-1 text-[10px] uppercase tracking-wider font-mono text-hax-muted bg-hax-bg/60 border-b border-hax-border">
          <span className="text-hax-accent-bright">$</span> {searchMessage}
        </div>
      )}
      <Virtuoso
        className={classNames({
          "flex-1": true,
          [classes.list_container]: true,
          "sidebar-loading": isLoading,
        })}
        data={transformedFlowData}
        ref={virtuoso}
        initialTopMostItemIndex={flowIndex}
        itemContent={(index, flow) => (
          <Link
            to={`/flow/${flow.id}?${searchParams}`}
            onClick={() => setFlowIndex(index)}
            key={flow.id}
            className="focus-visible:rounded-md"
            //style={{ paddingTop: '1em' }}
          >
            <FlowListEntry
              key={flow.id}
              flow={flow}
              isActive={flow.id === openedFlowID}
              onHeartClick={onHeartHandler}
            />
          </Link>
        )}
      />
    </div>
  );
}

interface FlowListEntryProps {
  flow: Flow;
  isActive: boolean;
  onHeartClick: (flow: Flow) => void;
}

function FlowListEntry({ flow, isActive, onHeartClick }: FlowListEntryProps) {
  const formatted_time_h_m_s = format(new Date(flow.time), "HH:mm:ss");
  const formatted_time_ms = format(new Date(flow.time), ".SSS");

  const [isStarred, setStarred] = useState(flow.tags.includes("starred"));

  // Filter tag list for tags that are handled specially
  const filtered_tag_list = flow.tags.filter((t) => t != "starred");

  const duration =
    flow.duration > 10000 ? (
      <div className="text-hax-danger font-mono">&gt;10s</div>
    ) : (
      <div className="font-mono">{flow.duration}ms</div>
    );
  return (
    <li
      className={classNames({
        [classes.active]: isActive,
      })}
    >
      <div className="flex">
        <div
          className="w-5 ml-1 mr-1 self-center shrink-0"
          onClick={() => {
            setStarred(!isStarred);
            onHeartClick(flow);
          }}
        >
          {isStarred ? (
            <HeartIcon className="text-hax-accent-bright" style={{ filter: 'drop-shadow(0 0 4px rgba(192,132,252,0.7))' }} />
          ) : (
            <EmptyHeartIcon className="text-hax-dim" />
          )}
        </div>

        <div className="w-5 mr-2 self-center shrink-0">
          {flow.child_id != null || flow.parent_id != null ? (
            <LinkIcon className="text-hax-accent" />
          ) : undefined}
        </div>
        <div className="flex-1 shrink">
          <div className="flex">
            <div className="shrink-0">
              <span className="text-hax-text font-bold overflow-ellipsis overflow-hidden uppercase tracking-wide text-xs">
                {flow.service_tag}
              </span>
              <span className="text-hax-muted font-mono">:{flow.dst_port}</span>
            </div>

            <div className="ml-2 font-mono">
              <span className="text-hax-muted">{formatted_time_h_m_s}</span>
              <span className="text-hax-dim">{formatted_time_ms}</span>
            </div>
            <div className="text-hax-muted ml-auto">{duration}</div>
          </div>
          <div className="flex gap-1.5 flex-wrap mt-1">
            {filtered_tag_list.map((tag) => (
              <Tag key={tag} tag={tag}></Tag>
            ))}
          </div>
        </div>
      </div>
    </li>
  );
}

export { FlowListEntry };
