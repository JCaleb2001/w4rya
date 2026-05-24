import {
  createApi,
  fetchBaseQuery,
  BaseQueryFn,
  FetchArgs,
  FetchBaseQueryError,
} from "@reduxjs/toolkit/query/react";

import { API_BASE_PATH } from "./const";
import {
  Service,
  FullFlow,
  TickInfo,
  Flow,
  FlowsQuery,
  StatsQuery,
  Stats,
  TicksAttackInfo,
  TicksAttackQuery,
} from "./types";

function base64DecodeUnicode(str: string) : string {
  const text = atob(str);
  const bytes = new Uint8Array(text.length);
  for(let i = 0; i < text.length; i++)
    bytes[i] = text.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

const rawBaseQuery = fetchBaseQuery({
  baseUrl: API_BASE_PATH,
  credentials: "include",
});

// Wrap the base query so that any 401 (session expired / never set) invalidates
// the cached /me result. RequireAuth subscribes to /me, so it will re-render
// and redirect to /login.
const baseQueryWithReauth: BaseQueryFn<
  string | FetchArgs,
  unknown,
  FetchBaseQueryError
> = async (args, api, extraOptions) => {
  const result = await rawBaseQuery(args, api, extraOptions);
  if (result.error && result.error.status === 401) {
    api.dispatch(w4ryaApi.util.invalidateTags(["Me"]));
  }
  return result;
};

export const w4ryaApi = createApi({
  baseQuery: baseQueryWithReauth,
  tagTypes: ["Me", "Config", "Services", "Teams", "TickInfo", "FlagRegex"],
  endpoints: (builder) => ({
    getServices: builder.query<Service[], void>({
      query: () => "/services",
      providesTags: ["Services"],
    }),
    getFlagRegex: builder.query<string, void>({
      query: () => "/flag_regex",
      providesTags: ["FlagRegex"],
    }),
    getFlow: builder.query<FullFlow, string>({
      query: (id) => `/flow/${id}`,
      transformResponse: (flow: any): FullFlow => {
        const representations: any = {};

        for(const item of flow.items) {
          if(!(item.kind in representations))
            representations[item.kind] = { type: item.kind, flow: [] };
          representations[item.kind].flow.push({
            from: item.direction,
            data: base64DecodeUnicode(item.data),
            b64: item.data,
            time: new Date(item.time).getTime(),
          });
        }

        return {
          id: flow.id,
          src_port: flow.port_src,
          dst_port: flow.port_dst,
          src_ip: flow.ip_src,
          dst_ip: flow.ip_dst,
          time: new Date(flow.time).getTime(),
          duration: +(flow.duration * 1000).toFixed(0),
          num_packets: flow.packets_count,
          parent_id: flow.link_parent_id,
          child_id: flow.link_child_id,
          tags: flow.tags,
          flags: flow.flags,
          flagids: flow.flagids,
          filename: flow.pcap_name,
          service_tag: "",
          suricata: [],
          signatures: flow.signatures,
          flow: Object.values(representations),
        };
      },
    }),
    getFlows: builder.query<Flow[], FlowsQuery>({
      query: (query) => ({
        url: `/query`,
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        body: query,
      }),
      transformResponse: (response: Array<any>) => {
        return response.map((flow: any): Flow => ({
          id: flow.id,
          src_port: flow.port_src,
          dst_port: flow.port_dst,
          src_ip: flow.ip_src,
          dst_ip: flow.ip_dst,
          time: new Date(flow.time).getTime(),
          duration: +(flow.duration * 1000).toFixed(0),
          num_packets: flow.packets_count,
          parent_id: flow.link_parent_id,
          child_id: flow.link_child_id,
          tags: flow.tags,
          flags: flow.flags,
          flagids: flow.flagids,
          filename: flow.pcap_name,
          service_tag: "",
          suricata: [],
        }));
      },
    }),
    getStats: builder.query<Stats[], StatsQuery>({
      query: (query) => ({
        url: `/stats`,
        method: "GET",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        params: {
          service: query.service,
          tick_from: query.tick_from,
          tick_to: query.tick_to,
        }
      })
    }),
    getTags: builder.query<string[], void>({
      query: () => `/tags`,
    }),
    getTickInfo: builder.query<TickInfo, void>({
      query: () => `/tick_info`,
      providesTags: ["TickInfo"],
    }),
    getUnderAttack: builder.query<TicksAttackInfo, TicksAttackQuery>({
      query: (query) => ({
        url: '/under_attack',
        params: {
          from_tick: query.from_tick,
          to_tick: query.to_tick,
        }
      }),
    }),
    toPwnTools: builder.query<string, string>({
      query: (id) => ({ url: `/to_pwn/${id}`, responseHandler: "text" }),
    }),
    toSinglePythonRequest: builder.query<
      string,
      { body: string; id: string; item_index: number; tokenize: boolean }
    >({
      query: ({ body, id, item_index, tokenize }) => ({
        url: `/to_single_python_request?tokenize=${
          tokenize ? "1" : "0"
        }&id=${id}&index=${item_index}`,
        method: "POST",
        responseHandler: "text",
        headers: {
          "Content-Type": "text/plain;charset=UTF-8",
        },
        body,
      }),
    }),
    toFullPythonRequest: builder.query<string, string>({
      query: (id) => ({
        url: `/to_python_request/${id}`,
        responseHandler: "text",
      }),
    }),
    starFlow: builder.mutation<unknown, { id: string; star: boolean }>({
      query: ({ id, star }) => ({
        url: `/star`,
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        body: { id, star },
      }),
      // TODO: optimistic cache update

      async onQueryStarted({ id, star }, { dispatch, queryFulfilled }) {
        // `updateQueryData` requires the endpoint name and cache key arguments,
        // so it knows which piece of cache state to update
        const patchResult = dispatch(
          w4ryaApi.util.updateQueryData("getFlows", {service: "undefined", tags_include: [], tags_exclude:[]}, (flows) => {
            // The `flows` is Immer-wrapped and can be "mutated" like in createSlice
            const flow = flows.find((flow) => flow.id === id);
            if (flow) {
              if (star) {
                flow.tags.push("starred");
              } else {
                flow.tags = flow.tags.filter((tag) => tag != "starred");
              }
            }
          })
        );
        try {
          await queryFulfilled;
        } catch {
          patchResult.undo();
        }
      },
    }),
    getMe: builder.query<{ user: string | null }, void>({
      query: () => "/me",
      providesTags: ["Me"],
    }),
    login: builder.mutation<{ user: string }, { username: string; password: string }>({
      query: (body) => ({ url: "/login", method: "POST", body }),
      invalidatesTags: ["Me"],
    }),
    logout: builder.mutation<{ ok: boolean }, void>({
      query: () => ({ url: "/logout", method: "POST" }),
      invalidatesTags: ["Me"],
    }),

    // --- runtime config ---
    getConfig: builder.query<GameConfig, void>({
      query: () => "/config",
      providesTags: ["Config"],
    }),
    updateConfig: builder.mutation<GameConfig, Partial<GameConfig>>({
      query: (body) => ({ url: "/config", method: "PUT", body }),
      invalidatesTags: ["Config", "TickInfo", "FlagRegex"],
    }),
    getConfigServices: builder.query<Service[], void>({
      query: () => "/config/services",
      providesTags: ["Services"],
    }),
    updateConfigServices: builder.mutation<Service[], Service[]>({
      query: (body) => ({ url: "/config/services", method: "PUT", body }),
      invalidatesTags: ["Services"],
    }),
    getConfigTeams: builder.query<Team[], void>({
      query: () => "/config/teams",
      providesTags: ["Teams"],
    }),
    updateConfigTeams: builder.mutation<Team[], Team[]>({
      query: (body) => ({ url: "/config/teams", method: "PUT", body }),
      invalidatesTags: ["Teams"],
    }),

    // --- attack / exploit replay ---
    getAttackPreview: builder.query<AttackPreview, string>({
      query: (flow_id) => `/attack/preview/${flow_id}`,
    }),
    attackReplay: builder.mutation<
      ReplayResponse,
      { flow_id: string; targets: { name: string; ip: string }[]; timeout?: number }
    >({
      query: (body) => ({ url: "/attack/replay", method: "POST", body }),
    }),
  }),
});

export interface GameConfig {
  flag_regex: string;
  tick_length: number;
  start_date: string;
  flag_lifetime: number;
  vm_ip: string;
  team_id: string;
  visualizer_url: string;
  bpf: string;
}

export interface Team {
  name: string;
  ip: string;
  notes?: string;
}

export interface AttackPreview {
  flow_id: string;
  port: number;
  src_ip: string;
  dst_ip: string;
  payload_size: number;
  client_items: number;
  server_items: number;
}

export interface ReplayResult {
  team_name: string;
  target_ip: string;
  ok: boolean;
  latency_ms?: number;
  response_size?: number;
  response_excerpt?: string;
  flags?: string[];
  flag_count?: number;
  error?: string;
}

export interface ReplayResponse {
  flow_id: string;
  port: number;
  payload_size: number;
  timeout_s?: number;
  results: ReplayResult[];
}

export const {
  useGetServicesQuery,
  useGetFlagRegexQuery,
  useGetFlowQuery,
  useGetFlowsQuery,
  useLazyGetFlowsQuery,
  useGetTagsQuery,
  useGetTickInfoQuery,
  useLazyToPwnToolsQuery,
  useLazyToFullPythonRequestQuery,
  useToSinglePythonRequestQuery,
  useStarFlowMutation,
  useGetStatsQuery,
  useGetUnderAttackQuery,
  useGetMeQuery,
  useLoginMutation,
  useLogoutMutation,
  useGetConfigQuery,
  useUpdateConfigMutation,
  useGetConfigServicesQuery,
  useUpdateConfigServicesMutation,
  useGetConfigTeamsQuery,
  useUpdateConfigTeamsMutation,
  useGetAttackPreviewQuery,
  useAttackReplayMutation,
} = w4ryaApi;
