// /vulnbox endpoints, code-split into the shared w4ryaApi slice (RTK Query
// "injectEndpoints"): same base query, same 401 handling, same cache — no
// second API. The feature declares its own tag type, so the base api.ts
// doesn't need to know this module exists.

import { w4ryaApi } from "../../api";
import {
  ImportResult,
  Job,
  JobKind,
  KeyStatus,
  SeedResult,
  VulnboxOverview,
} from "./types";

const vulnboxApi = w4ryaApi
  .enhanceEndpoints({ addTagTypes: ["Vulnbox"] })
  .injectEndpoints({
    endpoints: (builder) => ({
      getVulnbox: builder.query<VulnboxOverview, void>({
        query: () => "/vulnbox",
        providesTags: ["Vulnbox"],
      }),
      generateVulnboxKey: builder.mutation<KeyStatus, { rotate: boolean }>({
        query: (body) => ({ url: "/vulnbox/key", method: "POST", body }),
        invalidatesTags: ["Vulnbox"],
      }),
      forgetVulnboxHostKey: builder.mutation<{ removed: boolean }, void>({
        query: () => ({ url: "/vulnbox/known-host", method: "DELETE" }),
        invalidatesTags: ["Vulnbox"],
      }),
      startVulnboxJob: builder.mutation<Job<unknown>, JobKind>({
        query: (kind) => ({ url: `/vulnbox/${kind}`, method: "POST" }),
        invalidatesTags: ["Vulnbox"],
      }),
      importVulnboxServices: builder.mutation<ImportResult, void>({
        query: () => ({ url: "/vulnbox/import-services", method: "POST" }),
        invalidatesTags: ["Services"],
      }),
      seedVulnboxDefaults: builder.mutation<SeedResult, void>({
        query: () => ({ url: "/vulnbox/seed-defaults", method: "POST" }),
        invalidatesTags: ["Vulnbox", "Config", "TickInfo", "FlagRegex"],
      }),
    }),
  });

export const {
  useGetVulnboxQuery,
  useGenerateVulnboxKeyMutation,
  useForgetVulnboxHostKeyMutation,
  useStartVulnboxJobMutation,
  useImportVulnboxServicesMutation,
  useSeedVulnboxDefaultsMutation,
} = vulnboxApi;

/** The private key is a file download (never JSON), via a plain anchor. */
export const PRIVATE_KEY_PATH = "/vulnbox/key/private";
