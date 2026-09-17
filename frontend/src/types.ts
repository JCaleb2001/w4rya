export interface Flow {
  id: Id;
  src_port: number;
  dst_port: number;
  src_ip: string;
  dst_ip: string;
  time: number;
  duration: number;
  // TODO: Get this from backend instead of hacky workaround
  service_tag: string;
  num_packets: number;
  parent_id: Id;
  child_id: Id;
  tags: string[];
  flags: string[];
  flagids: string[];
  suricata: number[];
  filename: string;
}

export interface TickInfo {
  startDate: string;
  tickLength: number;
  flagLifetime: number;
}

export interface FullFlow extends Flow {
  signatures: Signature[];
  flow: FlowRepresentation[];
}

export type Id = string;

export interface FlowRepresentation {
  type: string;
  flow: FlowData[];
}

export interface FlowData {
  from: string;
  data: string;
  b64: string;
  time: number;
}

export interface Signature {
  id: number;
  message: string;
  action: string;
}

// TODO: pagination WTF
export interface FlowsQuery {
  // Text filter
  regex_insensitive?: string;
  // Multi-service filter: server-side OR. Names resolved against the runtime
  // services config (DB-backed via /config/services).
  service_names?: string[];
  // Legacy single-service filter (still supported by backend, used by Corrie).
  service?: string;
  ip_dst?: string;
  port_dst?: number;
  time_from?: string;
  time_to?: string;
  // Substring match (case-insensitive) against the source pcap's filename.
  // Bypasses the tick/time filter entirely — useful for a pcap whose own
  // capture timestamp is way outside the game's tick-0 anchor (a
  // historical/test pcap loaded for detection testing, say), where no time
  // window will surface it without knowing that offset in advance.
  pcap_name?: string;
  tags_include?: string[];
  tags_exclude?: string[];
  tag_intersection_mode?: "AND" | "OR";
  // Drop the checker and our own tooling. Which ips those are lives in
  // the noise_ips config, so the client only sends the intent.
  hide_noise?: boolean;
  flags?: string[];
  flagids?: string[];
}

export interface StatsQuery {
  service: string;
  tick_from: number;
  tick_to: number;
}

export interface Stats {
  [key: string]: number; // little hack to make typescript happy
  tick: number;
  tag_flag_in: number;
  tag_flag_out: number;
  tag_blocked: number;
  tag_suricata: number;
  tag_enemy: number;
  flag_in: number;
  flag_out: number;
};

export type Service = {
  ip: string;
  port: number;
  name: string;
};

export type TicksAttackInfo = Record<number, Record<string, number>>;

export interface TicksAttackQuery {
  from_tick: number;
  to_tick: number;
}
