import { useCallback, useEffect, useMemo, useRef, useState } from "react";

type Summary = {
  processes: number;
  connections: number;
  domains: number;
  alerts: number;
  observation_level: string;
};

type ProcessRow = {
  pid: number;
  name: string;
  command_line: string | null;
  connections: number;
  sent_bytes: number;
  received_bytes: number;
  level: string;
  risk_score?: number;
};

type Endpoint = {
  address: string;
  port: number;
};

type ConnectionRow = {
  id: string;
  pid: number | null;
  process_name: string | null;
  process_command_line: string | null;
  protocol: string;
  remote: Endpoint;
  state: string;
  tcp_state: string | null;
  sent_bytes: number;
  received_bytes: number;
  domain: string | null;
  tls_sni?: string | null;
  tls_version?: string | null;
  first_seen_ns?: number;
  last_seen_ns?: number;
  risk_score?: number;
};

type AlertRow = {
  id: string;
  event_id: string | null;
  timestamp_ns: number;
  severity: "low" | "medium" | "high" | "critical";
  rule: string;
  summary: string;
  process_id: number | null;
  process_name: string | null;
  connection_id: string | null;
  domain: string | null;
  evidence: string[];
  risk_score: number;
};

type GraphNode = {
  id: string;
  kind: "process" | "domain" | "connection" | "file";
  label: string;
  risk_score: number;
  pid: number | null;
  connection_id: string | null;
  metadata: Record<string, string>;
};

type GraphEdge = {
  id: string;
  source: string;
  target: string;
  relation: string;
  event_count: number;
  first_seen_ns: number;
  last_seen_ns: number;
};

type BehaviorGraph = {
  nodes: GraphNode[];
  edges: GraphEdge[];
  updated_at_ns: number;
};

type TimelineEntry = {
  id: string;
  timestamp_ns: number;
  source: string;
  kind: string;
  pid: number | null;
  process_name: string | null;
  process_command_line: string | null;
  summary: string;
  domain: string | null;
  addresses: string[];
  protocol: string | null;
  connection_id: string | null;
  remote: Endpoint | null;
  state: string | null;
  tcp_state: string | null;
  sent_bytes: number | null;
  received_bytes: number | null;
  tls_sni?: string | null;
  tls_version?: string | null;
  ssl_object?: number | null;
  fd?: number | null;
  plaintext_direction?: string | null;
  plaintext?: string | null;
  plaintext_bytes?: number | null;
  plaintext_truncated?: boolean;
  http_direction?: string | null;
  http_version?: string | null;
  http_method?: string | null;
  http_target?: string | null;
  http_host?: string | null;
  http_status?: number | null;
  http_reason?: string | null;
  http_headers?: Array<{ name: string; value: string }>;
  http_content_length?: number | null;
  file_path?: string | null;
  file_bytes?: number | null;
};

type TimelinePage = {
  entries: TimelineEntry[];
  total: number;
  offset: number;
  limit: number;
  has_more: boolean;
};

type ConnectionTimeline = {
  id: string;
  pid: number | null;
  process_name: string | null;
  process_command_line: string | null;
  protocol: string;
  local: Endpoint | null;
  remote: Endpoint;
  domain: string | null;
  tls_sni?: string | null;
  tls_version?: string | null;
  state: string;
  tcp_state: string | null;
  first_seen_ns: number;
  last_seen_ns: number;
  duration_ns: number;
  sent_bytes: number;
  received_bytes: number;
  event_count: number;
  events: TimelineEntry[];
};

type ConnectionTimelinePage = {
  sessions: ConnectionTimeline[];
  total: number;
  offset: number;
  limit: number;
  has_more: boolean;
};

type Snapshot = {
  summary: Summary;
  processes: ProcessRow[];
  connections: ConnectionRow[];
  connection_timeline: ConnectionTimelinePage;
  timeline: TimelinePage;
  alerts: AlertRow[];
  graph: BehaviorGraph;
  mode: "demo" | "live";
};

const API_BASE = import.meta.env.VITE_CORE_API_URL ?? "";
const PROCESS_PAGE_SIZE = 8;
const CONNECTION_PAGE_SIZE = 20;
const TIMELINE_PAGE_SIZE = 50;

type SortDirection = "asc" | "desc";
type ProcessSortKey = "name" | "pid" | "connections" | "traffic" | "level" | "risk";
type ConnectionSortKey = "process" | "pid" | "remote" | "domain" | "state" | "traffic" | "last_seen" | "risk";

type SortState<Key extends string> = {
  key: Key;
  direction: SortDirection;
};

const demoSummary: Summary = {
  processes: 4,
  connections: 54,
  domains: 31,
  alerts: 1,
  observation_level: "L1",
};

const demoProcesses: ProcessRow[] = [
  { name: "chrome", pid: 4821, connections: 48, sent_bytes: 1_200_000, received_bytes: 1_600_000, level: "L1", command_line: null },
  { name: "curl", pid: 12345, connections: 1, sent_bytes: 8_000, received_bytes: 10_432, level: "L1", command_line: "curl https://example.com" },
  { name: "python3", pid: 9172, connections: 3, sent_bytes: 500_000_000, received_bytes: 0, level: "L3", command_line: "python3 uploader.py" },
  { name: "sshd", pid: 1061, connections: 2, sent_bytes: 0, received_bytes: 0, level: "L1", command_line: null },
];

const demoConnections: ConnectionRow[] = [
  { id: "demo-curl", pid: 12345, process_name: "curl", process_command_line: "curl https://example.com", protocol: "tcp", remote: { address: "93.184.216.34", port: 443 }, state: "established", tcp_state: "established", sent_bytes: 8_000, received_bytes: 10_432, domain: "example.com" },
  { id: "demo-python", pid: 9172, process_name: "python3", process_command_line: "python3 uploader.py", protocol: "tcp", remote: { address: "203.0.113.42", port: 443 }, state: "established", tcp_state: "established", sent_bytes: 500_000_000, received_bytes: 0, domain: "suspicious.example" },
];

const demoTimeline: TimelineEntry[] = [
  { id: "demo-timeline-1", timestamp_ns: 1_723_000_000_000_000_000, source: "kernel", kind: "process_exec", pid: 12345, process_name: "curl", process_command_line: "curl https://example.com", summary: "curl started", domain: null, addresses: [], protocol: null, connection_id: null, remote: null, state: null, tcp_state: null, sent_bytes: null, received_bytes: null },
  { id: "demo-timeline-2", timestamp_ns: 1_723_000_001_000_000_000, source: "kernel", kind: "dns_response", pid: 12345, process_name: "curl", process_command_line: "curl https://example.com", summary: "DNS response for example.com", domain: "example.com", addresses: ["93.184.216.34"], protocol: "udp", connection_id: null, remote: null, state: null, tcp_state: null, sent_bytes: null, received_bytes: null },
  { id: "demo-timeline-3", timestamp_ns: 1_723_000_002_000_000_000, source: "kernel", kind: "tcp_connect", pid: 12345, process_name: "curl", process_command_line: "curl https://example.com", summary: "Connected to example.com:443", domain: "example.com", addresses: [], protocol: "tcp", connection_id: "demo-curl", remote: { address: "93.184.216.34", port: 443 }, state: "established", tcp_state: "established", sent_bytes: 8_000, received_bytes: 10_432 },
];

const demoConnectionTimeline: ConnectionTimelinePage = {
  sessions: [
    {
      id: "demo-curl",
      pid: 12345,
      process_name: "curl",
      process_command_line: "curl https://example.com",
      protocol: "tcp",
      local: null,
      remote: { address: "93.184.216.34", port: 443 },
      domain: "example.com",
      state: "established",
      tcp_state: "established",
      first_seen_ns: 1_723_000_002_000_000_000,
      last_seen_ns: 1_723_000_004_400_000_000,
      duration_ns: 2_400_000_000,
      sent_bytes: 8_000,
      received_bytes: 10_432,
      event_count: 3,
      events: [
        { ...demoTimeline[1], connection_id: "demo-curl" },
        demoTimeline[2],
        { ...demoTimeline[2], id: "demo-timeline-4", kind: "tcp_close", summary: "Closed connection to example.com:443", timestamp_ns: 1_723_000_004_400_000_000, state: "closed", tcp_state: "close", connection_id: "demo-curl" },
      ],
    },
  ],
  total: 1,
  offset: 0,
  limit: 50,
  has_more: false,
};

const initialSnapshot: Snapshot = {
  summary: demoSummary,
  processes: demoProcesses,
  connections: demoConnections,
  connection_timeline: demoConnectionTimeline,
  timeline: {
    entries: demoTimeline,
    total: demoTimeline.length,
    offset: 0,
    limit: 50,
    has_more: false,
  },
  alerts: [],
  graph: { nodes: [], edges: [], updated_at_ns: 0 },
  mode: "demo",
};

async function fetchJson<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`);
  if (!response.ok) {
    throw new Error(`${path}: ${response.status}`);
  }
  return response.json() as Promise<T>;
}

function buildTimelinePath(kind: string, pid: string, connectionId: string, offset: number): string {
  const params = new URLSearchParams({ limit: String(TIMELINE_PAGE_SIZE), offset: String(offset) });
  if (kind !== "all") params.set("kind", kind);
  if (/^\d+$/.test(pid.trim())) params.set("pid", pid.trim());
  if (connectionId.trim()) params.set("connection_id", connectionId.trim());
  return `/api/timeline?${params.toString()}`;
}

function buildConnectionTimelinePath(offset: number, includeClosed: boolean): string {
  const params = new URLSearchParams({
    limit: "20",
    offset: String(offset),
    include_closed: String(includeClosed),
    include_events: "false",
  });
  return `/api/connection-timeline?${params.toString()}`;
}

function buildConnectionDetailPath(connectionId: string): string {
  const params = new URLSearchParams({
    limit: "1",
    offset: "0",
    include_closed: "true",
    include_events: "true",
    event_limit: "200",
    connection_id: connectionId,
  });
  return `/api/connection-timeline?${params.toString()}`;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "—";
  if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}

function formatTimestamp(timestampNs: number, originNs: number): string {
  const deltaNs = Math.max(0, timestampNs - originNs);
  const totalSeconds = Math.floor(deltaNs / 1_000_000_000);
  const hours = Math.floor(totalSeconds / 3_600);
  const minutes = Math.floor((totalSeconds % 3_600) / 60);
  const seconds = totalSeconds % 60;
  if (hours > 0) return `T+${hours}h ${minutes}m`;
  if (minutes > 0) return `T+${minutes}m ${seconds}s`;
  return `T+${seconds}s`;
}

function formatClock(timestampNs?: number): string {
  if (!timestampNs) return "—";
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(new Date(timestampNs / 1_000_000));
}

function formatDuration(durationNs: number): string {
  const totalSeconds = Math.max(0, Math.floor(durationNs / 1_000_000_000));
  if (totalSeconds < 1) return "<1s";
  if (totalSeconds < 60) return `${totalSeconds}s`;
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  if (minutes < 60) return `${minutes}m ${seconds}s`;
  return `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
}

function compareSortableValues(left: string | number | null | undefined, right: string | number | null | undefined): number {
  if (typeof left === "number" && typeof right === "number") return left - right;
  return String(left ?? "").localeCompare(String(right ?? ""), undefined, { numeric: true, sensitivity: "base" });
}

function nextSortState<Key extends string>(current: SortState<Key>, key: Key): SortState<Key> {
  return current.key === key
    ? { key, direction: current.direction === "asc" ? "desc" : "asc" }
    : { key, direction: "asc" };
}

function SortableHeader<Key extends string>({
  label,
  column,
  sort,
  onSort,
}: {
  label: string;
  column: Key;
  sort: SortState<Key>;
  onSort: (column: Key) => void;
}) {
  const active = sort.key === column;
  return (
    <th scope="col" aria-sort={active ? (sort.direction === "asc" ? "ascending" : "descending") : "none"}>
      <button
        type="button"
        className={`sort-button ${active ? "active" : ""}`}
        onClick={() => onSort(column)}
        aria-label={`Sort by ${label}`}
      >
        <span>{label}</span>
        <span className="sort-indicator" aria-hidden="true">{active ? (sort.direction === "asc" ? "↑" : "↓") : "↕"}</span>
      </button>
    </th>
  );
}

function TablePagination({
  pageIndex,
  pageCount,
  totalRows,
  pageSize,
  loading,
  onPageChange,
}: {
  pageIndex: number;
  pageCount: number;
  totalRows: number;
  pageSize: number;
  loading?: boolean;
  onPageChange: (pageIndex: number) => void;
}) {
  const firstRow = totalRows === 0 ? 0 : pageIndex * pageSize + 1;
  const lastRow = totalRows === 0 ? 0 : Math.min(totalRows, (pageIndex + 1) * pageSize);
  return (
    <div className="table-pagination">
      <button
        className="ghost-button"
        onClick={() => onPageChange(Math.max(0, pageIndex - 1))}
        disabled={loading || pageIndex === 0}
      >
        Previous
      </button>
      <span>{firstRow}–{lastRow} of {totalRows} <b>·</b> Page {pageIndex + 1} / {pageCount}</span>
      <button
        className="ghost-button"
        onClick={() => onPageChange(Math.min(pageCount - 1, pageIndex + 1))}
        disabled={loading || pageIndex >= pageCount - 1}
      >
        Next
      </button>
    </div>
  );
}

function BehaviorGraphView({
  graph,
  onNodeClick,
}: {
  graph: BehaviorGraph;
  onNodeClick: (node: GraphNode) => void;
}) {
  const positions = useMemo(() => {
    const result = new Map<string, { x: number; y: number }>();
    const columns: GraphNode["kind"][] = ["process", "connection"];
    const xByKind: Record<GraphNode["kind"], number> = {
      process: 120,
      connection: 380,
      domain: 650,
      file: 650,
    };
    for (const kind of columns) {
      const nodes = graph.nodes.filter((node) => node.kind === kind).slice(0, kind === "process" ? 4 : 5);
      nodes.forEach((node, index) => {
        result.set(node.id, { x: xByKind[kind], y: 44 + index * 52 });
      });
    }
    graph.nodes
      .filter((node) => node.kind === "domain" || node.kind === "file")
      .slice(0, 6)
      .forEach((node, index) => {
        result.set(node.id, { x: 650, y: 44 + index * 46 });
      });
    return result;
  }, [graph.nodes]);
  if (graph.nodes.length === 0) {
    return <div className="graph-empty"><span>⌘</span><p>关系图会在进程产生网络、域名或文件事件后出现。</p></div>;
  }
  const visibleEdges = graph.edges.filter((edge) => positions.has(edge.source) && positions.has(edge.target));
  return (
    <div className="graph-canvas" role="img" aria-label="Process behavior graph">
      <svg viewBox="0 0 780 330" preserveAspectRatio="xMidYMid meet">
        <defs>
          <marker id="graph-arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
            <path d="M0,0 L0,6 L7,3 z" fill="#45606b" />
          </marker>
        </defs>
        {visibleEdges.map((edge) => {
          const source = positions.get(edge.source);
          const target = positions.get(edge.target);
          if (!source || !target) return null;
          return (
            <g key={edge.id} className="graph-edge">
              <line x1={source.x} y1={source.y} x2={target.x} y2={target.y} markerEnd="url(#graph-arrow)" />
              <text x={(source.x + target.x) / 2} y={(source.y + target.y) / 2 - 5}>{edge.relation}</text>
            </g>
          );
        })}
        {graph.nodes.map((node) => {
          const position = positions.get(node.id);
          if (!position) return null;
          const label = node.label.length > 24 ? `${node.label.slice(0, 22)}…` : node.label;
          return (
            <g
              key={node.id}
              className={`graph-node graph-node-${node.kind}`}
              transform={`translate(${position.x}, ${position.y})`}
              tabIndex={0}
              role="button"
              aria-label={`${node.kind}: ${node.label}`}
              onClick={() => onNodeClick(node)}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") onNodeClick(node);
              }}
            >
              <rect x="-92" y="-20" width="184" height="40" rx="9" />
              <text className="graph-node-kind" x="-80" y="-5">{node.kind.toUpperCase()}</text>
              <text className="graph-node-label" x="-80" y="11">{label}</text>
              {node.risk_score > 0 && <text className="graph-node-risk" x="78" y="-5">R{Math.round(node.risk_score)}</text>}
              <title>{node.label}{node.risk_score > 0 ? ` · risk ${Math.round(node.risk_score)}` : ""}</title>
            </g>
          );
        })}
      </svg>
      <div className="graph-legend">
        <span><i className="legend-dot legend-process" />Process</span>
        <span><i className="legend-dot legend-connection" />Connection</span>
        <span><i className="legend-dot legend-domain" />Domain</span>
        <span><i className="legend-dot legend-file" />File</span>
      </div>
    </div>
  );
}

function stateLabel(state: string): string {
  return state
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function timelineKindLabel(kind: string): string {
  if (kind === "http") return "HTTP";
  return kind
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function timelineDetail(entry: TimelineEntry): string {
  if (entry.file_path) {
    return `${entry.file_path}${entry.file_bytes ? ` · ${formatBytes(entry.file_bytes)}` : ""}`;
  }
  if (entry.http_direction) {
    if (entry.http_direction === "request") {
      const target = entry.http_target ?? "?";
      const host = entry.http_host ? ` · Host ${entry.http_host}` : "";
      const headers = entry.http_headers?.length ? ` · ${entry.http_headers.length} headers` : "";
      const body = entry.http_content_length !== null && entry.http_content_length !== undefined
        ? ` · ${formatBytes(entry.http_content_length)}`
        : "";
      return `${entry.http_method ?? "?"} ${target}${host}${headers}${body}`;
    }
    const reason = entry.http_reason ? ` ${entry.http_reason}` : "";
    const headers = entry.http_headers?.length ? ` · ${entry.http_headers.length} headers` : "";
    const body = entry.http_content_length !== null && entry.http_content_length !== undefined
      ? ` · ${formatBytes(entry.http_content_length)}`
      : "";
    return `${entry.http_status ?? "?"}${reason}${headers}${body}`;
  }
  if (entry.plaintext !== null && entry.plaintext !== undefined) {
    const direction = entry.plaintext_direction ? stateLabel(entry.plaintext_direction) : "Plaintext";
    return `${direction}: ${entry.plaintext}${entry.plaintext_truncated ? " · truncated" : ""}`;
  }
  if (entry.addresses.length > 0) return entry.addresses.join(", ");
  if (entry.remote) return `${entry.remote.address}:${entry.remote.port}`;
  if (entry.tls_sni) return `SNI ${entry.tls_sni}${entry.tls_version ? ` · ${entry.tls_version}` : ""}`;
  if (entry.tls_version) return `TLS ${entry.tls_version}`;
  return entry.domain ?? entry.protocol ?? "metadata event";
}

function App() {
  const [snapshot, setSnapshot] = useState<Snapshot>(initialSnapshot);
  const [refreshing, setRefreshing] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [refreshError, setRefreshError] = useState<string | null>(null);
  const [showClosedConnections, setShowClosedConnections] = useState(false);
  const [timelineKind, setTimelineKind] = useState("all");
  const [timelinePidInput, setTimelinePidInput] = useState("");
  const [timelinePid, setTimelinePid] = useState("");
  const [timelineConnectionInput, setTimelineConnectionInput] = useState("");
  const [timelineConnection, setTimelineConnection] = useState("");
  const [observationBusyPid, setObservationBusyPid] = useState<number | null>(null);
  const [observationError, setObservationError] = useState<string | null>(null);
  const [selectedConnectionId, setSelectedConnectionId] = useState<string | null>(null);
  const [connectionEventsLoadingId, setConnectionEventsLoadingId] = useState<string | null>(null);
  const [processSort, setProcessSort] = useState<SortState<ProcessSortKey>>({ key: "connections", direction: "desc" });
  const [processPageIndex, setProcessPageIndex] = useState(0);
  const [connectionSort, setConnectionSort] = useState<SortState<ConnectionSortKey>>({ key: "last_seen", direction: "desc" });
  const [connectionTimelineOffset, setConnectionTimelineOffset] = useState(0);
  const [connectionPageIndex, setConnectionPageIndex] = useState(0);
  const [timelineOffset, setTimelineOffset] = useState(0);
  const [selectedConnectionCache, setSelectedConnectionCache] = useState<ConnectionTimeline | null>(null);
  const refreshingRef = useRef(false);

  const timelineRequestPath = useMemo(
    () => buildTimelinePath(timelineKind, timelinePid, timelineConnection, timelineOffset),
    [timelineConnection, timelineKind, timelineOffset, timelinePid],
  );
  const connectionTimelineRequestPath = useMemo(
    () => buildConnectionTimelinePath(connectionTimelineOffset, showClosedConnections),
    [connectionTimelineOffset, showClosedConnections],
  );

  const refresh = useCallback(async () => {
    if (refreshingRef.current) return;
    refreshingRef.current = true;
    setRefreshing(true);
    setRefreshError(null);
    try {
      const [summary, processes, connections, connectionTimeline, timeline, alerts, graph] = await Promise.all([
        fetchJson<Summary>("/api/summary"),
        fetchJson<ProcessRow[]>("/api/processes"),
        fetchJson<ConnectionRow[]>("/api/connections"),
        fetchJson<ConnectionTimelinePage>(connectionTimelineRequestPath),
        fetchJson<TimelinePage>(timelineRequestPath),
        fetchJson<AlertRow[]>('/api/alerts?limit=100'),
        fetchJson<BehaviorGraph>('/api/graph'),
      ]);
      setSnapshot((current) => ({
        summary,
        processes,
        connections,
        connection_timeline: {
          ...connectionTimeline,
          sessions: connectionTimeline.sessions.map((session) => {
            const previous = current.connection_timeline.sessions.find((item) => item.id === session.id);
            return previous && previous.events.length > session.events.length
              ? { ...session, events: previous.events }
              : session;
          }),
        },
        timeline,
        alerts,
        graph,
        mode: "live",
      }));
      setSelectedConnectionCache((current) => {
        if (!current) return null;
        return connectionTimeline.sessions.find((session) => session.id === current.id) ?? current;
      });
      setConnectionTimelineOffset(connectionTimeline.offset);
      setTimelineOffset(timeline.offset);
      setLastUpdated(new Date());
    } catch {
      setRefreshError("Core 暂时不可用，保留当前画面");
      setSnapshot((current) => ({ ...current, mode: current.mode === "live" ? "live" : "demo" }));
    } finally {
      refreshingRef.current = false;
      setRefreshing(false);
    }
  }, [connectionTimelineRequestPath, timelineRequestPath]);

  const loadConnectionEvents = useCallback(async (connectionId: string) => {
    setConnectionEventsLoadingId(connectionId);
    try {
      const detail = await fetchJson<ConnectionTimelinePage>(buildConnectionDetailPath(connectionId));
      const session = detail.sessions.find((item) => item.id === connectionId);
      if (session) {
        setSelectedConnectionCache(session);
        setSnapshot((current) => ({
          ...current,
          connection_timeline: {
            ...current.connection_timeline,
            sessions: current.connection_timeline.sessions.map((item) => item.id === connectionId ? session : item),
          },
        }));
      }
    } catch {
      // Keep the session summary visible if the detail request fails.
    } finally {
      setConnectionEventsLoadingId(null);
    }
  }, []);

  const toggleConnectionSession = useCallback((session: ConnectionTimeline) => {
    if (selectedConnectionId === session.id) {
      setSelectedConnectionId(null);
      setSelectedConnectionCache(null);
      return;
    }
    setSelectedConnectionId(session.id);
    setSelectedConnectionCache(session);
    if (snapshot.mode === "live" && session.event_count > 0 && session.events.length === 0) {
      void loadConnectionEvents(session.id);
    }
  }, [loadConnectionEvents, selectedConnectionId, snapshot.mode]);

  const applyTimelineFilters = useCallback(() => {
    setTimelinePid(timelinePidInput.trim());
    setTimelineConnection(timelineConnectionInput.trim());
    setTimelineOffset(0);
  }, [timelineConnectionInput, timelinePidInput]);

  const resetTimelineFilters = useCallback(() => {
    setTimelineKind("all");
    setTimelinePidInput("");
    setTimelinePid("");
    setTimelineConnectionInput("");
    setTimelineConnection("");
    setTimelineOffset(0);
  }, []);

  const setObservationLevel = useCallback(async (pid: number, level: string) => {
    setObservationBusyPid(pid);
    setObservationError(null);
    try {
      const numericLevel = Number(level.replace(/^L/i, ""));
      if (!Number.isInteger(numericLevel) || numericLevel < 1 || numericLevel > 5) {
        throw new Error("invalid observation level");
      }
      const response = await fetch(`${API_BASE}/api/observations`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: `process:${pid}`, level: numericLevel, exact: true }),
      });
      if (!response.ok) {
        const message = await response.text();
        throw new Error(message || `observation command: ${response.status}`);
      }
      await refresh();
    } catch (error) {
      setObservationError(error instanceof Error ? error.message : "observation command failed");
    } finally {
      setObservationBusyPid(null);
    }
  }, [refresh]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    if (!autoRefresh) return undefined;
    const timer = window.setInterval(() => void refresh(), 5000);
    return () => window.clearInterval(timer);
  }, [autoRefresh, refresh]);

  useEffect(() => {
    if (!selectedConnectionId) return undefined;
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setSelectedConnectionId(null);
        setSelectedConnectionCache(null);
      }
    };
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [selectedConnectionId]);

  const processNames = useMemo(
    () => new Map(snapshot.processes.map((process) => [process.pid, process.name])),
    [snapshot.processes],
  );
  const sortedProcesses = useMemo(() => {
    const rows = snapshot.processes.slice();
    rows.sort((left, right) => {
      const valueFor = (process: ProcessRow): string | number => {
        switch (processSort.key) {
          case "name": return process.name;
          case "pid": return process.pid;
          case "connections": return process.connections;
          case "traffic": return process.sent_bytes + process.received_bytes;
          case "level": return process.level;
          case "risk": return process.risk_score ?? 0;
        }
      };
      const result = compareSortableValues(valueFor(left), valueFor(right));
      if (result !== 0) return processSort.direction === "asc" ? result : -result;
      return left.pid - right.pid;
    });
    return rows;
  }, [processSort, snapshot.processes]);
  const processPageCount = Math.max(1, Math.ceil(sortedProcesses.length / PROCESS_PAGE_SIZE));
  const currentProcessPage = Math.min(processPageIndex, processPageCount - 1);
  const pagedProcesses = sortedProcesses.slice(
    currentProcessPage * PROCESS_PAGE_SIZE,
    (currentProcessPage + 1) * PROCESS_PAGE_SIZE,
  );
  useEffect(() => {
    setProcessPageIndex((page) => Math.min(page, processPageCount - 1));
  }, [processPageCount]);
  const visibleConnections = useMemo(
    () => {
      const rows = (showClosedConnections
        ? snapshot.connections
        : snapshot.connections.filter((connection) => connection.state !== "closed"))
        .slice();
      rows.sort((left, right) => {
        const processLabel = (connection: ConnectionRow) => connection.process_name
          ?? (connection.pid ? processNames.get(connection.pid) ?? `exited (${connection.pid})` : "unknown");
        const valueFor = (connection: ConnectionRow): string | number => {
          switch (connectionSort.key) {
            case "process": return processLabel(connection);
            case "pid": return connection.pid ?? -1;
            case "remote": return `${connection.remote.address}:${connection.remote.port}`;
            case "domain": return connection.domain ?? "";
            case "state": return connection.tcp_state ?? connection.state;
            case "traffic": return connection.sent_bytes + connection.received_bytes;
            case "last_seen": return connection.last_seen_ns ?? connection.first_seen_ns ?? 0;
            case "risk": return connection.risk_score ?? 0;
          }
        };
        const result = compareSortableValues(valueFor(left), valueFor(right));
        if (result !== 0) return connectionSort.direction === "asc" ? result : -result;
        return left.id.localeCompare(right.id);
      });
      return rows;
    },
    [connectionSort, processNames, showClosedConnections, snapshot.connections],
  );
  const connectionPageCount = Math.max(1, Math.ceil(visibleConnections.length / CONNECTION_PAGE_SIZE));
  const currentConnectionPage = Math.min(connectionPageIndex, connectionPageCount - 1);
  const pagedConnections = visibleConnections.slice(
    currentConnectionPage * CONNECTION_PAGE_SIZE,
    (currentConnectionPage + 1) * CONNECTION_PAGE_SIZE,
  );
  useEffect(() => {
    setConnectionPageIndex((page) => Math.min(page, connectionPageCount - 1));
  }, [connectionPageCount]);
  const timelinePageCount = Math.max(1, Math.ceil(snapshot.timeline.total / Math.max(1, snapshot.timeline.limit)));
  const currentTimelinePage = Math.min(
    Math.floor(snapshot.timeline.offset / Math.max(1, snapshot.timeline.limit)),
    timelinePageCount - 1,
  );
  const connectionTimelinePageSize = Math.max(1, snapshot.connection_timeline.limit);
  const connectionTimelinePageCount = Math.max(
    1,
    Math.ceil(snapshot.connection_timeline.total / connectionTimelinePageSize),
  );
  const currentConnectionTimelinePage = Math.min(
    Math.floor(snapshot.connection_timeline.offset / connectionTimelinePageSize),
    connectionTimelinePageCount - 1,
  );
  const visibleConnectionSessions = useMemo(
    () => showClosedConnections
      ? snapshot.connection_timeline.sessions
      : snapshot.connection_timeline.sessions.filter((session) => session.state !== "closed"),
    [showClosedConnections, snapshot.connection_timeline.sessions],
  );
  const focusConnection = useCallback((connectionId: string) => {
    setSelectedConnectionId(connectionId);
    const session = snapshot.connection_timeline.sessions.find((item) => item.id === connectionId);
    if (session) setSelectedConnectionCache(session);
    if (snapshot.mode === "live" && (!session || session.event_count > 0 && session.events.length === 0)) {
      void loadConnectionEvents(connectionId);
    }
    setTimelineConnectionInput(connectionId);
    setTimelineConnection(connectionId);
  }, [loadConnectionEvents, snapshot.connection_timeline.sessions, snapshot.mode]);
  const selectedConnection = useMemo(
    () => selectedConnectionId
      ? snapshot.connection_timeline.sessions.find((session) => session.id === selectedConnectionId) ?? selectedConnectionCache
      : null,
    [selectedConnectionCache, selectedConnectionId, snapshot.connection_timeline.sessions],
  );
  const changeProcessSort = useCallback((column: ProcessSortKey) => {
    setProcessSort((current) => nextSortState(current, column));
    setProcessPageIndex(0);
  }, []);
  const changeConnectionSort = useCallback((column: ConnectionSortKey) => {
    setConnectionSort((current) => nextSortState(current, column));
    setConnectionPageIndex(0);
  }, []);
  const isLive = snapshot.mode === "live";
  const statusText = isLive ? "Core connected" : "Core offline · demo data";
  const latestAlert = snapshot.alerts[0] ?? null;

  return (
    <main className="shell">
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark">◌</span>
          <span>TraceLens</span>
        </div>
        <div className={`runtime-status ${isLive ? "" : "offline"}`}>
          <span className="status-dot" />
          {statusText}
          <span className="refresh-status">{refreshing ? "syncing" : lastUpdated ? `updated ${lastUpdated.toLocaleTimeString()}` : "not synced"}</span>
          <label className="auto-refresh-toggle">
            <input type="checkbox" checked={autoRefresh} onChange={(event) => setAutoRefresh(event.target.checked)} />
            live refresh
          </label>
        </div>
      </header>

      <section className="hero">
        <div>
          <p className="eyebrow">PROCESS-AWARE NETWORK OBSERVATION</p>
          <h1>See the process behind every connection.</h1>
          <p className="hero-copy">
            A calm overview first. Deep inspection only when a process or
            connection earns your attention.
          </p>
        </div>
        <div className="hero-stat">
          <span className="stat-label">OBSERVATION LEVEL</span>
          <strong>{snapshot.summary.observation_level}</strong>
          <span>metadata only</span>
        </div>
      </section>

      <section className="metrics">
        <div className="metric-card"><span>Processes</span><strong>{snapshot.summary.processes}</strong><small>being observed</small></div>
        <div className="metric-card"><span>Connections</span><strong>{snapshot.summary.connections}</strong><small>active network edges</small></div>
        <div className="metric-card"><span>Domains</span><strong>{snapshot.summary.domains}</strong><small>correlated from DNS</small></div>
        <div className="metric-card alert-card"><span>Alerts</span><strong>{snapshot.summary.alerts}</strong><small>needs review</small></div>
      </section>

      <section className="content-grid">
        <div className="panel process-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">{isLive ? "LIVE INVENTORY" : "DEMO INVENTORY"}</p>
              <h2>Processes</h2>
            </div>
            <button className="ghost-button" onClick={() => void refresh()} disabled={refreshing}>
              {refreshing ? "Syncing…" : "Refresh"}
            </button>
          </div>
          {observationError && <p className="error-note">Observation change failed: {observationError}</p>}
          <div className="table-wrap process-table-wrap">
            <table>
              <thead>
                <tr>
                  <SortableHeader label="Process" column="name" sort={processSort} onSort={changeProcessSort} />
                  <SortableHeader label="PID" column="pid" sort={processSort} onSort={changeProcessSort} />
                  <SortableHeader label="Connections" column="connections" sort={processSort} onSort={changeProcessSort} />
                  <SortableHeader label="Traffic" column="traffic" sort={processSort} onSort={changeProcessSort} />
                  <SortableHeader label="Level" column="level" sort={processSort} onSort={changeProcessSort} />
                  <SortableHeader label="Risk" column="risk" sort={processSort} onSort={changeProcessSort} />
                  <th scope="col">Inspect</th>
                </tr>
              </thead>
              <tbody>
                {sortedProcesses.length === 0 ? (
                  <tr><td colSpan={7} className="muted empty-cell">No processes observed yet.</td></tr>
                ) : pagedProcesses.map((process) => (
                  <tr key={process.pid}>
                    <td><span className="process-name">{process.name}</span></td>
                    <td className="muted">{process.pid}</td>
                    <td>{process.connections}</td>
                    <td>{formatBytes(process.sent_bytes + process.received_bytes)}</td>
                    <td><span className={`level level-${process.level.toLowerCase()}`}>{process.level}</span></td>
                    <td><span className="risk-score">{process.risk_score ? Math.round(process.risk_score) : "—"}</span></td>
                    <td>
                      <select
                        className="observation-select"
                        value={process.level}
                        disabled={observationBusyPid === process.pid || !isLive}
                        onChange={(event) => void setObservationLevel(process.pid, event.target.value)}
                        aria-label={`Observation level for ${process.name} ${process.pid}`}
                      >
                        <option value="L1">L1 · metadata</option>
                        <option value="L2">L2 · reserved</option>
                        <option value="L3">L3 · TLS metadata</option>
                        <option value="L4">L4 · HTTP metadata</option>
                        <option value="L5">L5 · plaintext</option>
                      </select>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <TablePagination
            pageIndex={currentProcessPage}
            pageCount={processPageCount}
            totalRows={sortedProcesses.length}
            pageSize={PROCESS_PAGE_SIZE}
            loading={false}
            onPageChange={setProcessPageIndex}
          />
        </div>

        <div className="panel focus-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">FOCUS QUEUE</p>
              <h2>Needs attention</h2>
            </div>
            <span className="risk-pill">{snapshot.summary.alerts} signal{snapshot.summary.alerts === 1 ? "" : "s"}</span>
          </div>
          <div className="focus-content">
            <div className="focus-item">
              <div className="focus-icon">↗</div>
              <div>
                <strong>{latestAlert?.summary ?? (isLive ? "No active signals" : "Waiting for Core")}</strong>
                <p>{latestAlert ? `${latestAlert.rule} · risk ${Math.round(latestAlert.risk_score)}${latestAlert.domain ? ` · ${latestAlert.domain}` : ""}` : "Detection rules will appear here as the event pipeline observes traffic."}</p>
              </div>
              <button
                className="inspect-button"
                disabled={!latestAlert?.connection_id}
                onClick={() => latestAlert?.connection_id && focusConnection(latestAlert.connection_id)}
              >Inspect signal</button>
            </div>
            <div className="empty-note">
              <span>⌁</span>
              <p>Deep inspection is on-demand.<br />L4 keeps HTTP metadata only; L5 plaintext is capped at 512 B/event.</p>
            </div>
          </div>
        </div>
      </section>

      {refreshError && <p className="refresh-error">{refreshError}</p>}

      <section className="insight-grid">
        <div className="panel alert-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">DETECTION</p>
              <h2>Signals</h2>
            </div>
            <span className="connection-count">{snapshot.alerts.length} in memory</span>
          </div>
          <div className="alert-list">
            {snapshot.alerts.length === 0 ? (
              <div className="graph-empty alert-empty"><span>✓</span><p>No rule matched in the current runtime window.</p></div>
            ) : snapshot.alerts.slice(0, 6).map((alert) => (
              <button
                className="alert-row"
                key={alert.id}
                onClick={() => {
                  if (alert.connection_id) {
                    focusConnection(alert.connection_id);
                  } else if (alert.process_id) {
                    const pid = String(alert.process_id);
                    setTimelinePidInput(pid);
                    setTimelinePid(pid);
                    setTimelineOffset(0);
                  }
                }}
              >
                <span className={`severity severity-${alert.severity}`}>{alert.severity}</span>
                <span className="alert-row-body">
                  <strong>{alert.summary}</strong>
                  <small>{alert.rule} · risk {Math.round(alert.risk_score)}{alert.process_name ? ` · ${alert.process_name}` : ""}</small>
                </span>
                <span className="alert-row-arrow">›</span>
              </button>
            ))}
          </div>
        </div>
        <div className="panel graph-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">PHASE 12</p>
              <h2>Behavior graph</h2>
            </div>
            <span className="connection-count">{snapshot.graph.nodes.length} nodes · {snapshot.graph.edges.length} links</span>
          </div>
          <BehaviorGraphView
            graph={snapshot.graph}
            onNodeClick={(node) => {
              if (node.connection_id) {
                focusConnection(node.connection_id);
              } else if (node.pid) {
                setTimelinePidInput(String(node.pid));
                setTimelinePid(String(node.pid));
                setTimelineOffset(0);
              }
            }}
          />
        </div>
      </section>

      <section className="panel connection-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">{isLive ? "KERNEL EVENTS" : "DEMO EVENTS"}</p>
            <h2>Connections</h2>
          </div>
          <div className="connection-controls">
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={showClosedConnections}
                onChange={(event) => {
                  setShowClosedConnections(event.target.checked);
                  setConnectionTimelineOffset(0);
                  setConnectionPageIndex(0);
                }}
              />
              Show closed
            </label>
            <span className="connection-count">
              {showClosedConnections ? `${visibleConnections.length} observed` : `${visibleConnections.length} active`}
            </span>
          </div>
        </div>
        <div className="table-wrap connection-table-wrap">
          <table>
            <thead>
              <tr>
                <SortableHeader label="Process" column="process" sort={connectionSort} onSort={changeConnectionSort} />
                <SortableHeader label="PID" column="pid" sort={connectionSort} onSort={changeConnectionSort} />
                <SortableHeader label="Remote" column="remote" sort={connectionSort} onSort={changeConnectionSort} />
                <SortableHeader label="Domain" column="domain" sort={connectionSort} onSort={changeConnectionSort} />
                <SortableHeader label="State" column="state" sort={connectionSort} onSort={changeConnectionSort} />
                <SortableHeader label="Traffic" column="traffic" sort={connectionSort} onSort={changeConnectionSort} />
                <SortableHeader label="Updated" column="last_seen" sort={connectionSort} onSort={changeConnectionSort} />
                <SortableHeader label="Risk" column="risk" sort={connectionSort} onSort={changeConnectionSort} />
                <th scope="col">Trace</th>
              </tr>
            </thead>
            <tbody>
              {visibleConnections.length === 0 ? (
                <tr><td colSpan={9} className="muted empty-cell">
                  {showClosedConnections ? "No connections observed yet." : "No active connections. Enable Show closed to inspect history."}
                </td></tr>
              ) : pagedConnections.map((connection) => (
                <tr key={connection.id}>
                  <td><span className="process-name">{connection.process_name ?? (connection.pid ? processNames.get(connection.pid) ?? `exited (${connection.pid})` : "unknown")}</span></td>
                  <td className="muted">{connection.pid ?? "—"}</td>
                  <td>{connection.remote.address}:{connection.remote.port}</td>
                  <td className="muted">{connection.domain ?? "—"}</td>
                  <td><span className={`state state-${connection.state}`}>{stateLabel(connection.tcp_state ?? connection.state)}</span></td>
                  <td>{formatBytes(connection.sent_bytes + connection.received_bytes)}</td>
                  <td className="muted">{formatClock(connection.last_seen_ns ?? connection.first_seen_ns)}</td>
                  <td><span className="risk-score">{connection.risk_score ? Math.round(connection.risk_score) : "—"}</span></td>
                  <td>
                    <button
                      className="trace-button"
                      title={connection.id}
                      onClick={() => focusConnection(connection.id)}
                    >
                      View
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
            </table>
          </div>
        <TablePagination
          pageIndex={currentConnectionPage}
          pageCount={connectionPageCount}
          totalRows={visibleConnections.length}
          pageSize={CONNECTION_PAGE_SIZE}
          loading={false}
          onPageChange={setConnectionPageIndex}
        />
      </section>

      <section className="panel connection-timeline-panel">
        <div className="panel-heading connection-timeline-heading">
          <div>
            <p className="eyebrow">CONNECTION ACTIVITY</p>
            <h2>Sessions</h2>
          </div>
          <span className="connection-count">
            {showClosedConnections ? `${snapshot.connection_timeline.total} observed` : `${snapshot.connection_timeline.total} active`}
          </span>
        </div>
        <div className="session-list">
          {visibleConnectionSessions.length === 0 ? (
            <p className="muted empty-cell">No connection sessions observed yet.</p>
          ) : visibleConnectionSessions.map((session) => {
            const processLabel = session.process_name ?? (session.pid ? `exited (${session.pid})` : "unknown process");
            const remoteLabel = `${session.domain ?? session.remote.address}:${session.remote.port}`;
            return (
              <article className="connection-session" id={`connection-session-${encodeURIComponent(session.id)}`} key={session.id}>
                <div className="session-heading">
                  <div className="session-route">
                    <span className="process-name">{processLabel}</span>
                    {session.pid !== null && <span className="muted">PID {session.pid}</span>}
                    <span className="session-arrow">→</span>
                    <strong>{remoteLabel}</strong>
                  </div>
                  <span className={`state state-${session.state}`}>{stateLabel(session.tcp_state ?? session.state)}</span>
                </div>
                <div className="session-meta">
                  <span>{session.protocol.toUpperCase()}</span>
                  <span>{formatDuration(session.duration_ns)}</span>
                  <span>↑ {formatBytes(session.sent_bytes)}</span>
                  <span>↓ {formatBytes(session.received_bytes)}</span>
                  <span>{session.event_count} events</span>
                  {(session.tls_sni || session.tls_version) && (
                    <span className="tls-badge">
                      TLS {session.tls_sni ?? "—"}{session.tls_version ? ` · ${session.tls_version}` : ""}
                    </span>
                  )}
                  <button
                    className="trace-button"
                    title={session.id}
                    onClick={() => toggleConnectionSession(session)}
                  >
                    Open details
                  </button>
                </div>
                <div className="session-id">{session.id} · started {formatTimestamp(session.first_seen_ns, session.first_seen_ns)}</div>
              </article>
            );
          })}
        </div>
        <TablePagination
          pageIndex={currentConnectionTimelinePage}
          pageCount={connectionTimelinePageCount}
          totalRows={snapshot.connection_timeline.total}
          pageSize={connectionTimelinePageSize}
            loading={false}
          onPageChange={(page) => setConnectionTimelineOffset(page * connectionTimelinePageSize)}
        />
      </section>

      {selectedConnection && (
        <div
          className="modal-backdrop"
          role="presentation"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) {
              setSelectedConnectionId(null);
              setSelectedConnectionCache(null);
            }
          }}
        >
          <section
            className="session-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="session-modal-title"
            onMouseDown={(event) => event.stopPropagation()}
          >
            <div className="modal-heading">
              <div>
                <p className="eyebrow">SESSION DETAILS</p>
                <h2 id="session-modal-title">
                  {selectedConnection.process_name ?? (selectedConnection.pid ? `exited (${selectedConnection.pid})` : "unknown process")}
                  <span className="session-arrow"> → </span>
                  {selectedConnection.domain ?? selectedConnection.remote.address}:{selectedConnection.remote.port}
                </h2>
                <p className="modal-subtitle">
                  {selectedConnection.pid !== null && `PID ${selectedConnection.pid} · `}
                  {selectedConnection.id}
                </p>
              </div>
              <div className="modal-actions">
                <button
                  className="ghost-button"
                  onClick={() => void loadConnectionEvents(selectedConnection.id)}
                  disabled={connectionEventsLoadingId === selectedConnection.id || snapshot.mode !== "live"}
                >
                  {connectionEventsLoadingId === selectedConnection.id ? "Loading" : "Refresh details"}
                </button>
                <button
                  className="modal-close"
                  aria-label="Close session details"
                  onClick={() => {
                    setSelectedConnectionId(null);
                    setSelectedConnectionCache(null);
                  }}
                >
                  ×
                </button>
              </div>
            </div>
            <div className="modal-meta">
              <span className={`state state-${selectedConnection.state}`}>{stateLabel(selectedConnection.tcp_state ?? selectedConnection.state)}</span>
              <span>{selectedConnection.protocol.toUpperCase()}</span>
              <span>{formatDuration(selectedConnection.duration_ns)}</span>
              <span>↑ {formatBytes(selectedConnection.sent_bytes)}</span>
              <span>↓ {formatBytes(selectedConnection.received_bytes)}</span>
              <span>{selectedConnection.event_count} events</span>
            </div>
            {connectionEventsLoadingId === selectedConnection.id ? (
              <p className="muted session-events-empty">Loading session events…</p>
            ) : selectedConnection.events.length === 0 ? (
              <p className="muted session-events-empty">No event details available.</p>
            ) : (
              <div className="session-events modal-events">
                {selectedConnection.events.length < selectedConnection.event_count && (
                  <p className="muted session-events-note">Showing the latest {selectedConnection.events.length} of {selectedConnection.event_count} events.</p>
                )}
                {selectedConnection.events.map((event) => (
                  <div className="session-event" key={event.id}>
                    <time>{formatTimestamp(event.timestamp_ns, selectedConnection.first_seen_ns)}</time>
                    <span className={`timeline-marker timeline-marker-${event.kind}`} />
                    <div>
                      <div className="timeline-meta">
                        <span className="timeline-kind">{timelineKindLabel(event.kind)}</span>
                      </div>
                  <strong>{event.summary}</strong>
                      <p>{timelineDetail(event)}</p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>
        </div>
      )}

      <section className="panel timeline-panel">
        <div className="panel-heading timeline-heading">
          <div>
            <p className="eyebrow">ADVANCED VIEW</p>
            <h2>Raw events</h2>
          </div>
          <div className="timeline-toolbar">
            <label className="timeline-filter">
              <span>Event</span>
              <select
                value={timelineKind}
                onChange={(event) => {
                  setTimelineKind(event.target.value);
                  setTimelineOffset(0);
                }}
              >
                <option value="all">All events</option>
                <option value="process_exec">Process start</option>
                <option value="process_exit">Process exit</option>
                <option value="dns_query">DNS query</option>
                <option value="dns_response">DNS response</option>
                <option value="tcp_connect">TCP connect</option>
                <option value="tcp_state_changed">TCP state</option>
                <option value="tcp_bytes">TCP bytes</option>
                <option value="tcp_close">TCP close</option>
                <option value="tls_metadata">TLS metadata</option>
                <option value="plaintext">Plaintext (L5)</option>
                <option value="http">HTTP (L4)</option>
                <option value="file_open">File open</option>
                <option value="file_read">File read</option>
              </select>
            </label>
            <label className="timeline-filter">
              <span>PID</span>
              <input
                inputMode="numeric"
                placeholder="Any"
                value={timelinePidInput}
                onChange={(event) => setTimelinePidInput(event.target.value.replace(/\D/g, ""))}
                onKeyDown={(event) => {
                  if (event.key === "Enter") applyTimelineFilters();
                }}
              />
            </label>
            <label className="timeline-filter">
              <span>Connection</span>
              <input
                placeholder="Any"
                value={timelineConnectionInput}
                onChange={(event) => setTimelineConnectionInput(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter") {
                    setTimelineConnection(timelineConnectionInput.trim());
                    setTimelineOffset(0);
                  }
                }}
              />
            </label>
            <button className="ghost-button" onClick={applyTimelineFilters} disabled={refreshing}>Apply</button>
            <button className="ghost-button" onClick={resetTimelineFilters} disabled={refreshing}>Reset</button>
          </div>
          <span className="connection-count">{snapshot.timeline.total} matching events</span>
        </div>
        <div className="timeline-list">
          {snapshot.timeline.entries.length === 0 ? (
            <p className="muted empty-cell">No timeline events observed yet.</p>
          ) : snapshot.timeline.entries.slice().reverse().map((entry) => (
            <article className="timeline-item" key={entry.id}>
              <time className="timeline-time">
                {formatTimestamp(entry.timestamp_ns, snapshot.timeline.entries[0]?.timestamp_ns ?? entry.timestamp_ns)}
              </time>
              <span className={`timeline-marker timeline-marker-${entry.kind}`} />
              <div className="timeline-content">
                <div className="timeline-meta">
                  <span className="timeline-kind">{timelineKindLabel(entry.kind)}</span>
                  {entry.process_name && <span className="muted">{entry.process_name}</span>}
                  {entry.pid !== null && <span className="muted">PID {entry.pid}</span>}
                </div>
                <strong>{entry.summary}</strong>
                <p>{timelineDetail(entry)}</p>
              </div>
            </article>
          ))}
        </div>
        <TablePagination
          pageIndex={currentTimelinePage}
          pageCount={timelinePageCount}
          totalRows={snapshot.timeline.total}
          pageSize={Math.max(1, snapshot.timeline.limit)}
          loading={false}
          onPageChange={(page) => setTimelineOffset(page * Math.max(1, snapshot.timeline.limit))}
        />
      </section>
    </main>
  );
}

export default App;
