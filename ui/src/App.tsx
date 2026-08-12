import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

type Summary = {
  processes: number;
  connections: number;
  domains: number;
  capture_profile: CaptureProfile;
  capture_modules: CaptureModule[];
  capture_state: "stopped" | "capturing";
  capture_target: string;
  event_count: number;
};

type ProcessCandidate = {
  pid: number;
  name: string;
  command_line: string | null;
};

type TlsCapability = {
  provider: string;
  library: string;
  version_hint: string | null;
  symbols: string[];
  supported: boolean;
  reason: string | null;
};

type RuntimeHealth = {
  tls_capabilities: TlsCapability[];
};

type ProcessRow = {
  pid: number;
  name: string;
  command_line: string | null;
  connections: number;
  sent_bytes: number;
  received_bytes: number;
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

type TimelineEntry = {
  id: string;
  timestamp_ns: number;
  source: string;
  tls_provider?: string | null;
  tls_library?: string | null;
  tls_api_function?: string | null;
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
  plaintext_skipped?: boolean;
  plaintext_skip_reason?: string | null;
  http_direction?: string | null;
  http_stream_id?: string | null;
  http_version?: string | null;
  http_method?: string | null;
  http_target?: string | null;
  http_host?: string | null;
  http_status?: number | null;
  http_reason?: string | null;
  http_headers?: Array<{ name: string; value: string }>;
  http_content_length?: number | null;
  http_body_preview?: string | null;
  http_body_bytes?: number;
  http_body_truncated?: boolean;
  http_payload_skipped?: boolean;
  http_payload_skip_reason?: string | null;
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

type HttpTransaction = {
  id: string;
  request: TimelineEntry | null;
  response: TimelineEntry | null;
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
  mode: "demo" | "live";
};

const IS_DESKTOP = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
const API_BASE = import.meta.env.VITE_CORE_API_URL ?? (IS_DESKTOP ? "http://127.0.0.1:8080" : "");
const PROCESS_PAGE_SIZE = 8;
const CONNECTION_PAGE_SIZE = 20;
const TIMELINE_PAGE_SIZE = 50;

type SortDirection = "asc" | "desc";
type ProcessSortKey = "name" | "pid" | "connections" | "traffic";
type ConnectionSortKey = "process" | "pid" | "remote" | "domain" | "state" | "traffic" | "last_seen";
type ProcessColumnKey = ProcessSortKey;
type ConnectionColumnKey = ConnectionSortKey | "trace";
type WorkspaceView = "http" | "processes" | "connections" | "timeline";

type DesktopStatus = {
  core_ready: boolean;
  managed_by_desktop: boolean;
  api_url: string;
  message: string;
};

type DesktopBootState =
  | { phase: "browser" | "starting" | "ready"; message: string }
  | { phase: "error"; message: string };

type SortState<Key extends string> = {
  key: Key;
  direction: SortDirection;
};

type ScrollAnchor = {
  key: string;
  offset: number;
};

type ScrollContainerSnapshot = {
  element: HTMLDivElement;
  top: number;
  left: number;
  atStart: boolean;
  anchor: ScrollAnchor | null;
};

type ScrollSnapshot = {
  windowX: number;
  windowY: number;
  containers: ScrollContainerSnapshot[];
};

type CaptureTargetSelection = {
  mode: "pid" | "name" | "global";
  pid?: string;
  name?: string;
};

type CaptureProfile = "process" | "connections" | "network" | "web" | "security" | "custom";
type CaptureModule = "process" | "connections" | "traffic" | "dns" | "files" | "tls" | "http" | "plaintext";

const captureProfiles: Array<{ id: CaptureProfile; label: string; modules: CaptureModule[] }> = [
  { id: "process", label: "Process", modules: ["process"] },
  { id: "connections", label: "Connections", modules: ["process", "connections"] },
  { id: "network", label: "Network", modules: ["process", "connections", "traffic", "dns"] },
  { id: "web", label: "Web", modules: ["process", "connections", "traffic", "dns", "tls", "http"] },
  { id: "security", label: "Security", modules: ["process", "connections", "traffic", "dns", "tls", "files"] },
  { id: "custom", label: "Custom", modules: [] },
];

const captureModuleOptions: Array<{ id: CaptureModule; label: string; hint: string }> = [
  { id: "process", label: "Process lifecycle", hint: "exec and exit" },
  { id: "connections", label: "Connections", hint: "TCP endpoints and state" },
  { id: "traffic", label: "Traffic counters", hint: "sent and received bytes" },
  { id: "dns", label: "DNS", hint: "queries and domain correlation" },
  { id: "tls", label: "TLS metadata", hint: "provider, SNI and version" },
  { id: "http", label: "HTTP", hint: "metadata and bounded text preview" },
  { id: "plaintext", label: "Plaintext", hint: "sensitive raw TLS payload" },
  { id: "files", label: "File activity", hint: "openat security context" },
];

function closeModuleDependencies(modules: CaptureModule[]): CaptureModule[] {
  const selected = new Set(modules);
  if (selected.size > 0) selected.add("process");
  if (selected.has("traffic") || selected.has("dns") || selected.has("tls")) selected.add("connections");
  if (selected.has("http") || selected.has("plaintext")) {
    selected.add("tls");
    selected.add("connections");
  }
  return captureModuleOptions.map(({ id }) => id).filter((module) => selected.has(module));
}

const workspaceTabs: Array<{ id: WorkspaceView; label: string; hint: string }> = [
  { id: "http", label: "HTTP requests", hint: "request and response pairs" },
  { id: "connections", label: "Connections", hint: "network edges" },
  { id: "processes", label: "Processes", hint: "live inventory" },
  { id: "timeline", label: "Raw events", hint: "advanced view" },
];

const defaultProcessColumnWidths: Record<ProcessColumnKey, number> = {
  name: 190,
  pid: 90,
  connections: 110,
  traffic: 120,
};

const defaultConnectionColumnWidths: Record<ConnectionColumnKey, number> = {
  process: 180,
  pid: 80,
  remote: 180,
  domain: 180,
  state: 130,
  traffic: 130,
  last_seen: 130,
  trace: 100,
};

const demoSummary: Summary = {
  processes: 4,
  connections: 54,
  domains: 31,
  capture_profile: "network",
  capture_modules: ["process", "connections", "traffic", "dns"],
  capture_state: "capturing",
  capture_target: "global",
  event_count: 3,
};

const demoProcesses: ProcessRow[] = [
  { name: "chrome", pid: 4821, connections: 48, sent_bytes: 1_200_000, received_bytes: 1_600_000, command_line: null },
  { name: "curl", pid: 12345, connections: 1, sent_bytes: 8_000, received_bytes: 10_432, command_line: "curl https://example.com" },
  { name: "python3", pid: 9172, connections: 3, sent_bytes: 500_000_000, received_bytes: 0, command_line: "python3 uploader.py" },
  { name: "sshd", pid: 1061, connections: 2, sent_bytes: 0, received_bytes: 0, command_line: null },
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
  mode: "demo",
};

async function fetchJson<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`);
  if (!response.ok) {
    throw new Error(`${path}: ${response.status}`);
  }
  return response.json() as Promise<T>;
}

function parseCaptureTarget(target: string): CaptureTargetSelection {
  if (target === "global") return { mode: "global" };
  const pid = target.match(/^process:(\d+)$/)?.[1];
  if (pid) return { mode: "pid", pid };
  const name = target.match(/^process-name:(.+)$/)?.[1];
  if (name) return { mode: "name", name };
  return { mode: "global" };
}

function buildTimelinePath(kind: string, pid: string, connectionId: string, offset: number, includePlaintext: boolean): string {
  const params = new URLSearchParams({
    limit: String(TIMELINE_PAGE_SIZE),
    offset: String(offset),
    include_plaintext: String(includePlaintext),
  });
  if (kind !== "all") params.set("kind", kind);
  if (/^\d+$/.test(pid.trim())) params.set("pid", pid.trim());
  if (connectionId.trim()) params.set("connection_id", connectionId.trim());
  return `/api/timeline?${params.toString()}`;
}

function buildConnectionDetailPath(connectionId: string, includePlaintext: boolean): string {
  const params = new URLSearchParams({
    limit: "1",
    offset: "0",
    include_closed: "true",
    include_events: "true",
    event_limit: "200",
    connection_id: connectionId,
    include_plaintext: String(includePlaintext),
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

function ColumnResizer({
  label,
  onResizeStart,
}: {
  label: string;
  onResizeStart: (clientX: number) => void;
}) {
  return (
    <span
      className="column-resizer"
      role="separator"
      aria-label={`Resize ${label} column`}
      title={`Drag to resize ${label}`}
      onPointerDown={(event) => {
        event.preventDefault();
        event.stopPropagation();
        onResizeStart(event.clientX);
      }}
    />
  );
}

function SortableHeader<Key extends string>({
  label,
  column,
  sort,
  onSort,
  width,
  onResizeStart,
}: {
  label: string;
  column: Key;
  sort: SortState<Key>;
  onSort: (column: Key) => void;
  width?: number;
  onResizeStart?: (clientX: number) => void;
}) {
  const active = sort.key === column;
  return (
    <th
      scope="col"
      style={width ? { width: `${width}px` } : undefined}
      aria-sort={active ? (sort.direction === "asc" ? "ascending" : "descending") : "none"}
    >
      <button
        type="button"
        className={`sort-button ${active ? "active" : ""}`}
        onClick={() => onSort(column)}
        aria-label={`Sort by ${label}`}
      >
        <span>{label}</span>
        <span className="sort-indicator" aria-hidden="true">{active ? (sort.direction === "asc" ? "↑" : "↓") : "↕"}</span>
      </button>
      {onResizeStart && <ColumnResizer label={label} onResizeStart={onResizeStart} />}
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

function tlsProvenance(entry: TimelineEntry): string | null {
  if (!entry.tls_provider) return null;
  return `${entry.tls_provider}${entry.tls_api_function ? ` · ${entry.tls_api_function}` : ""}`;
}

function timelineDetail(entry: TimelineEntry): string {
  if (entry.file_path) {
    return `${entry.file_path}${entry.file_bytes ? ` · ${formatBytes(entry.file_bytes)}` : ""}`;
  }
  if (entry.http_direction) {
    const contentType = entry.http_headers?.find((header) => header.name.toLowerCase() === "content-type")?.value;
    const type = contentType ? ` · ${contentType}` : "";
    const bodyBytes = entry.http_body_bytes ? ` · body ${formatBytes(entry.http_body_bytes)} assembled` : "";
    const payload = entry.http_payload_skipped
      ? ` · payload skipped (${stateLabel(entry.http_payload_skip_reason ?? "unsupported")})`
      : bodyBytes;
    if (entry.http_direction === "request") {
      const target = entry.http_target ?? "?";
      const host = entry.http_host ? ` · Host ${entry.http_host}` : "";
      const headers = entry.http_headers?.length ? ` · ${entry.http_headers.length} headers` : "";
      const body = entry.http_content_length !== null && entry.http_content_length !== undefined
        ? ` · ${formatBytes(entry.http_content_length)}`
        : "";
      return `${entry.http_method ?? "?"} ${target}${host}${headers}${body}${type}${payload}`;
    }
    const reason = entry.http_reason ? ` ${entry.http_reason}` : "";
    const headers = entry.http_headers?.length ? ` · ${entry.http_headers.length} headers` : "";
    const body = entry.http_content_length !== null && entry.http_content_length !== undefined
      ? ` · ${formatBytes(entry.http_content_length)}`
      : "";
    return `${entry.http_status ?? "?"}${reason}${headers}${body}${type}${payload}`;
  }
  if (entry.plaintext !== null && entry.plaintext !== undefined) {
    const direction = entry.plaintext_direction ? stateLabel(entry.plaintext_direction) : "Plaintext";
    if (entry.plaintext_skipped) {
      return `${direction}: payload skipped (${stateLabel(entry.plaintext_skip_reason ?? "unsupported")}) · ${formatBytes(entry.plaintext_bytes ?? 0)}`;
    }
    return `${direction}: ${entry.plaintext}${entry.plaintext_truncated ? " · truncated" : ""}`;
  }
  if (entry.addresses.length > 0) return entry.addresses.join(", ");
  if (entry.remote) return `${entry.remote.address}:${entry.remote.port}`;
  if (entry.tls_sni) return `SNI ${entry.tls_sni}${entry.tls_version ? ` · ${entry.tls_version}` : ""}`;
  if (entry.tls_version) return `TLS ${entry.tls_version}`;
  return entry.domain ?? entry.protocol ?? "metadata event";
}

function timelineBody(entry: TimelineEntry): string | null {
  if (entry.http_payload_skipped || !entry.http_body_preview) return null;
  return entry.http_body_preview;
}

function canInspectPayload(entry: TimelineEntry): boolean {
  return Boolean(entry.http_direction || entry.kind === "http" || entry.kind === "plaintext");
}

function payloadContent(entry: TimelineEntry): string | null {
  if (entry.http_direction || entry.kind === "http") {
    return entry.http_payload_skipped ? null : entry.http_body_preview ?? null;
  }
  return entry.plaintext_skipped ? null : entry.plaintext ?? null;
}

function payloadTitle(entry: TimelineEntry): string {
  if (entry.http_direction === "request") {
    return `${entry.http_method ?? "HTTP"} ${entry.http_target ?? "/"}`;
  }
  if (entry.http_direction === "response") {
    return `HTTP ${entry.http_status ?? "?"}${entry.http_reason ? ` ${entry.http_reason}` : ""}`;
  }
  return `${stateLabel(entry.plaintext_direction ?? "plaintext")} payload`;
}

function payloadBytes(entry: TimelineEntry): number | null {
  return entry.http_body_bytes ?? entry.plaintext_bytes ?? null;
}

function httpBodyEmptyMessage(entry: TimelineEntry): string {
  if (entry.http_payload_skipped) {
    const reason = entry.http_payload_skip_reason ?? "unsupported";
    const messages: Record<string, string> = {
      binary_content: "Binary response body is intentionally hidden.",
      body_too_large: "Text body exceeds the 64 KB preview limit.",
      unsupported_content_type: "This response content type is not displayed as text.",
      unknown_content_type: "The response has no recognizable text content type.",
      unsupported_content_encoding: "This response uses an unsupported content encoding.",
      invalid_content_encoding: "The compressed response body could not be decoded.",
      unsupported_text_encoding: "The response character encoding is not supported.",
    };
    return messages[reason] ?? `Body skipped: ${stateLabel(reason)}.`;
  }
  if (entry.http_direction === "request" && ["GET", "HEAD", "DELETE", "OPTIONS"].includes(entry.http_method ?? "")) {
    return `${entry.http_method} requests normally do not contain a body.`;
  }
  if (entry.http_content_length === 0 || [204, 304].includes(entry.http_status ?? -1)) {
    return "This HTTP message has no body.";
  }
  return "No text body was captured for this HTTP message.";
}

function pairHttpTransactions(entries: TimelineEntry[]): HttpTransaction[] {
  const pending = new Map<string, TimelineEntry[]>();
  const transactions: HttpTransaction[] = [];

  entries
    .filter((entry) => entry.kind === "http" && entry.http_direction)
    .sort((left, right) => left.timestamp_ns - right.timestamp_ns)
    .forEach((entry) => {
      const key = entry.connection_id ?? entry.http_stream_id ?? `pid:${entry.pid ?? "unknown"}`;
      if (entry.http_direction === "request") {
        const requests = pending.get(key) ?? [];
        requests.push(entry);
        pending.set(key, requests);
        return;
      }

      const request = pending.get(key)?.shift() ?? null;
      transactions.push({
        id: request ? `${request.id}:${entry.id}` : entry.id,
        request,
        response: entry,
      });
    });

  pending.forEach((requests) => {
    requests.forEach((request) => transactions.push({ id: request.id, request, response: null }));
  });

  return transactions.sort((left, right) => {
    const leftTime = left.response?.timestamp_ns ?? left.request?.timestamp_ns ?? 0;
    const rightTime = right.response?.timestamp_ns ?? right.request?.timestamp_ns ?? 0;
    return rightTime - leftTime;
  });
}

function httpTransactionDuration(transaction: HttpTransaction): string {
  if (!transaction.request || !transaction.response) return "—";
  const milliseconds = Math.max(0, transaction.response.timestamp_ns - transaction.request.timestamp_ns) / 1_000_000;
  if (milliseconds < 1_000) return `${milliseconds.toFixed(milliseconds < 10 ? 1 : 0)} ms`;
  return `${(milliseconds / 1_000).toFixed(2)} s`;
}

function httpContentType(entry: TimelineEntry | null): string {
  const value = entry?.http_headers?.find((header) => header.name.toLowerCase() === "content-type")?.value;
  return value?.split(";", 1)[0] ?? "—";
}

function App() {
  const [desktopBoot, setDesktopBoot] = useState<DesktopBootState>(() => IS_DESKTOP
    ? { phase: "starting", message: "Waiting for administrator authorization…" }
    : { phase: "browser", message: "" });
  const [snapshot, setSnapshot] = useState<Snapshot>(initialSnapshot);
  const [refreshing, setRefreshing] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [refreshError, setRefreshError] = useState<string | null>(null);
  const [showClosedConnections, setShowClosedConnections] = useState(false);
  const [showPlaintextFragments, setShowPlaintextFragments] = useState(false);
  const [timelineKind, setTimelineKind] = useState("all");
  const [timelinePidInput, setTimelinePidInput] = useState("");
  const [timelinePid, setTimelinePid] = useState("");
  const [timelineConnectionInput, setTimelineConnectionInput] = useState("");
  const [timelineConnection, setTimelineConnection] = useState("");
  const [processCandidates, setProcessCandidates] = useState<ProcessCandidate[]>([]);
  const [captureTargetMode, setCaptureTargetMode] = useState<"pid" | "name" | "global">("pid");
  const [capturePidInput, setCapturePidInput] = useState("");
  const [captureNameInput, setCaptureNameInput] = useState("");
  const [captureProfile, setCaptureProfile] = useState<CaptureProfile>("network");
  const [captureModules, setCaptureModules] = useState<CaptureModule[]>(["process", "connections", "traffic", "dns"]);
  const [captureBusy, setCaptureBusy] = useState(false);
  const [resetBusy, setResetBusy] = useState(false);
  const [captureError, setCaptureError] = useState<string | null>(null);
  const [captureWorkspaceActive, setCaptureWorkspaceActive] = useState(false);
  const [tlsCapabilities, setTlsCapabilities] = useState<TlsCapability[]>([]);
  const [selectedConnectionId, setSelectedConnectionId] = useState<string | null>(null);
  const [connectionEventsLoadingId, setConnectionEventsLoadingId] = useState<string | null>(null);
  const [selectedPayloadEntry, setSelectedPayloadEntry] = useState<TimelineEntry | null>(null);
  const [selectedHttpTransaction, setSelectedHttpTransaction] = useState<HttpTransaction | null>(null);
  const [httpSearch, setHttpSearch] = useState("");
  const [httpStatusFilter, setHttpStatusFilter] = useState("all");
  const [processSort, setProcessSort] = useState<SortState<ProcessSortKey>>({ key: "connections", direction: "desc" });
  const [processColumnWidths, setProcessColumnWidths] = useState<Record<ProcessColumnKey, number>>(defaultProcessColumnWidths);
  const [processPageIndex, setProcessPageIndex] = useState(0);
  const [connectionSort, setConnectionSort] = useState<SortState<ConnectionSortKey>>({ key: "last_seen", direction: "desc" });
  const [connectionColumnWidths, setConnectionColumnWidths] = useState<Record<ConnectionColumnKey, number>>(defaultConnectionColumnWidths);
  const [connectionPageIndex, setConnectionPageIndex] = useState(0);
  const [timelineOffset, setTimelineOffset] = useState(0);
  const [selectedConnectionCache, setSelectedConnectionCache] = useState<ConnectionTimeline | null>(null);
  const [activeView, setActiveView] = useState<WorkspaceView>("connections");
  const refreshingRef = useRef(false);
  const columnResizeCleanupRef = useRef<(() => void) | null>(null);
  const processTableRef = useRef<HTMLDivElement>(null);
  const connectionTableRef = useRef<HTMLDivElement>(null);
  const timelineListRef = useRef<HTMLDivElement>(null);
  const workspaceViewInitializedRef = useRef(false);
  const pendingScrollSnapshotRef = useRef<ScrollSnapshot | null>(null);

  const startDesktopCore = useCallback(async () => {
    if (!IS_DESKTOP) return;
    setDesktopBoot({ phase: "starting", message: "Waiting for administrator authorization…" });
    try {
      const status = await invoke<DesktopStatus>("ensure_core");
      if (!status.core_ready) throw new Error(status.message);
      setDesktopBoot({ phase: "ready", message: status.message });
    } catch (error) {
      setDesktopBoot({
        phase: "error",
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }, []);

  useEffect(() => {
    void startDesktopCore();
  }, [startDesktopCore]);

  const beginProcessColumnResize = useCallback((column: ProcessColumnKey, clientX: number) => {
    columnResizeCleanupRef.current?.();
    const startWidth = processColumnWidths[column];
    const handleMove = (event: PointerEvent) => {
      const nextWidth = Math.max(72, Math.round(startWidth + event.clientX - clientX));
      setProcessColumnWidths((current) => current[column] === nextWidth
        ? current
        : { ...current, [column]: nextWidth });
    };
    const cleanup = () => {
      window.removeEventListener("pointermove", handleMove);
      window.removeEventListener("pointerup", cleanup);
      document.body.classList.remove("column-resizing");
      if (columnResizeCleanupRef.current === cleanup) columnResizeCleanupRef.current = null;
    };
    columnResizeCleanupRef.current = cleanup;
    window.addEventListener("pointermove", handleMove);
    window.addEventListener("pointerup", cleanup);
    document.body.classList.add("column-resizing");
  }, [processColumnWidths]);

  const beginConnectionColumnResize = useCallback((column: ConnectionColumnKey, clientX: number) => {
    columnResizeCleanupRef.current?.();
    const startWidth = connectionColumnWidths[column];
    const handleMove = (event: PointerEvent) => {
      const nextWidth = Math.max(72, Math.round(startWidth + event.clientX - clientX));
      setConnectionColumnWidths((current) => current[column] === nextWidth
        ? current
        : { ...current, [column]: nextWidth });
    };
    const cleanup = () => {
      window.removeEventListener("pointermove", handleMove);
      window.removeEventListener("pointerup", cleanup);
      document.body.classList.remove("column-resizing");
      if (columnResizeCleanupRef.current === cleanup) columnResizeCleanupRef.current = null;
    };
    columnResizeCleanupRef.current = cleanup;
    window.addEventListener("pointermove", handleMove);
    window.addEventListener("pointerup", cleanup);
    document.body.classList.add("column-resizing");
  }, [connectionColumnWidths]);

  useEffect(() => () => columnResizeCleanupRef.current?.(), []);

  const captureScrollSnapshot = useCallback((): ScrollSnapshot => {
    const containers = [
      processTableRef.current,
      connectionTableRef.current,
      timelineListRef.current,
    ].filter((element): element is HTMLDivElement => element !== null);

    return {
      windowX: window.scrollX,
      windowY: window.scrollY,
      containers: containers.map((element) => {
        const containerRect = element.getBoundingClientRect();
        const anchor = Array.from(element.querySelectorAll<HTMLElement>("[data-scroll-key]"))
          .map((candidate) => ({ candidate, rect: candidate.getBoundingClientRect() }))
          .find(({ rect }) => rect.bottom > containerRect.top && rect.top < containerRect.bottom);

        return {
          element,
          top: element.scrollTop,
          left: element.scrollLeft,
          atStart: element.scrollTop <= 1,
          anchor: anchor
            ? {
                key: anchor.candidate.dataset.scrollKey ?? "",
                offset: anchor.rect.top - containerRect.top,
              }
            : null,
        };
      }),
    };
  }, []);

  useLayoutEffect(() => {
    const pending = pendingScrollSnapshotRef.current;
    if (!pending) return;
    pendingScrollSnapshotRef.current = null;

    window.scrollTo(pending.windowX, pending.windowY);
    pending.containers.forEach((saved) => {
      const container = saved.element;
      if (!container.isConnected) return;

      if (saved.atStart || !saved.anchor?.key) {
        container.scrollTop = saved.top;
        container.scrollLeft = saved.left;
        return;
      }

      const anchor = Array.from(container.querySelectorAll<HTMLElement>("[data-scroll-key]"))
        .find((candidate) => candidate.dataset.scrollKey === saved.anchor?.key);
      if (!anchor) {
        container.scrollTop = saved.top;
        container.scrollLeft = saved.left;
        return;
      }

      const containerRect = container.getBoundingClientRect();
      const currentOffset = anchor.getBoundingClientRect().top - containerRect.top;
      container.scrollTop += currentOffset - saved.anchor.offset;
      container.scrollLeft = saved.left;
    });
  }, [snapshot]);

  const timelineRequestPath = useMemo(
    () => buildTimelinePath(
      timelineKind,
      timelinePid,
      timelineConnection,
      timelineOffset,
      showPlaintextFragments || timelineKind === "plaintext",
    ),
    [showPlaintextFragments, timelineConnection, timelineKind, timelineOffset, timelinePid],
  );
  const httpRequestPath = "/api/timeline?kind=http&limit=200&offset=0&include_plaintext=false";
  const refresh = useCallback(async () => {
    if (refreshingRef.current) return;
    refreshingRef.current = true;
    setRefreshing(true);
    setRefreshError(null);
    try {
      const needsCandidates = snapshot.mode !== "live"
        || (snapshot.summary.capture_state === "stopped" && !captureWorkspaceActive);
      const needsTlsDiagnostics = snapshot.summary.capture_state === "capturing" || captureWorkspaceActive;
      const [summary, processes, connections, timeline, candidates, health] = await Promise.all([
        fetchJson<Summary>("/api/summary"),
        activeView === "processes" ? fetchJson<ProcessRow[]>("/api/processes") : Promise.resolve(null),
        activeView === "connections" ? fetchJson<ConnectionRow[]>("/api/connections") : Promise.resolve(null),
        activeView === "timeline"
          ? fetchJson<TimelinePage>(timelineRequestPath)
          : activeView === "http"
            ? fetchJson<TimelinePage>(httpRequestPath)
            : Promise.resolve(null),
        needsCandidates ? fetchJson<ProcessCandidate[]>('/api/process-candidates') : Promise.resolve(null),
        needsTlsDiagnostics ? fetchJson<RuntimeHealth>('/api/health') : Promise.resolve(null),
      ]);
      // Capture immediately before replacing the live lists so a user who
      // scrolls while the API is responding does not get pulled back to an
      // older position.
      pendingScrollSnapshotRef.current = captureScrollSnapshot();
      if (candidates) setProcessCandidates(candidates);
      if (health) setTlsCapabilities(health.tls_capabilities);
      else if (!needsTlsDiagnostics) setTlsCapabilities([]);
      setSnapshot((current) => ({
        ...current,
        summary,
        processes: processes ?? current.processes,
        connections: connections ?? current.connections,
        timeline: timeline ?? current.timeline,
        mode: "live",
      }));
      if (timeline) setTimelineOffset(timeline.offset);
    } catch {
      setRefreshError("Core 暂时不可用，保留当前画面");
      pendingScrollSnapshotRef.current = captureScrollSnapshot();
      setSnapshot((current) => ({ ...current, mode: current.mode === "live" ? "live" : "demo" }));
    } finally {
      refreshingRef.current = false;
      setRefreshing(false);
    }
  }, [activeView, captureScrollSnapshot, captureWorkspaceActive, snapshot.mode, snapshot.summary.capture_state, showPlaintextFragments, timelineRequestPath]);

  const loadConnectionEvents = useCallback(async (connectionId: string, includePlaintext: boolean) => {
    setConnectionEventsLoadingId(connectionId);
    try {
      const detail = await fetchJson<ConnectionTimelinePage>(buildConnectionDetailPath(connectionId, includePlaintext));
      const session = detail.sessions.find((item) => item.id === connectionId);
      if (session) {
        setSelectedConnectionCache(session);
        setSnapshot((current) => ({
          ...current,
          connection_timeline: {
            ...current.connection_timeline,
            sessions: current.connection_timeline.sessions.some((item) => item.id === connectionId)
              ? current.connection_timeline.sessions.map((item) => item.id === connectionId ? session : item)
              : [...current.connection_timeline.sessions, session],
          },
        }));
      }
    } catch {
      // Keep the connection summary visible if the detail request fails.
    } finally {
      setConnectionEventsLoadingId(null);
    }
  }, []);

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

  const postCommand = useCallback(async (path: string, body?: unknown) => {
    const response = await fetch(`${API_BASE}${path}`, {
      method: "POST",
      headers: body === undefined ? undefined : { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!response.ok) {
      const message = await response.text();
      throw new Error(message || `${path}: ${response.status}`);
    }
  }, []);

  const chooseCaptureProfile = useCallback((profile: CaptureProfile) => {
    setCaptureProfile(profile);
    if (profile === "custom") return;
    const preset = captureProfiles.find((candidate) => candidate.id === profile);
    if (preset) setCaptureModules(preset.modules);
  }, []);

  const toggleCaptureModule = useCallback((module: CaptureModule, enabled: boolean) => {
    setCaptureProfile("custom");
    setCaptureModules((current) => {
      const next = new Set(current);
      if (enabled) {
        next.add(module);
      } else {
        next.delete(module);
        if (module === "process") next.clear();
        if (module === "connections") {
          ["traffic", "dns", "tls", "http", "plaintext"].forEach((item) => next.delete(item as CaptureModule));
        }
        if (module === "tls") {
          next.delete("http");
          next.delete("plaintext");
        }
      }
      return closeModuleDependencies([...next]);
    });
  }, []);

  const resetCapture = useCallback(async () => {
    if (resetBusy) return;
    setResetBusy(true);
    setCaptureError(null);
    try {
      await postCommand("/api/capture/reset");
      setCaptureWorkspaceActive(true);
      setSelectedConnectionId(null);
      setSelectedConnectionCache(null);
      setSelectedPayloadEntry(null);
      setSelectedHttpTransaction(null);
      setTimelineOffset(0);
      // Do not hold the button hostage to every read endpoint. The reset
      // command has already completed; refresh the workspace in the
      // background and let the control become usable immediately.
      void refresh();
    } catch (error) {
      setCaptureError(error instanceof Error ? error.message : "capture reset failed");
    } finally {
      setResetBusy(false);
    }
  }, [postCommand, refresh, resetBusy]);

  const runCaptureCommand = useCallback(async (action: "start" | "stop") => {
    setCaptureBusy(true);
    setCaptureError(null);
    try {
      let captureTarget = "global";
      if (action === "start") {
        const existingTarget = snapshot.mode === "live"
          && captureWorkspaceActive
          && snapshot.summary.event_count > 0
          ? parseCaptureTarget(snapshot.summary.capture_target)
          : null;
        const selection = existingTarget ?? {
          mode: captureTargetMode,
          pid: capturePidInput.trim(),
          name: captureNameInput.trim(),
        };
        if (selection.mode === "global") {
        } else if (selection.mode === "pid") {
          const pid = Number(selection.pid);
          if (!Number.isInteger(pid) || pid <= 0) throw new Error("请输入有效 PID");
          captureTarget = `process:${pid}`;
        } else {
          const name = selection.name;
          if (!name) throw new Error("请输入进程名");
          captureTarget = `process-name:${name}`;
        }
        if (captureModules.length === 0) throw new Error("至少选择一个采集模块");
        const confirmPlaintext = !captureModules.includes("plaintext")
          || window.confirm("Plaintext may contain credentials and private data. Start this capture?");
        if (!confirmPlaintext) return;
        await postCommand("/api/capture/start", {
          target: captureTarget,
          profile: captureProfile,
          modules: captureModules,
          confirm_plaintext: captureModules.includes("plaintext"),
        });
        if (captureModules.includes("http")) setActiveView("http");
      } else {
        await postCommand("/api/capture/stop");
      }
      setCaptureWorkspaceActive(action === "start");
      await refresh();
    } catch (error) {
      setCaptureError(error instanceof Error ? error.message : "capture command failed");
    } finally {
      setCaptureBusy(false);
    }
  }, [captureModules, captureNameInput, capturePidInput, captureProfile, captureTargetMode, captureWorkspaceActive, postCommand, refresh, snapshot.mode, snapshot.summary.capture_target, snapshot.summary.event_count]);

  useEffect(() => {
    if (IS_DESKTOP && desktopBoot.phase !== "ready") return;
    void refresh();
  }, [desktopBoot.phase, refresh]);

  useEffect(() => {
    if (snapshot.mode !== "live") return;
    // When the Core is stopped, this is the new-capture form. Do not mirror
    // the previous session back into it on every one-second refresh while the
    // user is editing a new target.
    if (snapshot.summary.capture_state === "stopped" && !captureWorkspaceActive) return;
    const selection = parseCaptureTarget(snapshot.summary.capture_target);
    setCaptureTargetMode(selection.mode);
    if (selection.mode === "pid" && selection.pid) setCapturePidInput(selection.pid);
    if (selection.mode === "name" && selection.name) setCaptureNameInput(selection.name);
  }, [captureWorkspaceActive, snapshot.mode, snapshot.summary.capture_state, snapshot.summary.capture_target]);

  useEffect(() => {
    if (snapshot.mode !== "live" || workspaceViewInitializedRef.current) return;
    workspaceViewInitializedRef.current = true;
    setActiveView(snapshot.summary.capture_modules.includes("http") ? "http" : "connections");
  }, [snapshot.mode, snapshot.summary.capture_modules]);

  useEffect(() => {
    if (IS_DESKTOP && desktopBoot.phase !== "ready") return undefined;
    if (!autoRefresh) return undefined;
    const timer = window.setInterval(() => void refresh(), 1000);
    return () => window.clearInterval(timer);
  }, [autoRefresh, desktopBoot.phase, refresh]);

  useEffect(() => {
    if (!selectedConnectionId && !selectedPayloadEntry && !selectedHttpTransaction) return undefined;
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        if (selectedPayloadEntry) {
          setSelectedPayloadEntry(null);
        } else if (selectedHttpTransaction) {
          setSelectedHttpTransaction(null);
        } else {
          setSelectedConnectionId(null);
          setSelectedConnectionCache(null);
        }
      }
    };
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [selectedConnectionId, selectedHttpTransaction, selectedPayloadEntry]);

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
  const httpTransactions = useMemo(() => pairHttpTransactions(snapshot.timeline.entries), [snapshot.timeline.entries]);
  const visibleHttpTransactions = useMemo(() => {
    const query = httpSearch.trim().toLowerCase();
    return httpTransactions.filter((transaction) => {
      const status = transaction.response?.http_status ?? null;
      const matchesStatus = httpStatusFilter === "all"
        || (httpStatusFilter === "pending" && status === null)
        || (httpStatusFilter === "success" && status !== null && status >= 200 && status < 300)
        || (httpStatusFilter === "redirect" && status !== null && status >= 300 && status < 400)
        || (httpStatusFilter === "error" && status !== null && status >= 400);
      if (!matchesStatus || !query) return matchesStatus;
      const request = transaction.request;
      const response = transaction.response;
      return [
        request?.http_method,
        request?.http_host,
        request?.http_target,
        request?.process_name,
        request?.pid,
        response?.http_status,
        response?.http_reason,
      ].some((value) => String(value ?? "").toLowerCase().includes(query));
    });
  }, [httpSearch, httpStatusFilter, httpTransactions]);
  const focusConnection = useCallback((connectionId: string) => {
    setSelectedConnectionId(connectionId);
    const session = snapshot.connection_timeline.sessions.find((item) => item.id === connectionId);
    if (session) setSelectedConnectionCache(session);
    if (snapshot.mode === "live" && (!session || session.event_count > 0 && session.events.length === 0)) {
      void loadConnectionEvents(connectionId, showPlaintextFragments);
    }
    setTimelineConnectionInput(connectionId);
    setTimelineConnection(connectionId);
  }, [loadConnectionEvents, showPlaintextFragments, snapshot.connection_timeline.sessions, snapshot.mode]);
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
  const processTableWidth = Object.values(processColumnWidths).reduce((total, width) => total + width, 0);
  const connectionTableWidth = Object.values(connectionColumnWidths).reduce((total, width) => total + width, 0);
  const isLive = snapshot.mode === "live";
  const isCapturing = isLive && snapshot.summary.capture_state === "capturing";
  // The setup console is only for an idle Core. Once Start succeeds, show
  // the capture workspace immediately even before the first event arrives.
  const showCaptureConsole = isLive
    && !captureWorkspaceActive
    && snapshot.summary.capture_state === "stopped";
  const statusText = isLive ? "Core connected" : "Core offline · demo data";

  if (IS_DESKTOP && desktopBoot.phase !== "ready") {
    return (
      <main className="desktop-bootstrap">
        <section className="desktop-bootstrap-card panel">
          <div className="brand desktop-bootstrap-brand"><span className="brand-mark">◌</span><span>TraceLens</span></div>
          <p className="eyebrow">LINUX DESKTOP</p>
          <h1>{desktopBoot.phase === "error" ? "Core could not start" : "Starting TraceLens"}</h1>
          <p className="hero-copy">
            {desktopBoot.phase === "error"
              ? desktopBoot.message
              : "TraceLens needs administrator access to load eBPF programs. Approve the system authorization dialog to continue."}
          </p>
          {desktopBoot.phase === "starting" && <div className="desktop-spinner" aria-label="Starting Core" />}
          {desktopBoot.phase === "error" && (
            <button className="primary-button desktop-retry" onClick={() => void startDesktopCore()}>
              Try again
            </button>
          )}
          <small>Core starts idle. No traffic is captured until you press Start capture.</small>
        </section>
      </main>
    );
  }

  if (showCaptureConsole) {
    return (
      <main className="shell capture-shell">
        <header className="topbar">
          <div className="brand"><span className="brand-mark">◌</span><span>TraceLens</span></div>
          <div className={`runtime-status ${isLive ? "" : "offline"}`}>
            <span className="status-dot" />
            {statusText}
          </div>
        </header>

        <section className="capture-console panel">
          <div className="capture-console-heading">
            <div>
              <p className="eyebrow">CAPTURE CONSOLE</p>
              <h1>{isCapturing ? "Waiting for traffic" : "New capture"}</h1>
              <p className="hero-copy">
                {isCapturing
                  ? "TraceLens is armed. Generate traffic in the selected target, then inspect the captured session below."
                  : "Nothing is being collected yet. Choose a target and the modules you need, then start a capture."}
              </p>
            </div>
          </div>

          <div className="capture-target-tabs" role="tablist" aria-label="Capture target">
            {(["pid", "name", "global"] as const).map((mode) => (
              <button
                key={mode}
                className={`capture-target-tab ${captureTargetMode === mode ? "active" : ""}`}
                onClick={() => setCaptureTargetMode(mode)}
                disabled={isCapturing || captureBusy}
              >
                {mode === "pid" ? "Selected PID" : mode === "name" ? "Process name" : "Global"}
              </button>
            ))}
          </div>

          <div className="capture-target-form">
            {captureTargetMode === "pid" && (
              <label className="capture-field">
                <span>PID</span>
                <input
                  list="process-pid-candidates"
                  value={capturePidInput}
                  onChange={(event) => setCapturePidInput(event.target.value)}
                  placeholder="例如 148042"
                  inputMode="numeric"
                  disabled={isCapturing || captureBusy}
                />
                <small>只追踪这个进程；进程退出后自动停止对应 probe。</small>
              </label>
            )}
            {captureTargetMode === "name" && (
              <label className="capture-field">
                <span>Process name</span>
                <input
                  list="process-name-candidates"
                  value={captureNameInput}
                  onChange={(event) => setCaptureNameInput(event.target.value)}
                  placeholder="例如 curl 或 node"
                  disabled={isCapturing || captureBusy}
                />
                <small>匹配当前和之后启动的同名进程。</small>
              </label>
            )}
            {captureTargetMode === "global" && (
              <div className="capture-field capture-global-note">
                <span>Global scope</span>
                <p>追踪所有当前及之后出现的进程。只会启用下面选中的模块。</p>
              </div>
            )}
          </div>

          <div className="capture-plan-builder">
            <div className="capture-profile-picker">
              <span className="capture-plan-label">Capture profile</span>
              <div className="capture-profile-options">
                {captureProfiles.map((profile) => (
                  <button
                    key={profile.id}
                    type="button"
                    className={`capture-profile-button ${captureProfile === profile.id ? "active" : ""}`}
                    onClick={() => chooseCaptureProfile(profile.id)}
                    disabled={isCapturing || captureBusy}
                  >
                    {profile.label}
                  </button>
                ))}
              </div>
            </div>
            <div className="capture-module-grid">
              {captureModuleOptions.map((module) => (
                <label key={module.id} className={`capture-module-option ${module.id === "plaintext" ? "sensitive" : ""}`}>
                  <input
                    type="checkbox"
                    checked={captureModules.includes(module.id)}
                    onChange={(event) => toggleCaptureModule(module.id, event.target.checked)}
                    disabled={isCapturing || captureBusy || (module.id === "process" && captureModules.length > 1)}
                  />
                  <span><strong>{module.label}</strong><small>{module.hint}</small></span>
                </label>
              ))}
            </div>
            <p className="capture-effective-plan">
              Effective modules: {captureModules.length > 0 ? captureModules.join(" · ") : "none"}
            </p>
          </div>

          <datalist id="process-pid-candidates">
            {processCandidates.map((process) => <option key={process.pid} value={process.pid}>{process.name}</option>)}
          </datalist>
          <datalist id="process-name-candidates">
            {[...new Set(processCandidates.map((process) => process.name))].map((name) => <option key={name} value={name} />)}
          </datalist>

          <div className="capture-console-actions">
            <button className="primary-button" onClick={() => void runCaptureCommand("start")} disabled={isCapturing || captureBusy}>
              {captureBusy ? "Working…" : "Start capture"}
            </button>
            {isCapturing && <button className="ghost-button danger-button" onClick={() => void runCaptureCommand("stop")} disabled={captureBusy}>Stop</button>}
            <button className="ghost-button danger-button" onClick={() => void resetCapture()} disabled={resetBusy}>{resetBusy ? "Resetting…" : "Reset & start new"}</button>
            <span className="capture-console-hint">Captured events: 0 · memory only</span>
          </div>
          {captureError && <p className="error-note capture-error">{captureError}</p>}

          <div className="process-picker">
            <div className="process-picker-heading">
              <div><p className="eyebrow">SYSTEM PROCESSES</p><h2>Quick select</h2></div>
            </div>
            <div className="process-picker-list">
              {processCandidates.slice(0, 36).map((process) => (
                <button key={process.pid} className="process-picker-item" onClick={() => {
                  setCaptureTargetMode("pid");
                  setCapturePidInput(String(process.pid));
                }} disabled={isCapturing || captureBusy}>
                  <strong>{process.name}</strong><span>PID {process.pid}</span>
                  {process.command_line && <small>{process.command_line}</small>}
                </button>
              ))}
              {processCandidates.length === 0 && <p className="muted empty-cell">No readable system processes.</p>}
            </div>
          </div>
        </section>
        {refreshError && <p className="refresh-error">{refreshError}</p>}
      </main>
    );
  }

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
          {isLive && <span className={`capture-state capture-state-${snapshot.summary.capture_state}`}>
            {isCapturing ? "CAPTURING" : "STOPPED"}
          </span>}
          {isLive && (
            <div className="capture-session-actions">
              <span className="capture-plan-summary">{snapshot.summary.capture_profile} · {snapshot.summary.capture_modules.join(" + ")}</span>
              {tlsCapabilities.length > 0 && (
                <span
                  className={`tls-provider-summary ${tlsCapabilities.some((capability) => !capability.supported) ? "has-unsupported" : ""}`}
                  title={tlsCapabilities.map((capability) => `${capability.provider}: ${capability.library}${capability.reason ? ` — ${capability.reason}` : ""}`).join("\n")}
                >
                  TLS {tlsCapabilities.map((capability) => `${capability.provider.split("_").join(" ")}${capability.supported ? "" : " unsupported"}`).join(" + ")}
                </span>
              )}
              {isCapturing && <button className="topbar-stop-button" onClick={() => void runCaptureCommand("stop")} disabled={captureBusy}>Stop</button>}
              {!isCapturing && <button className="topbar-capture-button" onClick={() => void runCaptureCommand("start")} disabled={captureBusy}>Start capture</button>}
              <button className="topbar-reset-button" onClick={() => void resetCapture()} disabled={resetBusy}>{resetBusy ? "Resetting…" : "Reset"}</button>
            </div>
          )}
          <label className="auto-refresh-toggle">
            <input type="checkbox" checked={autoRefresh} onChange={(event) => setAutoRefresh(event.target.checked)} />
            live refresh
          </label>
        </div>
      </header>

      <section className="metrics">
        <div className="metric-card"><span>Processes</span><strong>{snapshot.summary.processes}</strong><small>being observed</small></div>
        <div className="metric-card"><span>Connections</span><strong>{snapshot.summary.connections}</strong><small>active network edges</small></div>
        <div className="metric-card"><span>Domains</span><strong>{snapshot.summary.domains}</strong><small>correlated from DNS</small></div>
        <div className="metric-card"><span>Events</span><strong>{snapshot.summary.event_count}</strong><small>in this capture</small></div>
      </section>

      <nav className="workspace-tabs" role="tablist" aria-label="Capture views">
        {workspaceTabs.map((tab) => (
          <button
            key={tab.id}
            type="button"
            role="tab"
            aria-selected={activeView === tab.id}
            className={`workspace-tab ${activeView === tab.id ? "active" : ""}`}
            onClick={() => setActiveView(tab.id)}
          >
            <strong>{tab.label}</strong>
            <span>{tab.hint}</span>
          </button>
        ))}
      </nav>

      {refreshError && <p className="refresh-error workspace-error">{refreshError}</p>}
      {captureError && <p className="refresh-error capture-error workspace-error">{captureError}</p>}

      {activeView === "http" && <section className="panel http-panel">
        <div className="panel-heading http-heading">
          <div>
            <p className="eyebrow">APPLICATION TRAFFIC</p>
            <h2>HTTP requests</h2>
            <p className="panel-description">Requests and responses are paired by connection, newest first.</p>
          </div>
          <div className="http-toolbar">
            <input
              className="http-search"
              type="search"
              aria-label="Search HTTP requests"
              placeholder="Search host, path, process…"
              value={httpSearch}
              onChange={(event) => setHttpSearch(event.target.value)}
            />
            <select
              className="http-status-filter"
              aria-label="Filter HTTP status"
              value={httpStatusFilter}
              onChange={(event) => setHttpStatusFilter(event.target.value)}
            >
              <option value="all">All statuses</option>
              <option value="success">2xx Success</option>
              <option value="redirect">3xx Redirect</option>
              <option value="error">4xx / 5xx Error</option>
              <option value="pending">No response</option>
            </select>
            <span className="connection-count">{visibleHttpTransactions.length} requests</span>
          </div>
        </div>
        <div className="http-table-wrap">
          <table className="http-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Method</th>
                <th>Host / path</th>
                <th>Status</th>
                <th>Type</th>
                <th>Size</th>
                <th>Duration</th>
                <th>Process</th>
              </tr>
            </thead>
            <tbody>
              {visibleHttpTransactions.length === 0 ? (
                <tr><td colSpan={8} className="muted empty-cell">
                  {httpTransactions.length === 0
                    ? "No HTTP/1.1 requests captured yet. HTTP/2 and HTTP/3 are not decoded currently."
                    : "No requests match these filters."}
                </td></tr>
              ) : visibleHttpTransactions.map((transaction) => {
                const request = transaction.request;
                const response = transaction.response;
                const status = response?.http_status ?? null;
                const statusClass = status === null ? "pending" : status >= 400 ? "error" : status >= 300 ? "redirect" : "success";
                const process = request ?? response;
                return (
                  <tr
                    className="http-row"
                    key={transaction.id}
                    onClick={() => setSelectedHttpTransaction(transaction)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        setSelectedHttpTransaction(transaction);
                      }
                    }}
                    tabIndex={0}
                  >
                    <td className="muted http-nowrap">{formatClock(request?.timestamp_ns ?? response?.timestamp_ns)}</td>
                    <td><span className={`http-method http-method-${(request?.http_method ?? "unknown").toLowerCase()}`}>{request?.http_method ?? "—"}</span></td>
                    <td className="http-url-cell">
                      <strong>{request?.http_host ?? response?.http_host ?? "Unknown host"}</strong>
                      <span title={request?.http_target ?? undefined}>{request?.http_target ?? "Response without matching request"}</span>
                    </td>
                    <td><span className={`http-status http-status-${statusClass}`}>{status ?? "Pending"}</span></td>
                    <td className="muted">{httpContentType(response)}</td>
                    <td className="http-nowrap">{formatBytes(response?.http_body_bytes ?? 0)}</td>
                    <td className="http-nowrap">{httpTransactionDuration(transaction)}</td>
                    <td className="http-process-cell">
                      <span>{process?.process_name ?? "unknown"}</span>
                      <small>{process?.pid !== null && process?.pid !== undefined ? `PID ${process.pid}` : ""}</small>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <div className="http-footer">
          <span>Showing the latest {snapshot.timeline.entries.length} HTTP messages</span>
          {snapshot.timeline.has_more && <span>Older messages are available in Raw events.</span>}
        </div>
      </section>}

      {activeView === "processes" && <section className="content-grid">
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
          <div ref={processTableRef} className="table-wrap process-table-wrap">
            <table
              className="resizable-table"
              style={{ width: `${processTableWidth}px`, minWidth: "100%" }}
            >
              <colgroup>
                <col style={{ width: `${processColumnWidths.name}px` }} />
                <col style={{ width: `${processColumnWidths.pid}px` }} />
                <col style={{ width: `${processColumnWidths.connections}px` }} />
                <col style={{ width: `${processColumnWidths.traffic}px` }} />
              </colgroup>
              <thead>
                <tr>
                  <SortableHeader label="Process" column="name" sort={processSort} onSort={changeProcessSort} width={processColumnWidths.name} onResizeStart={(clientX) => beginProcessColumnResize("name", clientX)} />
                  <SortableHeader label="PID" column="pid" sort={processSort} onSort={changeProcessSort} width={processColumnWidths.pid} onResizeStart={(clientX) => beginProcessColumnResize("pid", clientX)} />
                  <SortableHeader label="Connections" column="connections" sort={processSort} onSort={changeProcessSort} width={processColumnWidths.connections} onResizeStart={(clientX) => beginProcessColumnResize("connections", clientX)} />
                  <SortableHeader label="Traffic" column="traffic" sort={processSort} onSort={changeProcessSort} width={processColumnWidths.traffic} onResizeStart={(clientX) => beginProcessColumnResize("traffic", clientX)} />
                </tr>
              </thead>
              <tbody>
                {sortedProcesses.length === 0 ? (
                  <tr><td colSpan={4} className="muted empty-cell">No processes observed yet.</td></tr>
                ) : pagedProcesses.map((process) => (
                  <tr key={process.pid} data-scroll-key={`process:${process.pid}`}>
                    <td><span className="process-name">{process.name}</span></td>
                    <td className="muted">{process.pid}</td>
                    <td>{process.connections}</td>
                    <td>{formatBytes(process.sent_bytes + process.received_bytes)}</td>
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

      </section>}

      {activeView === "connections" && <section className="panel connection-panel">
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
        <div ref={connectionTableRef} className="table-wrap connection-table-wrap">
          <table
            className="resizable-table"
            style={{ width: `${connectionTableWidth}px`, minWidth: "100%" }}
          >
            <colgroup>
              <col style={{ width: `${connectionColumnWidths.process}px` }} />
              <col style={{ width: `${connectionColumnWidths.pid}px` }} />
              <col style={{ width: `${connectionColumnWidths.remote}px` }} />
              <col style={{ width: `${connectionColumnWidths.domain}px` }} />
              <col style={{ width: `${connectionColumnWidths.state}px` }} />
              <col style={{ width: `${connectionColumnWidths.traffic}px` }} />
              <col style={{ width: `${connectionColumnWidths.last_seen}px` }} />
              <col style={{ width: `${connectionColumnWidths.trace}px` }} />
            </colgroup>
            <thead>
              <tr>
                <SortableHeader label="Process" column="process" sort={connectionSort} onSort={changeConnectionSort} width={connectionColumnWidths.process} onResizeStart={(clientX) => beginConnectionColumnResize("process", clientX)} />
                <SortableHeader label="PID" column="pid" sort={connectionSort} onSort={changeConnectionSort} width={connectionColumnWidths.pid} onResizeStart={(clientX) => beginConnectionColumnResize("pid", clientX)} />
                <SortableHeader label="Remote" column="remote" sort={connectionSort} onSort={changeConnectionSort} width={connectionColumnWidths.remote} onResizeStart={(clientX) => beginConnectionColumnResize("remote", clientX)} />
                <SortableHeader label="Domain" column="domain" sort={connectionSort} onSort={changeConnectionSort} width={connectionColumnWidths.domain} onResizeStart={(clientX) => beginConnectionColumnResize("domain", clientX)} />
                <SortableHeader label="State" column="state" sort={connectionSort} onSort={changeConnectionSort} width={connectionColumnWidths.state} onResizeStart={(clientX) => beginConnectionColumnResize("state", clientX)} />
                <SortableHeader label="Traffic" column="traffic" sort={connectionSort} onSort={changeConnectionSort} width={connectionColumnWidths.traffic} onResizeStart={(clientX) => beginConnectionColumnResize("traffic", clientX)} />
                <SortableHeader label="Updated" column="last_seen" sort={connectionSort} onSort={changeConnectionSort} width={connectionColumnWidths.last_seen} onResizeStart={(clientX) => beginConnectionColumnResize("last_seen", clientX)} />
                <th scope="col" style={{ width: `${connectionColumnWidths.trace}px` }}>
                  <span>Trace</span>
                  <ColumnResizer label="Trace" onResizeStart={(clientX) => beginConnectionColumnResize("trace", clientX)} />
                </th>
              </tr>
            </thead>
            <tbody>
              {visibleConnections.length === 0 ? (
                <tr><td colSpan={8} className="muted empty-cell">
                  {showClosedConnections ? "No connections observed yet." : "No active connections. Enable Show closed to inspect history."}
                </td></tr>
              ) : pagedConnections.map((connection) => (
                <tr key={connection.id} data-scroll-key={`connection:${connection.id}`}>
                  <td><span className="process-name">{connection.process_name ?? (connection.pid ? processNames.get(connection.pid) ?? `exited (${connection.pid})` : "unknown")}</span></td>
                  <td className="muted">{connection.pid ?? "—"}</td>
                  <td>{connection.remote.address}:{connection.remote.port}</td>
                  <td className="muted">{connection.domain ?? "—"}</td>
                  <td><span className={`state state-${connection.state}`}>{stateLabel(connection.tcp_state ?? connection.state)}</span></td>
                  <td>{formatBytes(connection.sent_bytes + connection.received_bytes)}</td>
                  <td className="muted">{formatClock(connection.last_seen_ns ?? connection.first_seen_ns)}</td>
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
      </section>}

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
                <p className="eyebrow">CONNECTION DETAILS</p>
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
                  onClick={() => void loadConnectionEvents(selectedConnection.id, showPlaintextFragments)}
                  disabled={connectionEventsLoadingId === selectedConnection.id || snapshot.mode !== "live"}
                >
                  {connectionEventsLoadingId === selectedConnection.id ? "Loading" : "Refresh details"}
                </button>
                <button
                  className="modal-close"
                  aria-label="Close connection details"
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
              <p className="muted session-events-empty">Loading connection events…</p>
            ) : selectedConnection.events.length === 0 ? (
              <p className="muted session-events-empty">No event details available.</p>
            ) : (
              <div className="session-events modal-events">
                {selectedConnection.events.length < selectedConnection.event_count && (
                  <p className="muted session-events-note">Showing the latest {selectedConnection.events.length} of {selectedConnection.event_count} events.</p>
                )}
                {selectedConnection.events.map((event) => (
                  <div
                    className={`session-event ${canInspectPayload(event) ? "payload-event" : ""}`}
                    key={event.id}
                    onClick={() => canInspectPayload(event) && setSelectedPayloadEntry(event)}
                    onKeyDown={(keyboardEvent) => {
                      if (canInspectPayload(event) && (keyboardEvent.key === "Enter" || keyboardEvent.key === " ")) {
                        keyboardEvent.preventDefault();
                        setSelectedPayloadEntry(event);
                      }
                    }}
                    role={canInspectPayload(event) ? "button" : undefined}
                    tabIndex={canInspectPayload(event) ? 0 : undefined}
                  >
                    <time>{formatTimestamp(event.timestamp_ns, selectedConnection.first_seen_ns)}</time>
                    <span className={`timeline-marker timeline-marker-${event.kind}`} />
                    <div>
                      <div className="timeline-meta">
                        <span className="timeline-kind">{timelineKindLabel(event.kind)}</span>
                        {tlsProvenance(event) && <span className="provider-hint" title={event.tls_library ?? undefined}>{tlsProvenance(event)}</span>}
                        {canInspectPayload(event) && <span className="payload-hint">click to inspect</span>}
                      </div>
                      <strong>{event.summary}</strong>
                      <p>{timelineDetail(event)}</p>
                      {timelineBody(event) && <pre className="timeline-payload">{timelineBody(event)}</pre>}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>
        </div>
      )}

      {selectedHttpTransaction && (
        <div
          className="modal-backdrop http-detail-backdrop"
          role="presentation"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setSelectedHttpTransaction(null);
          }}
        >
          <section
            className="http-detail-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="http-detail-title"
            onMouseDown={(event) => event.stopPropagation()}
          >
            <div className="modal-heading">
              <div>
                <p className="eyebrow">HTTP TRANSACTION</p>
                <h2 id="http-detail-title">
                  {selectedHttpTransaction.request?.http_method ?? "Response"}{" "}
                  {selectedHttpTransaction.request?.http_target ?? selectedHttpTransaction.response?.http_status ?? ""}
                </h2>
                <p className="modal-subtitle">
                  {selectedHttpTransaction.request?.http_host ?? "Unknown host"}
                  {` · ${selectedHttpTransaction.request?.http_version ?? selectedHttpTransaction.response?.http_version ?? "HTTP"}`}
                  {` · ${httpTransactionDuration(selectedHttpTransaction)}`}
                </p>
              </div>
              <button className="modal-close" aria-label="Close HTTP transaction" onClick={() => setSelectedHttpTransaction(null)}>×</button>
            </div>
            <div className="http-detail-columns">
              {[selectedHttpTransaction.request, selectedHttpTransaction.response].map((entry, index) => {
                const direction = index === 0 ? "Request" : "Response";
                return (
                  <section className="http-message" key={direction}>
                    <div className="http-message-heading">
                      <div>
                        <span className="http-message-direction">{direction}</span>
                        <strong>{entry ? payloadTitle(entry) : index === 0 ? "No matching request" : "Waiting for response"}</strong>
                      </div>
                      {entry && <button className="ghost-button" onClick={() => setSelectedPayloadEntry(entry)}>Open payload</button>}
                    </div>
                    {!entry ? (
                      <p className="muted http-message-empty">This side of the transaction has not been observed.</p>
                    ) : (
                      <>
                        <dl className="http-message-meta">
                          <div><dt>Time</dt><dd>{formatClock(entry.timestamp_ns)}</dd></div>
                          <div><dt>Process</dt><dd>{entry.process_name ?? "unknown"}{entry.pid !== null ? ` (${entry.pid})` : ""}</dd></div>
                          <div><dt>Captured body</dt><dd>{formatBytes(entry.http_body_bytes ?? 0)}</dd></div>
                          <div><dt>Content type</dt><dd>{httpContentType(entry)}</dd></div>
                        </dl>
                        <details className="http-detail-headers" open>
                          <summary>Headers ({entry.http_headers?.length ?? 0})</summary>
                          <pre>{entry.http_headers?.length
                            ? entry.http_headers.map((header) => `${header.name}: ${header.value}`).join("\n")
                            : "No headers captured"}</pre>
                        </details>
                        {entry.http_body_preview ? (
                          <pre className="http-detail-body">{entry.http_body_preview}</pre>
                        ) : (
                          <p className="muted http-message-empty">{httpBodyEmptyMessage(entry)}</p>
                        )}
                      </>
                    )}
                  </section>
                );
              })}
            </div>
          </section>
        </div>
      )}

      {selectedPayloadEntry && (
        <div
          className="modal-backdrop payload-backdrop"
          role="presentation"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setSelectedPayloadEntry(null);
          }}
        >
          <section
            className="payload-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="payload-modal-title"
            onMouseDown={(event) => event.stopPropagation()}
          >
            <div className="modal-heading">
              <div>
                <p className="eyebrow">PAYLOAD INSPECTOR</p>
                <h2 id="payload-modal-title">{payloadTitle(selectedPayloadEntry)}</h2>
                <p className="modal-subtitle">
                  {selectedPayloadEntry.process_name ?? "unknown process"}
                  {selectedPayloadEntry.pid !== null && ` · PID ${selectedPayloadEntry.pid}`}
                  {selectedPayloadEntry.connection_id && ` · ${selectedPayloadEntry.connection_id}`}
                </p>
              </div>
              <button
                className="modal-close"
                aria-label="Close payload inspector"
                onClick={() => setSelectedPayloadEntry(null)}
              >
                ×
              </button>
            </div>
            <div className="modal-meta">
              <span>{selectedPayloadEntry.http_direction ? `HTTP ${stateLabel(selectedPayloadEntry.http_direction)}` : stateLabel(selectedPayloadEntry.plaintext_direction ?? "plaintext")}</span>
              {selectedPayloadEntry.http_host && <span>Host {selectedPayloadEntry.http_host}</span>}
              {tlsProvenance(selectedPayloadEntry) && <span title={selectedPayloadEntry.tls_library ?? undefined}>{tlsProvenance(selectedPayloadEntry)}</span>}
              {selectedPayloadEntry.http_headers?.length ? <span>{selectedPayloadEntry.http_headers.length} headers</span> : null}
              {payloadBytes(selectedPayloadEntry) !== null && <span>{formatBytes(payloadBytes(selectedPayloadEntry) ?? 0)} captured</span>}
              {selectedPayloadEntry.http_body_truncated || selectedPayloadEntry.plaintext_truncated ? <span className="payload-warning">preview truncated</span> : null}
            </div>
            {selectedPayloadEntry.http_headers?.length ? (
              <details className="payload-headers">
                <summary>Show HTTP headers</summary>
                <pre>{selectedPayloadEntry.http_headers.map((header) => `${header.name}: ${header.value}`).join("\n")}</pre>
              </details>
            ) : null}
            {selectedPayloadEntry.http_payload_skipped || selectedPayloadEntry.plaintext_skipped ? (
              <div className="payload-skipped">
                <strong>内容未采集</strong>
                <p>
                  {stateLabel(selectedPayloadEntry.http_payload_skip_reason ?? selectedPayloadEntry.plaintext_skip_reason ?? "unsupported")}
                  。只保留了元数据和字节数，避免把二进制或大文件塞进内存。
                </p>
              </div>
            ) : payloadContent(selectedPayloadEntry) ? (
              <pre className="payload-view">{payloadContent(selectedPayloadEntry)}</pre>
            ) : (
              <p className="muted payload-empty">没有可显示的文本 body；如果这是 HTTP 事件，可以展开上面的 headers 查看请求/响应头。</p>
            )}
          </section>
        </div>
      )}

      {activeView === "timeline" && <section className="panel timeline-panel">
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
                <option value="plaintext">Plaintext</option>
                <option value="http">HTTP</option>
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
            <label className="timeline-toggle">
              <input
                type="checkbox"
                checked={showPlaintextFragments}
                onChange={(event) => {
                  setShowPlaintextFragments(event.target.checked);
                  setTimelineOffset(0);
                }}
              />
              show SSL fragments
            </label>
            <button className="ghost-button" onClick={applyTimelineFilters} disabled={refreshing}>Apply</button>
            <button className="ghost-button" onClick={resetTimelineFilters} disabled={refreshing}>Reset</button>
          </div>
          <span className="connection-count">{snapshot.timeline.total} matching events</span>
        </div>
        <div ref={timelineListRef} className="timeline-list">
          {snapshot.timeline.entries.length === 0 ? (
            <p className="muted empty-cell">No timeline events observed yet.</p>
          ) : snapshot.timeline.entries.slice().reverse().map((entry) => (
            <article
              className={`timeline-item ${canInspectPayload(entry) ? "payload-event" : ""}`}
              key={entry.id}
              data-scroll-key={`timeline:${entry.id}`}
              onClick={() => canInspectPayload(entry) && setSelectedPayloadEntry(entry)}
              onKeyDown={(keyboardEvent) => {
                if (canInspectPayload(entry) && (keyboardEvent.key === "Enter" || keyboardEvent.key === " ")) {
                  keyboardEvent.preventDefault();
                  setSelectedPayloadEntry(entry);
                }
              }}
              role={canInspectPayload(entry) ? "button" : undefined}
              tabIndex={canInspectPayload(entry) ? 0 : undefined}
            >
              <time className="timeline-time">
                {formatTimestamp(entry.timestamp_ns, snapshot.timeline.entries[0]?.timestamp_ns ?? entry.timestamp_ns)}
              </time>
              <span className={`timeline-marker timeline-marker-${entry.kind}`} />
              <div className="timeline-content">
                <div className="timeline-meta">
                  <span className="timeline-kind">{timelineKindLabel(entry.kind)}</span>
                  {tlsProvenance(entry) && <span className="provider-hint" title={entry.tls_library ?? undefined}>{tlsProvenance(entry)}</span>}
                  {entry.process_name && <span className="muted">{entry.process_name}</span>}
                  {entry.pid !== null && <span className="muted">PID {entry.pid}</span>}
                  {canInspectPayload(entry) && <span className="payload-hint">click to inspect</span>}
                </div>
                <strong>{entry.summary}</strong>
                <p>{timelineDetail(entry)}</p>
                {timelineBody(entry) && <pre className="timeline-payload">{timelineBody(entry)}</pre>}
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
      </section>}
    </main>
  );
}

export default App;
