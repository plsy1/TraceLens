import { useCallback, useEffect, useMemo, useState } from "react";

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
};

type TimelinePage = {
  entries: TimelineEntry[];
  total: number;
  offset: number;
  limit: number;
  has_more: boolean;
};

type Snapshot = {
  summary: Summary;
  processes: ProcessRow[];
  connections: ConnectionRow[];
  timeline: TimelinePage;
  mode: "demo" | "live";
};

const API_BASE = import.meta.env.VITE_CORE_API_URL ?? "";

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

const initialSnapshot: Snapshot = {
  summary: demoSummary,
  processes: demoProcesses,
  connections: demoConnections,
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

function buildTimelinePath(kind: string, pid: string, offset: number): string {
  const params = new URLSearchParams({ limit: "50", offset: String(offset) });
  if (kind !== "all") params.set("kind", kind);
  if (/^\d+$/.test(pid.trim())) params.set("pid", pid.trim());
  return `/api/timeline?${params.toString()}`;
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

function stateLabel(state: string): string {
  return state
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function timelineKindLabel(kind: string): string {
  return kind
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function App() {
  const [snapshot, setSnapshot] = useState<Snapshot>(initialSnapshot);
  const [loading, setLoading] = useState(false);
  const [showClosedConnections, setShowClosedConnections] = useState(false);
  const [timelineKind, setTimelineKind] = useState("all");
  const [timelinePidInput, setTimelinePidInput] = useState("");
  const [timelinePid, setTimelinePid] = useState("");

  const timelineRequestPath = useMemo(
    () => buildTimelinePath(timelineKind, timelinePid, 0),
    [timelineKind, timelinePid],
  );

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const [summary, processes, connections, timeline] = await Promise.all([
        fetchJson<Summary>("/api/summary"),
        fetchJson<ProcessRow[]>("/api/processes"),
        fetchJson<ConnectionRow[]>("/api/connections"),
        fetchJson<TimelinePage>(timelineRequestPath),
      ]);
      setSnapshot({ summary, processes, connections, timeline, mode: "live" });
    } catch {
      setSnapshot((current) => ({ ...current, mode: current.mode === "live" ? "live" : "demo" }));
    } finally {
      setLoading(false);
    }
  }, [timelineRequestPath]);

  const loadOlderTimeline = useCallback(async () => {
    const nextOffset = snapshot.timeline.offset + snapshot.timeline.entries.length;
    try {
      const olderPage = await fetchJson<TimelinePage>(
        buildTimelinePath(timelineKind, timelinePid, nextOffset),
      );
      setSnapshot((current) => ({
        ...current,
        timeline: {
          ...olderPage,
          offset: olderPage.offset + olderPage.entries.length,
          entries: [...olderPage.entries, ...current.timeline.entries],
        },
      }));
    } catch {
      // Keep the current page visible if the history request fails.
    }
  }, [snapshot.timeline.entries.length, snapshot.timeline.offset, timelineKind, timelinePid]);

  const applyTimelinePid = useCallback(() => {
    setTimelinePid(timelinePidInput.trim());
  }, [timelinePidInput]);

  const resetTimelineFilters = useCallback(() => {
    setTimelineKind("all");
    setTimelinePidInput("");
    setTimelinePid("");
  }, []);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), 2000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  const processNames = useMemo(
    () => new Map(snapshot.processes.map((process) => [process.pid, process.name])),
    [snapshot.processes],
  );
  const visibleConnections = useMemo(
    () => showClosedConnections
      ? snapshot.connections
      : snapshot.connections.filter((connection) => connection.state !== "closed"),
    [showClosedConnections, snapshot.connections],
  );
  const isLive = snapshot.mode === "live";
  const statusText = isLive ? "Core connected" : "Core offline · demo data";
  const focusTitle = isLive ? "No alerts from Core" : "python3 uploaded 500 MB";
  const focusDetail = isLive ? "Detection rules will appear here as the event pipeline grows." : "suspicious.example · 3 minutes ago";

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
            <button className="ghost-button" onClick={() => void refresh()} disabled={loading}>
              {loading ? "Loading" : "Refresh"}
            </button>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>Process</th><th>PID</th><th>Connections</th><th>Traffic</th><th>Level</th></tr>
              </thead>
              <tbody>
                {snapshot.processes.length === 0 ? (
                  <tr><td colSpan={5} className="muted empty-cell">No processes observed yet.</td></tr>
                ) : snapshot.processes.map((process) => (
                  <tr key={process.pid}>
                    <td><span className="process-name">{process.name}</span></td>
                    <td className="muted">{process.pid}</td>
                    <td>{process.connections}</td>
                    <td>{formatBytes(process.sent_bytes + process.received_bytes)}</td>
                    <td><span className={`level level-${process.level.toLowerCase()}`}>{process.level}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="panel focus-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">FOCUS QUEUE</p>
              <h2>Needs attention</h2>
            </div>
            <span className="risk-pill">{snapshot.summary.alerts} signal{snapshot.summary.alerts === 1 ? "" : "s"}</span>
          </div>
          <div className="focus-item">
            <div className="focus-icon">↗</div>
            <div>
              <strong>{focusTitle}</strong>
              <p>{focusDetail}</p>
            </div>
            <button className="inspect-button" disabled>Deep inspect</button>
          </div>
          <div className="empty-note">
            <span>⌁</span>
            <p>Deep inspection is on-demand.<br />No plaintext is collected at L1.</p>
          </div>
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
                onChange={(event) => setShowClosedConnections(event.target.checked)}
              />
              Show closed
            </label>
            <span className="connection-count">
              {showClosedConnections ? `${snapshot.connections.length} observed` : `${visibleConnections.length} active`}
            </span>
          </div>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>Process</th><th>PID</th><th>Remote</th><th>Domain</th><th>State</th><th>Traffic</th></tr>
            </thead>
            <tbody>
              {visibleConnections.length === 0 ? (
                <tr><td colSpan={6} className="muted empty-cell">
                  {showClosedConnections ? "No connections observed yet." : "No active connections. Enable Show closed to inspect history."}
                </td></tr>
              ) : visibleConnections.slice(0, 20).map((connection) => (
                <tr key={connection.id}>
                  <td><span className="process-name">{connection.process_name ?? (connection.pid ? processNames.get(connection.pid) ?? `exited (${connection.pid})` : "unknown")}</span></td>
                  <td className="muted">{connection.pid ?? "—"}</td>
                  <td>{connection.remote.address}:{connection.remote.port}</td>
                  <td className="muted">{connection.domain ?? "—"}</td>
                  <td><span className={`state state-${connection.state}`}>{stateLabel(connection.tcp_state ?? connection.state)}</span></td>
                  <td>{formatBytes(connection.sent_bytes + connection.received_bytes)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel timeline-panel">
        <div className="panel-heading timeline-heading">
          <div>
            <p className="eyebrow">UNIFIED EVENT STREAM</p>
            <h2>Timeline</h2>
          </div>
          <div className="timeline-toolbar">
            <label className="timeline-filter">
              <span>Event</span>
              <select value={timelineKind} onChange={(event) => setTimelineKind(event.target.value)}>
                <option value="all">All events</option>
                <option value="process_exec">Process start</option>
                <option value="process_exit">Process exit</option>
                <option value="dns_query">DNS query</option>
                <option value="dns_response">DNS response</option>
                <option value="tcp_connect">TCP connect</option>
                <option value="tcp_state_changed">TCP state</option>
                <option value="tcp_bytes">TCP bytes</option>
                <option value="tcp_close">TCP close</option>
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
                  if (event.key === "Enter") applyTimelinePid();
                }}
              />
            </label>
            <button className="ghost-button" onClick={applyTimelinePid} disabled={loading}>Apply</button>
            <button className="ghost-button" onClick={resetTimelineFilters} disabled={loading}>Reset</button>
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
                <p>
                  {entry.addresses.length > 0
                    ? entry.addresses.join(", ")
                    : entry.remote
                      ? `${entry.remote.address}:${entry.remote.port}`
                      : entry.domain ?? entry.protocol ?? "metadata event"}
                </p>
              </div>
            </article>
          ))}
        </div>
        {snapshot.timeline.has_more && (
          <div className="timeline-footer">
            <button className="ghost-button timeline-load-more" onClick={() => void loadOlderTimeline()}>
              Load older events
            </button>
          </div>
        )}
      </section>
    </main>
  );
}

export default App;
