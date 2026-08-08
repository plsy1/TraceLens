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

type Snapshot = {
  summary: Summary;
  processes: ProcessRow[];
  connections: ConnectionRow[];
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

const initialSnapshot: Snapshot = {
  summary: demoSummary,
  processes: demoProcesses,
  connections: demoConnections,
  mode: "demo",
};

async function fetchJson<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`);
  if (!response.ok) {
    throw new Error(`${path}: ${response.status}`);
  }
  return response.json() as Promise<T>;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "—";
  if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}

function stateLabel(state: string): string {
  return state
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function App() {
  const [snapshot, setSnapshot] = useState<Snapshot>(initialSnapshot);
  const [loading, setLoading] = useState(false);
  const [showClosedConnections, setShowClosedConnections] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const [summary, processes, connections] = await Promise.all([
        fetchJson<Summary>("/api/summary"),
        fetchJson<ProcessRow[]>("/api/processes"),
        fetchJson<ConnectionRow[]>("/api/connections"),
      ]);
      setSnapshot({ summary, processes, connections, mode: "live" });
    } catch {
      setSnapshot((current) => ({ ...current, mode: current.mode === "live" ? "live" : "demo" }));
    } finally {
      setLoading(false);
    }
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
    </main>
  );
}

export default App;
