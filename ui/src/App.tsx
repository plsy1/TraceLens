type ProcessRow = {
  name: string;
  pid: number;
  connections: number;
  traffic: string;
  level: string;
};

const processes: ProcessRow[] = [
  { name: "chrome", pid: 4821, connections: 48, traffic: "2.8 MB/s", level: "L1" },
  { name: "curl", pid: 12345, connections: 1, traffic: "18 KB/s", level: "L1" },
  { name: "python3", pid: 9172, connections: 3, traffic: "500 MB", level: "L3" },
  { name: "sshd", pid: 1061, connections: 2, traffic: "—", level: "L1" },
];

function App() {
  return (
    <main className="shell">
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark">◌</span>
          <span>TraceLens</span>
        </div>
        <div className="runtime-status">
          <span className="status-dot" />
          Core framework ready
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
          <strong>L1</strong>
          <span>metadata only</span>
        </div>
      </section>

      <section className="metrics">
        <div className="metric-card"><span>Processes</span><strong>4</strong><small>being observed</small></div>
        <div className="metric-card"><span>Connections</span><strong>54</strong><small>active network edges</small></div>
        <div className="metric-card"><span>Domains</span><strong>31</strong><small>correlated from DNS</small></div>
        <div className="metric-card alert-card"><span>Alerts</span><strong>1</strong><small>needs review</small></div>
      </section>

      <section className="content-grid">
        <div className="panel process-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">LIVE INVENTORY</p>
              <h2>Processes</h2>
            </div>
            <button className="ghost-button">Refresh</button>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>Process</th><th>PID</th><th>Connections</th><th>Traffic</th><th>Level</th></tr>
              </thead>
              <tbody>
                {processes.map((process) => (
                  <tr key={process.pid}>
                    <td><span className="process-name">{process.name}</span></td>
                    <td className="muted">{process.pid}</td>
                    <td>{process.connections}</td>
                    <td>{process.traffic}</td>
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
            <span className="risk-pill">1 signal</span>
          </div>
          <div className="focus-item">
            <div className="focus-icon">↗</div>
            <div>
              <strong>python3 uploaded 500 MB</strong>
              <p>suspicious.example · 3 minutes ago</p>
            </div>
            <button className="inspect-button">Deep inspect</button>
          </div>
          <div className="empty-note">
            <span>⌁</span>
            <p>Deep inspection is on-demand.<br />No plaintext is collected at L1.</p>
          </div>
        </div>
      </section>
    </main>
  );
}

export default App;
