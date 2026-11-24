import type { ConnectionSnapshot, ProcessSnapshot, Snapshot } from "../types/analysis.ts";

/**
 * TCP connections at one sample (checklist 7.21). The owning process is
 * resolved from the same sample by PID. A connection with no recorded owner
 * says "owner not recorded" instead of guessing.
 *
 * Not yet shown: the NO RX highlight. It needs per-socket receive counters,
 * which the stored document does not carry yet (ConnectionSnapshot has no
 * such fields in the fixtures).
 */
export function NetworkTable({ series, index }: { series: readonly Snapshot[]; index: number }) {
  const snapshot = series[index];
  const connections: ConnectionSnapshot[] = snapshot?.connections ?? [];
  if (!snapshot || connections.length === 0) {
    return (
      <section aria-labelledby="net-title" className="subsection">
        <h3 id="net-title" className="subhead">Network connections</h3>
        <p className="muted">No connection sample was recorded at this point.</p>
      </section>
    );
  }
  const owners = new Map<number, ProcessSnapshot>();
  for (const process of snapshot.processes ?? []) owners.set(process.pid, process);
  return (
    <section aria-labelledby="net-title" className="subsection">
      <h3 id="net-title" className="subhead">Network connections</h3>
      <div className="table-wrap" role="region" aria-label="Network connections" tabIndex={0}>
        <table className="data-table">
          <caption>Connections in sample {index + 1}</caption>
          <thead>
            <tr>
              <th scope="col">Owner</th>
              <th scope="col">Local</th>
              <th scope="col">Remote</th>
              <th scope="col">State</th>
            </tr>
          </thead>
          <tbody>
            {connections.map((connection) => {
              const owner = connection.pid ? owners.get(connection.pid) : undefined;
              return (
                <tr key={`${connection.inode ?? "x"}-${connection.local_port}-${connection.remote_port}-${connection.remote_addr}`}>
                  <td>
                    {connection.pid ? (
                      <>
                        {owner?.name ?? "process not in sample"} <span className="mono muted">PID {connection.pid}</span>
                      </>
                    ) : (
                      <span className="muted">owner not recorded</span>
                    )}
                  </td>
                  <td className="mono">
                    {connection.local_addr}:{connection.local_port}
                  </td>
                  <td className="mono">
                    {connection.remote_addr}:{connection.remote_port}
                  </td>
                  <td className="mono">{connection.state}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}
