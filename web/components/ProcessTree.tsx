import type { ProcessSnapshot, Snapshot } from "../types/analysis.ts";
import { buildProcessTree, processKey, processLifetimes, type ProcessNode } from "../lib/processes.ts";
import { formatBytes, formatClock } from "../lib/format.ts";

/**
 * process tree at one sample (checklist 7.20): PID, state, RSS, CPU and the
 * observed window. shape comes from the stored parent PIDs. an orphan appears
 * as its own root.
 */
export function ProcessTree({ series, index }: { series: readonly Snapshot[]; index: number }) {
  const snapshot = series[index];
  const processes: ProcessSnapshot[] = snapshot?.processes ?? [];
  if (!snapshot || processes.length === 0) {
    return (
      <section aria-labelledby="proc-title">
        <h2 id="proc-title">Process tree</h2>
        <p>No process sample was recorded at this point.</p>
      </section>
    );
  }
  const lifetimes = processLifetimes(series);
  const roots = buildProcessTree(processes);
  return (
    <section aria-labelledby="proc-title">
      <h2 id="proc-title">Process tree</h2>
      <p className="muted">Sample {index + 1} of {series.length} at {formatClock(snapshot.timestamp)} UTC</p>
      <table>
        <caption>Processes in sample {index + 1}</caption>
        <thead>
          <tr>
            <th scope="col">Process</th>
            <th scope="col">PID</th>
            <th scope="col">State</th>
            <th scope="col">RSS</th>
            <th scope="col">CPU</th>
            <th scope="col">Observed</th>
          </tr>
        </thead>
        <tbody>
          {roots.map((root) => (
            <TreeRows key={processKey(root.process)} node={root} depth={0} lifetimes={lifetimes} />
          ))}
        </tbody>
      </table>
    </section>
  );
}

function TreeRows({
  node,
  depth,
  lifetimes,
}: {
  node: ProcessNode;
  depth: number;
  lifetimes: ReturnType<typeof processLifetimes>;
}) {
  const p = node.process;
  const life = lifetimes.get(processKey(p));
  return (
    <>
      <tr id={`proc-${p.pid}`}>
        <td style={{ paddingLeft: `${depth * 1.25}rem` }}>
          {depth > 0 && <span aria-hidden="true">└ </span>}
          {p.name}
        </td>
        <td>{p.pid}</td>
        <td>{p.state}</td>
        <td>{formatBytes(p.rss_bytes)}</td>
        <td>{p.cpu_percent.toFixed(1)}%</td>
        <td>
          {life
            ? `${formatClock(life.first)} – ${formatClock(life.last)} (${life.samples} sample${life.samples === 1 ? "" : "s"})`
            : "—"}
        </td>
      </tr>
      {node.children.map((child) => (
        <TreeRows key={processKey(child.process)} node={child} depth={depth + 1} lifetimes={lifetimes} />
      ))}
    </>
  );
}
