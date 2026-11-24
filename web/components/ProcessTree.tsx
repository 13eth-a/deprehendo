import type { ProcessSnapshot, Snapshot } from "../types/analysis.ts";
import { buildProcessTree, processKey, processLifetimes, type ProcessNode } from "../lib/processes.ts";
import { formatBytes } from "../lib/format.ts";
import { Clock } from "./Clock.tsx";

/**
 * Process tree at one sample (checklist 7.20): PID, state, RSS, CPU and the
 * observed window. Shape comes from the stored parent PIDs. An orphan appears
 * as its own root.
 */
export function ProcessTree({ series, index }: { series: readonly Snapshot[]; index: number }) {
  const snapshot = series[index];
  const processes: ProcessSnapshot[] = snapshot?.processes ?? [];
  if (!snapshot || processes.length === 0) {
    return (
      <section aria-labelledby="proc-title" className="subsection">
        <h3 id="proc-title" className="subhead">Process tree</h3>
        <p className="muted">No process sample was recorded at this point.</p>
      </section>
    );
  }
  const lifetimes = processLifetimes(series);
  const roots = buildProcessTree(processes);
  return (
    <section aria-labelledby="proc-title" className="subsection">
      <div className="subsection__head">
        <h3 id="proc-title" className="subhead">Process tree</h3>
        <span className="muted small">
          Sample {index + 1} of {series.length} at <Clock iso={snapshot.timestamp} zone />
        </span>
      </div>
      <div className="table-wrap" role="region" aria-label="Process tree" tabIndex={0}>
        <table className="data-table">
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
      </div>
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
        <td style={{ paddingLeft: `${0.75 + depth * 1.25}rem` }}>
          {depth > 0 && <span aria-hidden="true" className="tree-branch">└ </span>}
          {p.name}
        </td>
        <td className="mono">{p.pid}</td>
        <td className="mono">{p.state}</td>
        <td className="mono">{formatBytes(p.rss_bytes)}</td>
        <td className="mono">{p.cpu_percent.toFixed(1)}%</td>
        <td className="mono muted">
          {life
            ? <><Clock iso={life.first} /> – <Clock iso={life.last} /> ({life.samples} sample{life.samples === 1 ? "" : "s"})</>
            : "—"}
        </td>
      </tr>
      {node.children.map((child) => (
        <TreeRows key={processKey(child.process)} node={child} depth={depth + 1} lifetimes={lifetimes} />
      ))}
    </>
  );
}
