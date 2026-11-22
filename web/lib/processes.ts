import type { ProcessSnapshot, Snapshot } from "../types/analysis.ts";

/**
 * process identity and tree shape, both read from stored fields (7.20).
 * A process is identified by PID together with its start time: a reused PID
 * is a different process (the same rule as ConnectionSnapshot.StartTicks).
 */
export function processKey(p: Pick<ProcessSnapshot, "pid" | "start_ticks">): string {
  return `${p.pid}@${p.start_ticks ?? 0}`;
}

export interface ProcessNode {
  process: ProcessSnapshot;
  children: ProcessNode[];
}

/**
 * builds the tree from the stored parent PIDs. A process whose parent is not
 * in this sample becomes a root, so orphans show up instead of disappearing.
 * A link that would close a loop (A under B and B under A) is cut, so both
 * processes stay visible and the result is always a finite tree. children keep
 * the stored order.
 */
export function buildProcessTree(processes: readonly ProcessSnapshot[]): ProcessNode[] {
  const parentOf = new Map<number, number>();
  const nodes = new Map<number, ProcessNode>();
  for (const process of processes) {
    if (!nodes.has(process.pid)) {
      nodes.set(process.pid, { process, children: [] });
      parentOf.set(process.pid, process.ppid);
    }
  }
  const linksToSelf = (pid: number, ppid: number): boolean => {
    const seen = new Set<number>();
    let current: number | undefined = ppid;
    while (current !== undefined && !seen.has(current)) {
      if (current === pid) return true;
      seen.add(current);
      current = parentOf.get(current);
    }
    return false;
  };
  const roots: ProcessNode[] = [];
  for (const process of processes) {
    const node = nodes.get(process.pid);
    if (!node || node.process !== process) continue;
    const parent =
      process.ppid !== process.pid && nodes.has(process.ppid) && !linksToSelf(process.pid, process.ppid)
        ? nodes.get(process.ppid)
        : undefined;
    if (parent) parent.children.push(node);
    else roots.push(node);
  }
  return roots;
}

export interface Lifetime {
  first: string;
  last: string;
  samples: number;
}

/**
 * first and last sample at which each process identity was seen, in capture
 * order. this is what "start/end" means in 7.20: the observed window, not a
 * recorded exit.
 */
export function processLifetimes(series: readonly Snapshot[]): Map<string, Lifetime> {
  const out = new Map<string, Lifetime>();
  for (const snapshot of series) {
    for (const process of snapshot.processes ?? []) {
      const key = processKey(process);
      const seen = out.get(key);
      if (seen) {
        seen.last = snapshot.timestamp;
        seen.samples += 1;
      } else {
        out.set(key, { first: snapshot.timestamp, last: snapshot.timestamp, samples: 1 });
      }
    }
  }
  return out;
}
