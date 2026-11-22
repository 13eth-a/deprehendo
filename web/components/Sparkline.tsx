import type { Snapshot } from "../types/analysis.ts";
import { systemPercentSeries, toSvgPaths } from "../lib/series.ts";
import { formatClock } from "../lib/format.ts";

/**
 * host CPU over the capture, with the trigger marked (checklist 7.19). the
 * chart carries a text summary, so the same numbers reach a screen reader and
 * a reader without colour perception (7.45). it draws only stored samples.
 */
export function CpuChart({ series, triggeredAt }: { series: readonly Snapshot[]; triggeredAt?: string }) {
  const metric = systemPercentSeries(series, triggeredAt);
  if (!metric.range) {
    return (
      <section aria-labelledby="cpu-title">
        <h2 id="cpu-title">CPU</h2>
        <p>No CPU percentage was captured in this incident.</p>
      </section>
    );
  }
  const width = 600;
  const height = 120;
  const { segments, x } = toSvgPaths(metric, width, height);
  const last = [...metric.points].reverse().find((p) => p.value !== null);
  const summary = `CPU ranged from ${metric.range.min.toFixed(1)}% to ${metric.range.max.toFixed(1)}% over ${metric.points.length} samples.`;
  return (
    <section aria-labelledby="cpu-title">
      <h2 id="cpu-title">CPU</h2>
      <p>{summary}</p>
      <svg
        role="img"
        aria-label={summary}
        viewBox={`0 0 ${width} ${height}`}
        width="100%"
        preserveAspectRatio="none"
      >
        {segments.map((d, i) => (
          <path key={i} d={d} fill="none" stroke="currentColor" strokeWidth={2} />
        ))}
        {metric.triggerIndex >= 0 && (
          <line
            x1={x(metric.triggerIndex)}
            x2={x(metric.triggerIndex)}
            y1={0}
            y2={height}
            stroke="currentColor"
            strokeDasharray="4 4"
            data-marker="trigger"
          />
        )}
      </svg>
      <p className="muted">
        {metric.triggerIndex >= 0
          ? `Dashed line: trigger, sample ${metric.triggerIndex} at ${formatClock(series[metric.triggerIndex]!.timestamp)} UTC.`
          : "The trigger falls outside the captured samples."}
        {last ? ` Last captured value: ${last.value!.toFixed(1)}%.` : ""}
      </p>
    </section>
  );
}
