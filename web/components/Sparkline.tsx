import { useId } from "react";

import type { Snapshot } from "../types/analysis.ts";
import { systemPercentSeries, toSvgPaths } from "../lib/series.ts";
import { formatClock } from "../lib/format.ts";

/**
 * Host CPU over the capture, with the trigger marked (checklist 7.19). The
 * chart carries a text summary, so the same numbers reach a screen reader and
 * a reader without color perception (7.45). It draws only stored samples:
 * a missing sample is a gap, never a zero.
 */
export function CpuChart({ series, triggeredAt }: { series: readonly Snapshot[]; triggeredAt?: string }) {
  const gradientId = useId();
  const metric = systemPercentSeries(series, triggeredAt);
  if (!metric.range) {
    return (
      <section aria-labelledby="cpu-title" className="subsection">
        <h3 id="cpu-title" className="subhead">Host CPU</h3>
        <p className="muted">No CPU percentage was captured in this incident.</p>
      </section>
    );
  }
  const width = 600;
  const height = 120;
  const { segments, x } = toSvgPaths(metric, width, height);
  const last = [...metric.points].reverse().find((p) => p.value !== null);
  const summary = `CPU ranged from ${metric.range.min.toFixed(1)}% to ${metric.range.max.toFixed(1)}% over ${metric.points.length} samples.`;
  return (
    <section aria-labelledby="cpu-title" className="subsection">
      <div className="subsection__head">
        <h3 id="cpu-title" className="subhead">Host CPU</h3>
        <span className="muted small">{summary}</span>
      </div>
      <div className="chart">
        <svg
          role="img"
          aria-label={summary}
          viewBox={`0 0 ${width} ${height}`}
          width="100%"
          height="120"
          preserveAspectRatio="none"
        >
          <defs>
            <linearGradient id={gradientId} x1="0" x2="0" y1="0" y2="1">
              <stop offset="0%" stopColor="var(--chart-line)" stopOpacity="0.22" />
              <stop offset="100%" stopColor="var(--chart-line)" stopOpacity="0" />
            </linearGradient>
          </defs>
          {[0.25, 0.5, 0.75].map((f) => (
            <line key={f} x1={0} x2={width} y1={height * f} y2={height * f} className="chart__grid" />
          ))}
          {segments.map((d, i) => (
            <path key={`a${i}`} d={`${d} V${height} H${d.match(/^M([\d.]+)/)?.[1] ?? 0} Z`} fill={`url(#${gradientId})`} stroke="none" />
          ))}
          {segments.map((d, i) => (
            <path key={i} d={d} fill="none" className="chart__line" strokeWidth={1.75} vectorEffect="non-scaling-stroke" />
          ))}
          {metric.triggerIndex >= 0 && (
            <line
              x1={x(metric.triggerIndex)}
              x2={x(metric.triggerIndex)}
              y1={0}
              y2={height}
              className="chart__trigger"
              strokeDasharray="4 4"
              vectorEffect="non-scaling-stroke"
              data-marker="trigger"
            />
          )}
        </svg>
      </div>
      <p className="muted small">
        {metric.triggerIndex >= 0
          ? `Dashed orange line: trigger, sample ${metric.triggerIndex} at ${formatClock(series[metric.triggerIndex]!.timestamp)} UTC.`
          : "The trigger falls outside the captured samples."}
        {last ? ` Last captured value: ${last.value!.toFixed(1)}%.` : ""}
      </p>
    </section>
  );
}
