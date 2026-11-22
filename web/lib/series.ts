import type { Snapshot } from "../types/analysis.ts";
import { epochNanos } from "./format.ts";

/**
 * chart input taken from the stored series. values keep capture order, so
 * index equals position (7.44). A sample without the sensor is null, and a
 * chart must show a gap there, never a zero.
 */
export interface SeriesPoint {
  index: number;
  timestamp: string;
  value: number | null;
}

export interface MetricSeries {
  points: SeriesPoint[];
  /** position of the first sample at or after the trigger; -1 if none. */
  triggerIndex: number;
  /** minimum and maximum of the non-null values, or null when there are none. */
  range: { min: number; max: number } | null;
}

export function systemPercentSeries(series: readonly Snapshot[], triggeredAt: string | undefined): MetricSeries {
  const points: SeriesPoint[] = series.map((snapshot, index) => {
    const system = snapshot.system;
    const value = system && system.cpu_percent_available ? system.cpu_percent : null;
    return { index, timestamp: snapshot.timestamp, value };
  });
  const trigger = triggeredAt ? epochNanos(triggeredAt) : null;
  let triggerIndex = -1;
  if (trigger !== null) {
    for (const point of points) {
      const at = epochNanos(point.timestamp);
      if (at !== null && at >= trigger) {
        triggerIndex = point.index;
        break;
      }
    }
  }
  const values = points.map((p) => p.value).filter((v): v is number => v !== null);
  const range = values.length === 0 ? null : { min: Math.min(...values), max: Math.max(...values) };
  return { points, triggerIndex, range };
}

/** maps points into SVG coordinates. null values produce no point (a gap). */
export function toSvgPaths(metric: MetricSeries, width: number, height: number): { segments: string[]; x: (i: number) => number } {
  const n = metric.points.length;
  const x = (i: number) => (n <= 1 ? 0 : (i / (n - 1)) * width);
  const { range } = metric;
  const span = range && range.max > range.min ? range.max - range.min : 1;
  const y = (v: number) => (range ? height - ((v - range.min) / span) * height : height);
  const segments: string[] = [];
  let current = "";
  for (const point of metric.points) {
    if (point.value === null) {
      if (current) segments.push(current);
      current = "";
      continue;
    }
    const command = current === "" ? "M" : "L";
    current += `${command}${x(point.index).toFixed(1)},${y(point.value).toFixed(1)} `;
  }
  if (current) segments.push(current.trim());
  return { segments, x };
}
