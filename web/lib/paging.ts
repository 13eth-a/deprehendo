/**
 * pages over arrays that keep the analyzer's order (7.44). A page is a slice:
 * nothing is re-sorted, so index equals position in the stored document.
 */
export interface Page<T> {
  items: T[];
  /** 1-based page number actually shown (clamped into range). */
  page: number;
  pages: number;
  total: number;
  /** position of items[0] in the full array. */
  start: number;
}

export function pageOf<T>(all: readonly T[], requested: number, size: number): Page<T> {
  if (!Number.isInteger(size) || size < 1) {
    throw new RangeError("page size must be a positive integer");
  }
  const total = all.length;
  const pages = Math.max(1, Math.ceil(total / size));
  const page = Number.isInteger(requested) ? Math.min(Math.max(1, requested), pages) : 1;
  const start = (page - 1) * size;
  return { items: all.slice(start, start + size), page, pages, total, start };
}
