/**
 * The deprehendo mark and wordmark. The construction is specified in
 * web/BRAND.md; the numbers below are that spec, not tuned by eye per use.
 *
 * Mark: a lowercase d on a 14 x 20 unit grid. Stroke 3 units; the bowl is
 * x-height tall (14 units) and the stem rises to the ascender (20 units), so
 * at lockup size the mark has the same heights as the wordmark's own letters.
 * The 8 x 8 counter holds one 4 x 4 square in recorder orange: a reading
 * caught inside the letter ("deprehendo": I catch, I detect). The filled
 * square is the same sign the interface uses for direct evidence.
 */
export const MARK_PATH = "M0 6H11V0H14V20H0ZM3 9V17H11V9Z";
export const MARK_DOT = { x: 5, y: 11, size: 4 } as const;

/** The mark alone. One color when `accent` is false (print, embossing, single-ink use). */
export function Mark({ size = 20, accent = true, title }: { size?: number; accent?: boolean; title?: string }) {
  return (
    <svg
      className="mark"
      width={(size * 14) / 20}
      height={size}
      viewBox="0 0 14 20"
      role={title ? "img" : undefined}
      aria-label={title}
      aria-hidden={title ? undefined : true}
      focusable="false"
    >
      <path fill="currentColor" fillRule="evenodd" d={MARK_PATH} />
      <rect
        x={MARK_DOT.x}
        y={MARK_DOT.y}
        width={MARK_DOT.size}
        height={MARK_DOT.size}
        fill={accent ? "var(--accent)" : "currentColor"}
      />
    </svg>
  );
}

/**
 * Horizontal lockup: mark, then the wordmark. The mark is sized in em, so it
 * tracks the wordmark at any font size; the gap is the counter's width.
 */
export function Logo({ href = "/" }: { href?: string }) {
  return (
    <a className="logo" href={href} aria-label="deprehendo home">
      <svg className="logo__mark" viewBox="0 0 14 20" aria-hidden="true" focusable="false">
        <path fill="currentColor" fillRule="evenodd" d={MARK_PATH} />
        <rect x={MARK_DOT.x} y={MARK_DOT.y} width={MARK_DOT.size} height={MARK_DOT.size} fill="var(--accent)" />
      </svg>
      <span className="logo__word">deprehendo</span>
    </a>
  );
}
