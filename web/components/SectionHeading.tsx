import type { ReactNode } from "react";

/** Heading for one part of the incident report, with an optional note on the right. */
export function SectionHeading({ id, children, aside }: { id: string; children: ReactNode; aside?: ReactNode }) {
  return (
    <div className="section-head">
      <h2 id={id}>{children}</h2>
      {aside && <div className="section-aside">{aside}</div>}
    </div>
  );
}
