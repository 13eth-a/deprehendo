import { failureCopy, type FailureKind } from "../lib/failures.ts";

/**
 * Shown in place of data when a page cannot show an analysis (checklist 7.32).
 * It uses role="status" so the change is announced, and it always gives a next
 * step where one exists.
 */
export function FailureState({ kind, detail }: { kind: FailureKind; detail?: string }) {
  const copy = failureCopy(kind);
  return (
    <section className="failure panel" role="status" aria-labelledby="failure-title">
      <span className="failure__mark" aria-hidden="true">!</span>
      <div>
        <h2 id="failure-title">{copy.title}</h2>
        <p>{copy.body}</p>
        {copy.action && <p className="muted">{copy.action}</p>}
        {detail && (
          <p className="muted small">
            Detail: <code>{detail}</code>
          </p>
        )}
      </div>
    </section>
  );
}
