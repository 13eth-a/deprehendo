import { failureCopy, type FailureKind } from "../lib/failures.ts";

/**
 * shown in place of data when a page cannot show an analysis (checklist 7.32).
 * it uses role="status" so the change is announced, and it always gives a next
 * step where one exists.
 */
export function FailureState({ kind, detail }: { kind: FailureKind; detail?: string }) {
  const copy = failureCopy(kind);
  return (
    <section className="failure" role="status" aria-labelledby="failure-title">
      <h2 id="failure-title">{copy.title}</h2>
      <p>{copy.body}</p>
      {copy.action && <p>{copy.action}</p>}
      {detail && (
        <p className="muted">
          Detail: <code>{detail}</code>
        </p>
      )}
    </section>
  );
}
