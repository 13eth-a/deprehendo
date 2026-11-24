import type { ReactNode } from "react";

// shadcn/ui Empty, as listed on 21st.dev (https://21st.dev/@shadcn/components/empty).
// Structure follows shadcn/ui registry/new-york-v4/ui/empty.tsx (MIT, see
// ./LICENSE): header (media, title, description) and content. Styles are
// `.empty*` in styles/vendor.css.
export function Empty({
  icon,
  title,
  titleId,
  description,
  children,
}: {
  icon?: ReactNode;
  title: ReactNode;
  titleId?: string;
  description?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <section data-slot="empty" className="empty" aria-labelledby={titleId}>
      <div className="empty__header">
        {icon && <div className="empty__media" aria-hidden="true">{icon}</div>}
        <h2 id={titleId} className="empty__title">{title}</h2>
        {description && <div className="empty__description">{description}</div>}
      </div>
      {children && <div className="empty__content">{children}</div>}
    </section>
  );
}
