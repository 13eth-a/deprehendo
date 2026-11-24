import type { ReactNode } from "react";

// shadcn/ui Sidebar, as listed on 21st.dev (https://21st.dev/@shadcn/components/sidebar).
// The structure follows shadcn/ui registry/new-york-v4/ui/sidebar.tsx (MIT,
// see ./LICENSE): Sidebar > Header / Content > Group > GroupLabel > Menu >
// MenuItem > MenuButton, Footer, and an Inset for the page. The original's
// collapsible state, mobile sheet and keyboard shortcut need client state and
// Radix; this static version keeps the markup and data attributes and lets
// CSS (`.sidebar*` in styles/vendor.css) turn it into a top bar on narrow
// screens.

export function SidebarLayout({ children }: { children: ReactNode }) {
  return <div className="sidebar-wrapper" data-slot="sidebar-wrapper">{children}</div>;
}

export function Sidebar({ children, label = "Main" }: { children: ReactNode; label?: string }) {
  return (
    <aside className="sidebar" data-slot="sidebar" aria-label={label}>
      {children}
    </aside>
  );
}

export function SidebarHeader({ children }: { children: ReactNode }) {
  return <div className="sidebar__header" data-slot="sidebar-header">{children}</div>;
}

export function SidebarContent({ children }: { children: ReactNode }) {
  return <nav className="sidebar__content" data-slot="sidebar-content" aria-label="Sections">{children}</nav>;
}

export function SidebarGroup({ label, children }: { label?: string; children: ReactNode }) {
  return (
    <div className="sidebar__group" data-slot="sidebar-group">
      {label && <div className="sidebar__group-label" data-slot="sidebar-group-label">{label}</div>}
      <ul className="sidebar__menu" data-slot="sidebar-menu">{children}</ul>
    </div>
  );
}

export function SidebarMenuButton({
  href,
  active = false,
  icon,
  children,
}: {
  href: string;
  active?: boolean;
  icon?: ReactNode;
  children: ReactNode;
}) {
  return (
    <li className="sidebar__menu-item" data-slot="sidebar-menu-item">
      <a
        className="sidebar__menu-button"
        data-slot="sidebar-menu-button"
        data-active={active ? "true" : undefined}
        aria-current={active ? "page" : undefined}
        href={href}
      >
        {icon && <span className="sidebar__icon" aria-hidden="true">{icon}</span>}
        <span>{children}</span>
      </a>
    </li>
  );
}

export function SidebarFooter({ children }: { children: ReactNode }) {
  return <div className="sidebar__footer" data-slot="sidebar-footer">{children}</div>;
}

export function SidebarInset({ children, label }: { children: ReactNode; label?: string }) {
  return (
    <main className="sidebar-inset" data-slot="sidebar-inset" aria-label={label}>
      {children}
    </main>
  );
}
