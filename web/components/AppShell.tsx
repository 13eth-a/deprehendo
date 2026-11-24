import type { ReactNode } from "react";

import { SignOutButton } from "./AuthForms.tsx";
import { Logo } from "./Logo.tsx";
import { OrgSwitcher } from "./OrgSwitcher.tsx";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarHeader,
  SidebarInset,
  SidebarLayout,
  SidebarMenuButton,
} from "./shadcn/Sidebar.tsx";

export type AppSection = "incidents" | "org" | "account" | "install";

/**
 * Frame for signed-in pages: a small sidebar (investigation first, then the
 * organization) and the page. Subsystems such as processes or sockets are not
 * navigation; they live inside an incident. The sample incident is a
 * signed-out page only, so it has no entry here.
 */
export function AppShell({
  email,
  organization,
  active,
  label,
  orgSlot,
  children,
}: {
  email: string;
  organization: string | null;
  active?: AppSection;
  label?: string;
  /** Replaces the live organization switcher; for previews and tests that render without the API. */
  orgSlot?: ReactNode;
  children: ReactNode;
}) {
  return (
    <SidebarLayout>
      <Sidebar>
        <SidebarHeader>
          <Logo href="/incidents" />
        </SidebarHeader>
        <SidebarContent>
          <SidebarGroup label="Investigate">
            <SidebarMenuButton href="/incidents" active={active === "incidents"}>
              Incidents
            </SidebarMenuButton>
          </SidebarGroup>
          <SidebarGroup label="Workspace">
            <SidebarMenuButton href="/org" active={active === "org"}>
              Organizations
            </SidebarMenuButton>
            <SidebarMenuButton href="/account" active={active === "account"}>
              Account
            </SidebarMenuButton>
            <SidebarMenuButton href="/install" active={active === "install"}>
              Install agent
            </SidebarMenuButton>
          </SidebarGroup>
        </SidebarContent>
        <SidebarFooter>
          {orgSlot !== undefined ? orgSlot : <OrgSwitcher current={organization} />}
          <a className="sidebar__user" href="/account" title={`${email} · account settings`}>{email}</a>
          <SignOutButton />
        </SidebarFooter>
      </Sidebar>
      <SidebarInset label={label}>{children}</SidebarInset>
    </SidebarLayout>
  );
}
