import { Logo } from "./Logo.tsx";

/**
 * Header for signed-out pages: landing, install, sample incident, sign-in.
 * Signed-in visitors never see it; those pages send them to the dashboard or
 * render inside the app frame instead.
 */
export function PublicHeader({ current }: { current?: "install" | "demo" | "auth" }) {
  return (
    <header className="public-header">
      <div className="public-header__inner">
        <Logo />
        <nav aria-label="Site">
          <a href="/install" aria-current={current === "install" ? "page" : undefined}>Install</a>
          <a href="/demo" aria-current={current === "demo" ? "page" : undefined}>Sample incident</a>
          <a href="/auth/sign-in" aria-current={current === "auth" ? "page" : undefined}>Sign in</a>
        </nav>
      </div>
    </header>
  );
}

export function SiteFooter() {
  return (
    <footer className="site-footer">
      <div className="site-footer__inner">
        <span>deprehendo</span>
        <span>Every diagnosis comes from the analyzer and the evidence it stored.</span>
      </div>
    </footer>
  );
}
