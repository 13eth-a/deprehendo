// Client components that call useRouter() need a mounted app router: Next's
// real hook throws without one. This mounts a do-nothing router through the
// same context Next's <AppRouter> provides, for rendering in tests only.
import { createRequire } from "node:module";
import type { Context, ReactNode } from "react";

const { AppRouterContext } = createRequire(import.meta.url)(
  "next/dist/shared/lib/app-router-context.shared-runtime",
) as { AppRouterContext: Context<unknown> };

const noop = () => {};
export const testRouter = { back: noop, forward: noop, refresh: noop, hmrRefresh: noop, push: noop, replace: noop, prefetch: noop };

export function withRouter(node: ReactNode) {
  return <AppRouterContext.Provider value={testRouter}>{node}</AppRouterContext.Provider>;
}
