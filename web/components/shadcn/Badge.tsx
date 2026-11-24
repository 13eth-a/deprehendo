import type { ComponentProps } from "react";

// shadcn/ui Badge, as listed on 21st.dev (https://21st.dev/@shadcn/components/badge).
// 21st.dev serves the source only through its API, so this follows the same
// component in shadcn/ui (registry/new-york-v4/ui/badge.tsx, MIT, see ./LICENSE).
// The cva variants become `data-variant` and `.badge` rules in styles/vendor.css.
// deprehendo adds the status tones (critical, warning, success, info, brand, direct).

export type BadgeVariant =
  | "default"
  | "secondary"
  | "outline"
  | "critical"
  | "warning"
  | "success"
  | "info"
  | "brand"
  | "direct";

export function Badge({ variant = "outline", className, ...props }: ComponentProps<"span"> & { variant?: BadgeVariant }) {
  return <span data-slot="badge" data-variant={variant} className={["badge", className].filter(Boolean).join(" ")} {...props} />;
}
