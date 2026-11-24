import type { ComponentProps } from "react";

// shadcn/ui Kbd, as listed on 21st.dev (https://21st.dev/@shadcn/components/kbd).
// Source follows shadcn/ui registry/new-york-v4/ui/kbd.tsx (MIT, see ./LICENSE);
// styles are `.kbd` in styles/vendor.css.
export function Kbd({ className, ...props }: ComponentProps<"kbd">) {
  return <kbd data-slot="kbd" className={["kbd", className].filter(Boolean).join(" ")} {...props} />;
}
