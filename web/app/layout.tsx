import type { ReactNode } from "react";

import "../styles/dashboard.css";

export const metadata = {
  title: "deprehendo",
  description: "Know why your self-hosted CI runner died.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
