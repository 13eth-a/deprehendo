"use client";

import { useEffect, useState } from "react";

/**
 * "Use this browser's zone": fills the zone select with the zone the browser
 * reports. Only the browser knows it, so this is the one client part of the
 * display form; without JavaScript the select still works on its own.
 */
export function BrowserZone({ selectId }: { selectId: string }) {
  const [zone, setZone] = useState<string | null>(null);
  useEffect(() => {
    try {
      setZone(Intl.DateTimeFormat().resolvedOptions().timeZone || null);
    } catch {
      setZone(null);
    }
  }, []);
  if (!zone) return null;
  return (
    <button
      type="button"
      className="uv-button uv-button--ghost uv-button--sm"
      onClick={() => {
        const select = document.getElementById(selectId);
        if (select instanceof HTMLSelectElement) select.value = zone;
      }}
    >
      Use this browser&rsquo;s zone ({zone})
    </button>
  );
}
