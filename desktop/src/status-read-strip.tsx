import React from "react";
import type { StatusReadView } from "./status-read";

export function StatusReadStrip({view}:{view:StatusReadView}) {
  return <div className={`status-read-strip ${view.fresh ? "current" : "delayed"}`} data-status-kind={view.kind}>
    <strong role="status" aria-live="polite">{view.label}</strong>
    <span title={view.message} aria-live="off">{view.message}</span>
  </div>;
}
