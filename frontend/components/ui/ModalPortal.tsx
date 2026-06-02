"use client";

import { type ReactNode, useEffect } from "react";
import { createPortal } from "react-dom";

type ModalPortalProps = {
  open: boolean;
  children: ReactNode;
  className?: string;
};

const DEFAULT_BACKDROP_CLASS =
  "fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4";

export function ModalPortal({
  open,
  children,
  className = DEFAULT_BACKDROP_CLASS,
}: ModalPortalProps) {
  useEffect(() => {
    if (!open || typeof document === "undefined") return;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = previousOverflow;
    };
  }, [open]);

  if (!open) return null;
  if (typeof document === "undefined") return null;

  return createPortal(
    <div className={className} role="dialog" aria-modal="true">
      {children}
    </div>,
    document.body,
  );
}
