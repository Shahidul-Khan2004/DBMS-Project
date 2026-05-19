"use client";

import Link from "next/link";
import type { ReactNode } from "react";

export interface NiersNavbarProps {
  centerContent?: ReactNode;
  trailingContent?: ReactNode;
  ctaHref?: string;
  ctaLabel?: string;
  bottomPanel?: ReactNode;
  contained?: boolean;
}

export function NiersNavbar({
  centerContent,
  trailingContent,
  ctaHref,
  ctaLabel,
  bottomPanel,
  contained = false,
}: NiersNavbarProps) {
  const inner = (
    <div className="niers-nav-inner">
      <div className="flex min-w-0 flex-1 items-center justify-start gap-[var(--nav-gap)]">
        <Link
          href="/"
          className="flex shrink-0 cursor-pointer items-center rounded-md focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#002D62]"
        >
          <div
            className="niers-text-logo bg-[#002D62] font-bold tracking-[-1px] text-white"
            style={{
              paddingInline: "var(--nav-logo-px)",
              paddingBlock: "var(--nav-logo-py)",
            }}
          >
            NIERS
          </div>
        </Link>
        {centerContent}
      </div>

      <div className="flex shrink-0 items-center justify-end gap-[var(--nav-gap)]">
        {trailingContent}
        {ctaHref && ctaLabel ? (
          <Link
            href={ctaHref}
            className="niers-text-body cursor-pointer rounded-2xl border-2 border-primary-600 font-semibold text-primary-600 transition-colors hover:border-primary-700 hover:bg-gray-50 hover:text-primary-700"
            style={{
              paddingInline: "var(--nav-cta-px)",
              paddingBlock: "var(--nav-cta-py)",
            }}
          >
            {ctaLabel}
          </Link>
        ) : null}
      </div>
    </div>
  );

  return (
    <nav className="fixed inset-x-0 top-0 z-50 w-full border-b border-gray-200 bg-zinc-200/95 backdrop-blur-md">
      {contained ? (
        <div className="landing-container">{inner}</div>
      ) : (
        <div className="niers-container">{inner}</div>
      )}
      {bottomPanel}
    </nav>
  );
}
