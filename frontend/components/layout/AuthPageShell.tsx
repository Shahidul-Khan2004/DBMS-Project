"use client";

import type { ReactNode } from "react";
import { NiersNavbar } from "@/components/layout/NiersNavbar";

/**
 * Auth page shell: gradient background, fixed navbar, and main content offset.
 * Use for login/register; public marketing pages use NiersNavbar + .landing-page.
 */
export interface AuthPageShellProps {
  heading: { title: string; subtitle: string };
  cta: { href: string; label: string };
  variant: "login" | "register";
  children: ReactNode;
}

export function AuthPageShell({
  heading,
  cta,
  variant,
  children,
}: AuthPageShellProps) {
  const contentMax =
    variant === "register" ? "max-w-[1720px]" : "max-w-[800px]";
  const isRegister = variant === "register";

  return (
    <div className="niers-auth-bg min-h-[100svh]">
      <NiersNavbar ctaHref={cta.href} ctaLabel={cta.label} />
      <main
        className={`niers-auth-main mx-auto w-full ${
          isRegister
            ? "niers-auth-main--register max-w-[1720px]"
            : "niers-auth-main--login"
        }`}
      >
        <header
          className={`shrink-0 ${
            variant === "login"
              ? "mx-auto max-w-xl text-center"
              : "mb-8 max-w-xl lg:mb-7"
          }`}
        >
          <h1
            className={`niers-auth-title font-extrabold tracking-tight text-[#002D62] ${
              isRegister ? "niers-auth-title--register" : ""
            }`}
          >
            {heading.title}
          </h1>
          <p
            className={`max-w-2xl text-slate-600 ${
              isRegister
                ? "mt-2 text-sm leading-6 lg:mt-1"
                : "mt-3 text-base leading-7"
            }`}
          >
            {heading.subtitle}
          </p>
        </header>
        <div
          className={`mx-auto w-full ${contentMax} ${
            variant === "login" ? "mt-6" : ""
          }`}
        >
          {children}
        </div>
      </main>
    </div>
  );
}
