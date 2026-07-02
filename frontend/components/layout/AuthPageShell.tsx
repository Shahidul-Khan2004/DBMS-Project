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
  const isRegister = variant === "register";

  return (
    <div
      className={`niers-auth-bg min-h-[100svh] ${
        variant === "login" ? "niers-auth-bg--login" : ""
      }`}
    >
      <NiersNavbar ctaHref={cta.href} ctaLabel={cta.label} />
      <main
        className={`niers-auth-main w-full ${
          isRegister ? "niers-auth-main--register" : "niers-auth-main--login"
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
              isRegister
                ? "niers-auth-title--register"
                : "niers-auth-title--login"
            }`}
          >
            {heading.title}
          </h1>
          <p
            className={`max-w-2xl text-slate-600 ${
              isRegister
                ? "mt-2 text-sm leading-6 lg:mt-1"
                : "mt-1.5 text-sm leading-5 max-[699px]:hidden"
            }`}
          >
            {heading.subtitle}
          </p>
        </header>
        <div className={`w-full ${variant === "login" ? "mt-3" : ""}`}>
          {children}
        </div>
      </main>
    </div>
  );
}
