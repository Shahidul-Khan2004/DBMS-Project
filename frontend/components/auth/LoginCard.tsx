"use client";

import { motion } from "framer-motion";
import React from "react";
import { AuthPageShell } from "@/components/layout/AuthPageShell";
import { useAuthStepMotion } from "@/lib/auth-motion";

interface LoginCardProps {
  children: React.ReactNode;
}

export const LoginCard: React.FC<LoginCardProps> = ({ children }) => {
  const stepMotion = useAuthStepMotion();

  return (
    <AuthPageShell
      variant="login"
      heading={{
        title: "Sign in to NIERS",
        subtitle:
          "Access your National Integrated Emergency Response System workspace.",
      }}
      cta={{ href: "/auth/register", label: "Register" }}
    >
      <section className="w-full">
        <div
          className="flex items-center justify-center rounded-[2rem] border border-[#C9D6E3] bg-[#E8EDF3]/70 shadow-xl shadow-[#002D62]/10 [&_label]:text-[#0F172A] [&_p]:text-[#64748B] [&_[id$='-error']]:text-[#DA291C]"
          style={{ padding: "var(--card-p-login)" }}
        >
          <motion.div
            className="mx-auto w-full max-w-[540px]"
            initial={stepMotion.initial}
            animate={stepMotion.animate}
            transition={stepMotion.transition}
          >
            {children}
          </motion.div>
        </div>
        <p className="mt-3 hidden text-center text-xs text-[#64748B] min-[800px]:block">
          Official NIERS access portal | 2026
        </p>
      </section>
    </AuthPageShell>
  );
};
