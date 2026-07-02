"use client";

import { ChevronDown, ChevronUp, KeyRound } from "lucide-react";
import React, { useEffect, useState } from "react";
import { publicGet } from "@/lib/api";
import type { DemoAccountsResponse } from "@/types/demo-accounts";

interface DemoAccountsPanelProps {
  onUseAccount: (account: { email: string; password: string }) => void;
}

function formatRoleLabel(role: string) {
  return role
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

export const DemoAccountsPanel: React.FC<DemoAccountsPanelProps> = ({
  onUseAccount,
}) => {
  const [expanded, setExpanded] = useState(false);
  const [data, setData] = useState<DemoAccountsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    publicGet<DemoAccountsResponse>("/public/demo-accounts")
      .then((response) => {
        if (!cancelled) {
          setData(response);
          setError(null);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setError("Demo accounts are unavailable right now.");
        }
      });

    return () => {
      cancelled = true;
    };
  }, []);

  if (error) {
    return (
      <div className="rounded-xl border border-[#C9D6E3] bg-[#F7F9FC] px-3 py-2 text-xs text-[#64748B]">
        {error}
      </div>
    );
  }

  if (!data || data.groups.length === 0) {
    return null;
  }

  return (
    <section className="rounded-xl border border-[#C9D6E3] bg-[#F7F9FC]">
      <button
        type="button"
        onClick={() => setExpanded((current) => !current)}
        className="flex w-full items-center justify-between gap-2 px-3 py-2 text-left"
        aria-expanded={expanded}
      >
        <div className="flex min-w-0 items-center gap-2">
          <KeyRound className="h-4 w-4 shrink-0 text-[#002D62]" aria-hidden />
          <p className="truncate text-sm font-semibold text-[#002D62]">
            Demo accounts
          </p>
        </div>
        {expanded ? (
          <ChevronUp className="h-4 w-4 shrink-0 text-[#64748B]" aria-hidden />
        ) : (
          <ChevronDown className="h-4 w-4 shrink-0 text-[#64748B]" aria-hidden />
        )}
      </button>

      {expanded ? (
        <div className="max-h-[22svh] space-y-2 overflow-y-auto border-t border-[#C9D6E3] px-3 py-2">
          <p className="text-xs text-[#64748B]">
            Explore NIERS with pre-configured roles and passwords.
          </p>
          {data.groups.map((group) => (
            <div key={group.role} className="space-y-1.5">
              <div className="flex flex-wrap items-baseline justify-between gap-1">
                <h3 className="text-[0.65rem] font-semibold uppercase tracking-wide text-[#002D62]">
                  {group.roleLabel || formatRoleLabel(group.role)}
                </h3>
                <p className="text-[0.65rem] text-[#64748B]">
                  Password:{" "}
                  <span className="font-mono text-[#0F172A]">{group.password}</span>
                </p>
              </div>

              <ul className="space-y-1">
                {group.accounts.map((account) => (
                  <li
                    key={account.email}
                    className="flex items-center justify-between gap-2 rounded-lg border border-[#C9D6E3] bg-white px-2 py-1.5"
                  >
                    <div className="min-w-0">
                      {account.label ? (
                        <p className="truncate text-xs font-medium text-[#0F172A]">
                          {account.label}
                        </p>
                      ) : null}
                      <p className="truncate font-mono text-[0.65rem] text-[#64748B]">
                        {account.email}
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={() =>
                        onUseAccount({
                          email: account.email,
                          password: account.password,
                        })
                      }
                      className="shrink-0 rounded-md border border-[#002D62]/20 bg-[#002D62]/5 px-2 py-1 text-[0.65rem] font-semibold text-[#002D62] transition-colors hover:bg-[#002D62]/10"
                    >
                      Use
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      ) : null}
    </section>
  );
};
