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
  const [expanded, setExpanded] = useState(true);
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
      <div className="rounded-2xl border border-[#C9D6E3] bg-[#F7F9FC] px-4 py-3 text-sm text-[#64748B]">
        {error}
      </div>
    );
  }

  if (!data || data.groups.length === 0) {
    return null;
  }

  return (
    <section className="rounded-2xl border border-[#C9D6E3] bg-[#F7F9FC]">
      <button
        type="button"
        onClick={() => setExpanded((current) => !current)}
        className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left"
        aria-expanded={expanded}
      >
        <div className="flex items-center gap-2">
          <span className="inline-flex h-8 w-8 items-center justify-center rounded-xl bg-[#002D62]/10 text-[#002D62]">
            <KeyRound className="h-4 w-4" aria-hidden />
          </span>
          <div>
            <p className="text-sm font-semibold text-[#002D62]">Demo accounts</p>
            <p className="text-xs text-[#64748B]">
              Explore NIERS with pre-configured roles and passwords.
            </p>
          </div>
        </div>
        {expanded ? (
          <ChevronUp className="h-4 w-4 shrink-0 text-[#64748B]" aria-hidden />
        ) : (
          <ChevronDown className="h-4 w-4 shrink-0 text-[#64748B]" aria-hidden />
        )}
      </button>

      {expanded ? (
        <div className="space-y-4 border-t border-[#C9D6E3] px-4 py-4">
          {data.groups.map((group) => (
            <div key={group.role} className="space-y-2">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <h3 className="text-xs font-semibold uppercase tracking-wide text-[#002D62]">
                  {group.roleLabel || formatRoleLabel(group.role)}
                </h3>
                <p className="text-xs text-[#64748B]">
                  Password:{" "}
                  <span className="font-mono text-[#0F172A]">{group.password}</span>
                </p>
              </div>

              <ul className="space-y-2">
                {group.accounts.map((account) => (
                  <li
                    key={account.email}
                    className="flex flex-col gap-2 rounded-xl border border-[#C9D6E3] bg-white px-3 py-2 sm:flex-row sm:items-center sm:justify-between"
                  >
                    <div className="min-w-0">
                      {account.label ? (
                        <p className="text-sm font-medium text-[#0F172A]">
                          {account.label}
                        </p>
                      ) : null}
                      <p className="truncate font-mono text-xs text-[#64748B] sm:text-sm">
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
                      className="shrink-0 rounded-lg border border-[#002D62]/20 bg-[#002D62]/5 px-3 py-1.5 text-xs font-semibold text-[#002D62] transition-colors hover:bg-[#002D62]/10"
                    >
                      Use account
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
