"use client";

import Link from "next/link";
import { MoreHorizontal } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import {
  getServiceCaseOverflowActions,
  getServiceCasePrimaryActions,
  overflowActionLabel,
  primaryActionLabel,
  type ServiceCaseOverflowAction,
  type ServiceCasePrimaryAction,
} from "@/components/dispatcher/service-cases/detail/serviceCaseActions";
import { Button } from "@/components/ui/Button";

type ServiceCaseCommandBarProps = {
  statusCode: string | null | undefined;
  canEscalate: boolean;
  isRefreshing?: boolean;
  onRefresh: () => void;
  onPrimaryAction: (action: ServiceCasePrimaryAction) => void;
  onOverflowAction: (action: ServiceCaseOverflowAction) => void;
};

export function ServiceCaseCommandBar({
  statusCode,
  canEscalate,
  isRefreshing = false,
  onRefresh,
  onPrimaryAction,
  onOverflowAction,
}: ServiceCaseCommandBarProps) {
  const [overflowOpen, setOverflowOpen] = useState(false);
  const overflowRef = useRef<HTMLDivElement>(null);

  const primaryActions = getServiceCasePrimaryActions(statusCode).filter(
    (action) => action !== "escalate" || canEscalate,
  );
  const overflowActions = getServiceCaseOverflowActions(statusCode);

  useEffect(() => {
    if (!overflowOpen) return;

    function handlePointerDown(event: MouseEvent) {
      if (
        overflowRef.current &&
        !overflowRef.current.contains(event.target as Node)
      ) {
        setOverflowOpen(false);
      }
    }

    document.addEventListener("mousedown", handlePointerDown);
    return () => document.removeEventListener("mousedown", handlePointerDown);
  }, [overflowOpen]);

  return (
    <div className="flex shrink-0 flex-wrap items-center justify-between gap-x-2 gap-y-0 py-0 xl:flex-nowrap xl:items-center">
      <nav
        aria-label="Service case context"
        className="flex min-w-0 flex-wrap items-center gap-x-1 text-xs leading-none"
      >
        <Link
          href="/dashboard/dispatcher/service-cases"
          className="font-medium text-[#006747] transition hover:text-[#002D62]"
        >
          ← Service Cases
        </Link>
        <span className="text-slate-400" aria-hidden>
          /
        </span>
        <span className="text-slate-500">Case Workspace</span>
      </nav>

      <div className="flex flex-wrap items-center justify-end gap-2">
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={onRefresh}
          disabled={isRefreshing}
        >
          {isRefreshing ? "Refreshing…" : "Refresh"}
        </Button>

        {primaryActions.map((action) => (
          <Button
            key={action}
            type="button"
            variant={action === "escalate" ? "secondary" : "primary"}
            size="sm"
            onClick={() => onPrimaryAction(action)}
          >
            {primaryActionLabel(action)}
          </Button>
        ))}

        {overflowActions.length > 0 ? (
          <div className="relative" ref={overflowRef}>
            <Button
              type="button"
              variant="outline"
              size="sm"
              aria-expanded={overflowOpen}
              aria-haspopup="menu"
              onClick={() => setOverflowOpen((open) => !open)}
            >
              <MoreHorizontal className="h-4 w-4" aria-hidden />
              <span className="sr-only">More actions</span>
            </Button>
            {overflowOpen ? (
              <div
                role="menu"
                className="absolute right-0 z-20 mt-1 min-w-[10rem] rounded-lg border border-slate-200 bg-white py-1 shadow-lg"
              >
                {overflowActions.map((action) => (
                  <button
                    key={action}
                    type="button"
                    role="menuitem"
                    className="block w-full px-3 py-2 text-left text-sm text-slate-700 hover:bg-slate-50"
                    onClick={() => {
                      setOverflowOpen(false);
                      onOverflowAction(action);
                    }}
                  >
                    {overflowActionLabel(action)}
                  </button>
                ))}
              </div>
            ) : null}
          </div>
        ) : null}
      </div>
    </div>
  );
}
