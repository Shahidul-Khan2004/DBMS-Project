"use client";

import { useState } from "react";
import { getDispatcherSelectableRowClasses } from "@/components/dispatcher/listRowHoverStyles";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import {
  canCancelDispatch,
  formatReadableLabel,
  getDispatchActionLabel,
  getDispatchAgeLabel,
  getNextDispatchAction,
  isTerminalDispatch,
} from "@/lib/agency-dispatch-utils";
import type { AgencyDispatch, AgencyDispatchStatusAction } from "@/types/agency";

type AgencyDispatchRowProps = {
  dispatch: AgencyDispatch;
  selected?: boolean;
  onSelect: (dispatch: AgencyDispatch) => void;
  onStatusAction: (
    dispatch: AgencyDispatch,
    action: AgencyDispatchStatusAction,
  ) => void;
};

export function AgencyDispatchRow({
  dispatch,
  selected = false,
  onSelect,
  onStatusAction,
}: AgencyDispatchRowProps) {
  const [menuOpen, setMenuOpen] = useState(false);
  const nextAction = getNextDispatchAction(dispatch.status_code);
  const readOnly = isTerminalDispatch(dispatch.status_code);
  const showCancel = canCancelDispatch(dispatch.status_code);

  return (
    <article
      className={`rounded-xl border p-3 ${getDispatcherSelectableRowClasses({
        selected,
        variant: "card",
      })}`}
      onClick={() => onSelect(dispatch)}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onSelect(dispatch);
        }
      }}
      role="button"
      tabIndex={0}
      aria-pressed={selected}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-semibold text-slate-900">
            {dispatch.incident.title || dispatch.incident.incident_code}
          </p>
          <p className="mt-0.5 text-xs text-slate-600">{dispatch.incident.incident_code}</p>
        </div>
        <div
          className="flex shrink-0 flex-wrap items-center justify-end gap-1"
          onClick={(event) => event.stopPropagation()}
        >
          <Badge tone={dispatch.priority_level}>
            {formatBadgeLabel(dispatch.priority_level)}
          </Badge>
          <Badge tone={dispatch.status_code}>
            {formatReadableLabel(dispatch.status_code)}
          </Badge>
        </div>
      </div>

      <p className="mt-2 text-xs text-slate-600">
        {dispatch.unit.unit_name} · {dispatch.unit.unit_code}
      </p>
      <p className="mt-0.5 text-xs text-slate-500">{getDispatchAgeLabel(dispatch)}</p>

      {!readOnly ? (
        <div
          className="mt-3 flex flex-wrap items-center gap-2"
          onClick={(event) => event.stopPropagation()}
        >
          {nextAction ? (
            <Button
              type="button"
              size="sm"
              variant="primary"
              onClick={() => onStatusAction(dispatch, nextAction)}
            >
              {getDispatchActionLabel(nextAction)}
            </Button>
          ) : null}
          {showCancel ? (
            <div className="relative">
              <Button
                type="button"
                size="sm"
                variant="outline"
                onClick={() => setMenuOpen((open) => !open)}
                aria-expanded={menuOpen}
                aria-haspopup="menu"
              >
                More
              </Button>
              {menuOpen ? (
                <div className="absolute left-0 z-10 mt-1 w-40 rounded-lg border border-slate-200 bg-white p-1 shadow-lg">
                  <button
                    type="button"
                    className="block w-full rounded-md px-2 py-1.5 text-left text-xs text-[#991B1B] hover:bg-[#FEF2F2]"
                    onClick={() => {
                      setMenuOpen(false);
                      onStatusAction(dispatch, "cancelled");
                    }}
                  >
                    Cancel Dispatch
                  </button>
                </div>
              ) : null}
            </div>
          ) : null}
        </div>
      ) : null}
    </article>
  );
}
