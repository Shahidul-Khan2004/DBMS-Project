"use client";

import { useState } from "react";
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
import { getAgencyUnitTypeLabel } from "@/lib/agency-unit-types";
import type { AgencyDispatch, AgencyDispatchStatusAction } from "@/types/agency";

type AgencyAssignedUnitRowProps = {
  dispatch: AgencyDispatch;
  unitTypeCode?: string | null;
  onStatusAction: (
    dispatch: AgencyDispatch,
    action: AgencyDispatchStatusAction,
  ) => void;
  onAddFieldUpdate?: (dispatch: AgencyDispatch) => void;
};

export function AgencyAssignedUnitRow({
  dispatch,
  unitTypeCode,
  onStatusAction,
  onAddFieldUpdate,
}: AgencyAssignedUnitRowProps) {
  const [menuOpen, setMenuOpen] = useState(false);
  const nextAction = getNextDispatchAction(dispatch.status_code);
  const readOnly = isTerminalDispatch(dispatch.status_code);
  const showCancel = canCancelDispatch(dispatch.status_code);

  return (
    <article
      className={`rounded-xl border px-3 py-2.5 ${
        readOnly ? "border-slate-200/80 bg-slate-50/60" : "border-slate-200/90 bg-white"
      }`}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold uppercase tracking-wide text-slate-900">
            {dispatch.unit.unit_name}
          </p>
          <p className="mt-0.5 text-xs text-slate-600">
            {dispatch.unit.unit_code} · {getAgencyUnitTypeLabel(unitTypeCode)}
          </p>
        </div>
        <div className="flex shrink-0 flex-wrap items-center justify-end gap-1">
          {dispatch.priority_level ? (
            <Badge tone={dispatch.priority_level}>
              {formatBadgeLabel(dispatch.priority_level)}
            </Badge>
          ) : null}
          <Badge tone={dispatch.status_code}>
            {formatReadableLabel(dispatch.status_code)}
          </Badge>
        </div>
      </div>

      <p className="mt-1.5 text-xs text-slate-500">
        Assigned {getDispatchAgeLabel(dispatch)}
      </p>

      {!readOnly ? (
        <div className="mt-2.5 flex flex-wrap items-center gap-2">
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
          <div className="relative">
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => setMenuOpen((open) => !open)}
              aria-expanded={menuOpen}
              aria-haspopup="menu"
              aria-label="More dispatch actions"
            >
              ⋯
            </Button>
            {menuOpen ? (
              <div className="absolute left-0 z-10 mt-1 w-44 rounded-lg border border-slate-200 bg-white p-1 shadow-lg">
                {onAddFieldUpdate ? (
                  <button
                    type="button"
                    className="block w-full rounded-md px-2 py-1.5 text-left text-xs text-slate-700 hover:bg-slate-100"
                    onClick={() => {
                      setMenuOpen(false);
                      onAddFieldUpdate(dispatch);
                    }}
                  >
                    Add Field Update
                  </button>
                ) : null}
                {showCancel ? (
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
                ) : null}
              </div>
            ) : null}
          </div>
        </div>
      ) : null}
    </article>
  );
}
