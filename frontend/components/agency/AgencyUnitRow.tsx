"use client";

import { useState } from "react";
import { getDispatcherSelectableRowClasses } from "@/components/dispatcher/listRowHoverStyles";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { formatReadableLabel } from "@/lib/agency-dispatch-utils";
import { getAgencyUnitTypeLabel } from "@/lib/agency-unit-types";
import type { AgencyUnit } from "@/types/agency";

export type AgencyUnitAction =
  | "set_available"
  | "set_busy"
  | "edit"
  | "deactivate";

type AgencyUnitRowProps = {
  unit: AgencyUnit;
  onAction: (unit: AgencyUnit, action: AgencyUnitAction) => void;
};

export function AgencyUnitRow({ unit, onAction }: AgencyUnitRowProps) {
  const [menuOpen, setMenuOpen] = useState(false);
  const inactive = !unit.is_active;
  const canToggleStatus =
    !inactive && (unit.status_code === "available" || unit.status_code === "busy");

  return (
    <article
      className={`rounded-xl border p-2.5 ${getDispatcherSelectableRowClasses({
        disabled: inactive,
        variant: "flat",
      })}`}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="text-sm font-semibold uppercase tracking-wide text-slate-900">
            {unit.unit_name}
          </p>
          <p className="mt-0.5 text-xs text-slate-600">
            {unit.unit_code} · {getAgencyUnitTypeLabel(unit.unit_type_code)}
          </p>
        </div>
        <div className="flex shrink-0 flex-wrap items-center gap-1">
          <Badge tone={unit.status_code}>
            {formatReadableLabel(unit.status_code)}
          </Badge>
          {!unit.is_active ? <Badge tone="neutral">Inactive</Badge> : null}
        </div>
      </div>

      <div className="mt-2 flex flex-nowrap items-center gap-2">
        {canToggleStatus && unit.status_code === "busy" ? (
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={() => onAction(unit, "set_available")}
          >
            Set Available
          </Button>
        ) : null}
        {canToggleStatus && unit.status_code === "available" ? (
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={() => onAction(unit, "set_busy")}
          >
            Set Busy
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
            aria-label="More unit actions"
          >
            ⋯
          </Button>
          {menuOpen ? (
            <div className="absolute right-0 z-10 mt-1 w-40 rounded-lg border border-slate-200 bg-white p-1 shadow-lg">
              <button
                type="button"
                className="block w-full rounded-md px-2 py-1.5 text-left text-xs text-slate-700 hover:bg-slate-100"
                onClick={() => {
                  setMenuOpen(false);
                  onAction(unit, "edit");
                }}
              >
                Edit Unit
              </button>
              {!inactive ? (
                <button
                  type="button"
                  className="block w-full rounded-md px-2 py-1.5 text-left text-xs text-[#991B1B] hover:bg-[#FEF2F2]"
                  onClick={() => {
                    setMenuOpen(false);
                    onAction(unit, "deactivate");
                  }}
                >
                  Deactivate Unit
                </button>
              ) : null}
            </div>
          ) : null}
        </div>
      </div>
    </article>
  );
}
