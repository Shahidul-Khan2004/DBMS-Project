"use client";

import { useState } from "react";
import { AgencyAddUnitModal } from "@/components/agency/AgencyAddUnitModal";
import { AgencyDeactivateUnitModal } from "@/components/agency/AgencyDeactivateUnitModal";
import { AgencyEditUnitModal } from "@/components/agency/AgencyEditUnitModal";
import {
  AgencyUnitRow,
  type AgencyUnitAction,
} from "@/components/agency/AgencyUnitRow";
import { AgencyUnitStatusModal } from "@/components/agency/AgencyUnitStatusModal";
import { Button } from "@/components/ui/Button";
import { EmptyState } from "@/components/ui/StatusState";
import { AgencySkeletonBlock } from "@/components/agency/AgencySkeletonBlock";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import type { AgencyUnit, AgencyUnitStatusCode } from "@/types/agency";

export function AgencyUnitsPanel({
  units,
  loading,
  error,
  showAddButton = true,
  addOpen: controlledAddOpen,
  onAddOpenChange,
  onRefresh,
}: {
  units: AgencyUnit[];
  loading: boolean;
  error: string | null;
  showAddButton?: boolean;
  addOpen?: boolean;
  onAddOpenChange?: (open: boolean) => void;
  onRefresh: () => Promise<void>;
}) {
  const [internalAddOpen, setInternalAddOpen] = useState(false);
  const addOpen = controlledAddOpen ?? internalAddOpen;
  const setAddOpen = onAddOpenChange ?? setInternalAddOpen;

  const [editUnit, setEditUnit] = useState<AgencyUnit | null>(null);
  const [deactivateUnit, setDeactivateUnit] = useState<AgencyUnit | null>(null);
  const [statusTarget, setStatusTarget] = useState<{
    unit: AgencyUnit;
    status: AgencyUnitStatusCode;
  } | null>(null);

  const handleAction = (unit: AgencyUnit, action: AgencyUnitAction) => {
    switch (action) {
      case "set_available":
        setStatusTarget({ unit, status: "available" });
        break;
      case "set_busy":
        setStatusTarget({ unit, status: "busy" });
        break;
      case "edit":
        setEditUnit(unit);
        break;
      case "deactivate":
        setDeactivateUnit(unit);
        break;
      default:
        break;
    }
  };

  return (
    <>
      {showAddButton ? (
        <div className="mb-3 flex justify-end lg:hidden">
          <Button type="button" size="sm" variant="outline" onClick={() => setAddOpen(true)}>
            + Add Unit
          </Button>
        </div>
      ) : null}

      {error ? (
        <div className="mb-3">
          <ErrorAlert message={error} />
        </div>
      ) : null}

      {loading ? (
        <div className="space-y-2" aria-busy="true">
          <AgencySkeletonBlock className="h-16 w-full" />
          <AgencySkeletonBlock className="h-16 w-full" />
        </div>
      ) : units.length === 0 ? (
        <EmptyState
          title="No units"
          description="Add a unit to make it available for dispatch assignment."
          action={
            showAddButton ? (
              <Button type="button" size="sm" onClick={() => setAddOpen(true)}>
                Add Unit
              </Button>
            ) : undefined
          }
        />
      ) : (
        <div className="space-y-2">
          {units.map((unit) => (
            <AgencyUnitRow key={unit.public_uuid} unit={unit} onAction={handleAction} />
          ))}
        </div>
      )}

      <AgencyAddUnitModal
        open={addOpen}
        onClose={() => setAddOpen(false)}
        onSuccess={onRefresh}
      />
      <AgencyEditUnitModal
        open={Boolean(editUnit)}
        unit={editUnit}
        onClose={() => setEditUnit(null)}
        onSuccess={onRefresh}
      />
      <AgencyDeactivateUnitModal
        open={Boolean(deactivateUnit)}
        unit={deactivateUnit}
        onClose={() => setDeactivateUnit(null)}
        onSuccess={onRefresh}
      />
      <AgencyUnitStatusModal
        open={Boolean(statusTarget)}
        unit={statusTarget?.unit ?? null}
        targetStatus={statusTarget?.status ?? null}
        onClose={() => setStatusTarget(null)}
        onSuccess={onRefresh}
      />
    </>
  );
}
