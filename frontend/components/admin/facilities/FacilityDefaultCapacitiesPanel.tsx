"use client";

import { useEffect, useState } from "react";
import { CommandSectionCard } from "@/components/dispatcher/incidents/command/CommandSectionCard";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { ApiError, getApiErrorMessage } from "@/lib/api";
import { updateFacilityDefaultCapacities } from "@/lib/admin-facility-api";
import { FACILITY_CAPACITY_TYPE_OPTIONS } from "@/lib/admin-facility-format";
import type { AdminFacility, FacilityDefaultCapacity } from "@/types/admin-facility";
import { toast } from "sonner";

type CapacityRow = {
  capacityType: string;
  totalCapacity: string;
};

function toRows(capacities: FacilityDefaultCapacity[] | undefined): CapacityRow[] {
  if (!capacities?.length) {
    return [{ capacityType: "shelter_people", totalCapacity: "" }];
  }
  return capacities.map((c) => ({
    capacityType: c.capacityType,
    totalCapacity: String(c.totalCapacity),
  }));
}

type FacilityDefaultCapacitiesPanelProps = {
  facility: AdminFacility;
  onUpdated: (facility: AdminFacility) => void;
};

export function FacilityDefaultCapacitiesPanel({
  facility,
  onUpdated,
}: FacilityDefaultCapacitiesPanelProps) {
  const [rows, setRows] = useState<CapacityRow[]>(() =>
    toRows(facility.defaultCapacities),
  );
  const [error, setError] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState(false);

  useEffect(() => {
    setRows(toRows(facility.defaultCapacities));
  }, [facility]);

  const updateRow = (index: number, patch: Partial<CapacityRow>) => {
    setRows((prev) =>
      prev.map((row, i) => (i === index ? { ...row, ...patch } : row)),
    );
  };

  const addRow = () => {
    const used = new Set(rows.map((r) => r.capacityType));
    const nextType = FACILITY_CAPACITY_TYPE_OPTIONS.find(
      (o) => !used.has(o.value),
    )?.value;
    if (!nextType) return;
    setRows((prev) => [...prev, { capacityType: nextType, totalCapacity: "" }]);
  };

  const removeRow = (index: number) => {
    setRows((prev) => prev.filter((_, i) => i !== index));
  };

  const handleSave = async () => {
    const capacities: Array<{ capacityType: string; totalCapacity: number }> =
      [];

    for (const row of rows) {
      const total = Number.parseInt(row.totalCapacity, 10);
      if (!Number.isFinite(total) || total <= 0) {
        setError("Each capacity must be a positive whole number.");
        return;
      }
      capacities.push({
        capacityType: row.capacityType,
        totalCapacity: total,
      });
    }

    if (capacities.length === 0) {
      setError("Add at least one capacity row.");
      return;
    }

    setError(null);
    setIsSaving(true);
    try {
      const response = await updateFacilityDefaultCapacities(
        facility.publicUuid,
        { capacities },
      );
      toast.success("Default capacities updated.");
      onUpdated(response.facility);
    } catch (err) {
      setError(
        err instanceof ApiError
          ? getApiErrorMessage(err, err.message)
          : err instanceof Error
            ? err.message
            : "Failed to update capacities.",
      );
    } finally {
      setIsSaving(false);
    }
  };

  const canAddRow = rows.length < FACILITY_CAPACITY_TYPE_OPTIONS.length;

  return (
    <CommandSectionCard
      title="Default capacities"
      subtitle="Baseline capacity limits used when activating this facility."
      headerAction={
        <Button
          type="button"
          size="sm"
          onClick={() => void handleSave()}
          isLoading={isSaving}
          disabled={isSaving}
        >
          Save
        </Button>
      }
    >
      {error ? (
        <div className="mb-3">
          <ErrorAlert message={error} />
        </div>
      ) : null}
      <ul className="space-y-3">
        {rows.map((row, index) => (
          <li
            key={`${row.capacityType}-${index}`}
            className="flex flex-wrap items-end gap-2"
          >
            <div className="min-w-[10rem] flex-1">
              <label className="mb-1 block text-xs font-medium text-slate-600">
                Capacity type
              </label>
              <select
                value={row.capacityType}
                onChange={(e) =>
                  updateRow(index, { capacityType: e.target.value })
                }
                className={triageFieldClassName}
                disabled={isSaving}
              >
                {FACILITY_CAPACITY_TYPE_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>
            <div className="w-28">
              <label className="mb-1 block text-xs font-medium text-slate-600">
                Total
              </label>
              <input
                type="number"
                min={1}
                step={1}
                value={row.totalCapacity}
                onChange={(e) =>
                  updateRow(index, { totalCapacity: e.target.value })
                }
                className={triageFieldClassName}
                disabled={isSaving}
              />
            </div>
            {rows.length > 1 ? (
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => removeRow(index)}
                disabled={isSaving}
              >
                Remove
              </Button>
            ) : null}
          </li>
        ))}
      </ul>
      {canAddRow ? (
        <Button
          type="button"
          variant="secondary"
          size="sm"
          className="mt-3"
          onClick={addRow}
          disabled={isSaving}
        >
          Add capacity row
        </Button>
      ) : null}
    </CommandSectionCard>
  );
}
