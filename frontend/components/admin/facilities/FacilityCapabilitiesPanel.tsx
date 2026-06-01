"use client";

import { useEffect, useState } from "react";
import { CommandSectionCard } from "@/components/dispatcher/incidents/command/CommandSectionCard";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { ApiError, getApiErrorMessage } from "@/lib/api";
import { updateFacilityCapabilities } from "@/lib/admin-facility-api";
import {
  FACILITY_CAPABILITY_OPTIONS,
  formatCapabilityLabel,
} from "@/lib/admin-facility-format";
import type { AdminFacility } from "@/types/admin-facility";
import { toast } from "sonner";

type FacilityCapabilitiesPanelProps = {
  facility: AdminFacility;
  onUpdated: (facility: AdminFacility) => void;
};

export function FacilityCapabilitiesPanel({
  facility,
  onUpdated,
}: FacilityCapabilitiesPanelProps) {
  const initialCodes = new Set(
    (facility.capabilities ?? []).map((c) => c.capabilityCode),
  );
  const [selected, setSelected] = useState<Set<string>>(initialCodes);
  const [error, setError] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState(false);

  useEffect(() => {
    setSelected(
      new Set((facility.capabilities ?? []).map((c) => c.capabilityCode)),
    );
  }, [facility]);

  const toggle = (code: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(code)) next.delete(code);
      else next.add(code);
      return next;
    });
  };

  const handleSave = async () => {
    if (selected.size === 0) {
      setError("Select at least one capability.");
      return;
    }

    setError(null);
    setIsSaving(true);
    try {
      const response = await updateFacilityCapabilities(facility.publicUuid, {
        capabilityCodes: Array.from(selected),
      });
      toast.success("Capabilities updated.");
      onUpdated(response.facility);
    } catch (err) {
      setError(
        err instanceof ApiError
          ? getApiErrorMessage(err, err.message)
          : err instanceof Error
            ? err.message
            : "Failed to update capabilities.",
      );
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <CommandSectionCard
      title="Capabilities"
      subtitle="Operational roles this facility can perform during disasters."
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
      <ul className="space-y-2">
        {FACILITY_CAPABILITY_OPTIONS.map((opt) => (
          <li key={opt.value}>
            <label className="flex cursor-pointer items-center gap-2 text-sm text-slate-800">
              <input
                type="checkbox"
                className="rounded border-slate-300"
                checked={selected.has(opt.value)}
                onChange={() => toggle(opt.value)}
                disabled={isSaving}
              />
              {formatCapabilityLabel(opt.value)}
            </label>
          </li>
        ))}
      </ul>
    </CommandSectionCard>
  );
}
