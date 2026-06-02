"use client";

import { useEffect, useState } from "react";
import { toast } from "sonner";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import { AgencyUnitLocationFields } from "@/components/agency/AgencyUnitLocationFields";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { updateAgencyUnit } from "@/lib/agency-api";
import { mapAgencyUpdateUnitError } from "@/lib/agency-api-errors";
import type { AgencyUnit } from "@/types/agency";
import type { IntakeStructuredLocation } from "@/types/intake";

type AgencyEditUnitModalProps = {
  open: boolean;
  unit: AgencyUnit | null;
  onClose: () => void;
  onSuccess: () => Promise<void>;
};

export function AgencyEditUnitModal({
  open,
  unit,
  onClose,
  onSuccess,
}: AgencyEditUnitModalProps) {
  const [unitCode, setUnitCode] = useState("");
  const [unitName, setUnitName] = useState("");
  const [location, setLocation] = useState<IntakeStructuredLocation | null>(null);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (!open || !unit) return;
    setUnitCode(unit.unit_code);
    setUnitName(unit.unit_name);
    setLocation(null);
    setSubmitError(null);
  }, [open, unit]);

  if (!open || !unit) return null;

  const canSubmit = unitCode.trim() && unitName.trim();

  const handleSubmit = async () => {
    if (!canSubmit) return;
    setIsSubmitting(true);
    setSubmitError(null);
    try {
      await updateAgencyUnit(unit.public_uuid, {
        unit_code: unitCode.trim(),
        unit_name: unitName.trim(),
        base_location: location ?? undefined,
      });
      toast.success("Unit updated.");
      onClose();
      await onSuccess();
    } catch (err) {
      setSubmitError(mapAgencyUpdateUnitError(err));
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4 py-6">
      <div
        className="flex max-h-[92vh] w-full max-w-5xl flex-col overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-xl lg:max-w-6xl"
        role="dialog"
        aria-modal="true"
      >
        <div className="shrink-0 border-b border-slate-100 px-5 py-4">
          <h2 className="text-lg font-semibold text-slate-900">Edit Unit</h2>
        </div>
        <div className="overflow-y-auto px-5 py-4 lg:overflow-visible">
          <div className="grid gap-6 lg:grid-cols-2">
            <div className="space-y-4">
              <h3 className="text-sm font-semibold text-slate-900">Unit Details</h3>
              <div>
                <FieldLabel htmlFor="edit-unit-code" required>
                  Unit Code
                </FieldLabel>
                <input
                  id="edit-unit-code"
                  value={unitCode}
                  onChange={(event) => setUnitCode(event.target.value)}
                  className={triageFieldClassName}
                />
              </div>
              <div>
                <FieldLabel htmlFor="edit-unit-name" required>
                  Unit Name
                </FieldLabel>
                <input
                  id="edit-unit-name"
                  value={unitName}
                  onChange={(event) => setUnitName(event.target.value)}
                  className={triageFieldClassName}
                />
              </div>
            </div>
            <div className="space-y-3">
              <h3 className="text-sm font-semibold text-slate-900">Base Location</h3>
              <p className="text-xs text-slate-500">
                Optional — update only if you need to change the unit base.
              </p>
              <AgencyUnitLocationFields
                location={location}
                onLocationChange={setLocation}
                disabled={isSubmitting}
              />
            </div>
          </div>
          {submitError ? <div className="mt-4"><ErrorAlert message={submitError} /></div> : null}
        </div>
        <div className="flex shrink-0 justify-end gap-2 border-t border-slate-100 px-5 py-4">
          <Button type="button" variant="secondary" onClick={onClose} disabled={isSubmitting}>
            Cancel
          </Button>
          <Button
            type="button"
            variant="primary"
            onClick={() => void handleSubmit()}
            isLoading={isSubmitting}
            disabled={!canSubmit}
          >
            Save
          </Button>
        </div>
      </div>
    </div>
  );
}
