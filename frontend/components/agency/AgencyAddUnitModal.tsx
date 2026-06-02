"use client";

import { useEffect, useState } from "react";
import { toast } from "sonner";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import { AgencyUnitLocationFields } from "@/components/agency/AgencyUnitLocationFields";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { createAgencyUnit } from "@/lib/agency-api";
import { mapAgencyCreateUnitError } from "@/lib/agency-api-errors";
import { AGENCY_UNIT_TYPE_OPTIONS } from "@/lib/agency-unit-types";
import type { IntakeStructuredLocation } from "@/types/intake";

type AgencyAddUnitModalProps = {
  open: boolean;
  onClose: () => void;
  onSuccess: () => Promise<void>;
};

export function AgencyAddUnitModal({ open, onClose, onSuccess }: AgencyAddUnitModalProps) {
  const [unitCode, setUnitCode] = useState("");
  const [unitName, setUnitName] = useState("");
  const [unitTypeCode, setUnitTypeCode] = useState<string>(
    AGENCY_UNIT_TYPE_OPTIONS[0].value,
  );
  const [location, setLocation] = useState<IntakeStructuredLocation | null>(null);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (!open) return;
    setUnitCode("");
    setUnitName("");
    setUnitTypeCode(AGENCY_UNIT_TYPE_OPTIONS[0].value);
    setLocation(null);
    setSubmitError(null);
  }, [open]);

  if (!open) return null;

  const canSubmit =
    unitCode.trim() && unitName.trim() && unitTypeCode.trim() && location != null;

  const handleSubmit = async () => {
    if (!canSubmit || !location) return;
    setIsSubmitting(true);
    setSubmitError(null);
    try {
      await createAgencyUnit({
        unit_code: unitCode.trim(),
        unit_name: unitName.trim(),
        unit_type_code: unitTypeCode,
        base_location: location,
      });
      toast.success("Unit created.");
      onClose();
      await onSuccess();
    } catch (err) {
      setSubmitError(mapAgencyCreateUnitError(err));
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
          <h2 className="text-lg font-semibold text-slate-900">Add Unit</h2>
        </div>
        <div className="overflow-y-auto px-5 py-4 lg:overflow-visible">
          <div className="grid gap-6 lg:grid-cols-2">
            <div className="space-y-4">
              <h3 className="text-sm font-semibold text-slate-900">Unit Details</h3>
              <div>
                <FieldLabel htmlFor="add-unit-code" required>
                  Unit Code
                </FieldLabel>
                <input
                  id="add-unit-code"
                  value={unitCode}
                  onChange={(event) => setUnitCode(event.target.value)}
                  className={triageFieldClassName}
                />
              </div>
              <div>
                <FieldLabel htmlFor="add-unit-name" required>
                  Unit Name
                </FieldLabel>
                <input
                  id="add-unit-name"
                  value={unitName}
                  onChange={(event) => setUnitName(event.target.value)}
                  className={triageFieldClassName}
                />
              </div>
              <div>
                <FieldLabel htmlFor="add-unit-type" required>
                  Unit Type
                </FieldLabel>
                <select
                  id="add-unit-type"
                  value={unitTypeCode}
                  onChange={(event) => setUnitTypeCode(event.target.value)}
                  className={triageFieldClassName}
                >
                  {AGENCY_UNIT_TYPE_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </div>
            </div>
            <div className="space-y-3">
              <h3 className="text-sm font-semibold text-slate-900">Base Location</h3>
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
            Create Unit
          </Button>
        </div>
      </div>
    </div>
  );
}
