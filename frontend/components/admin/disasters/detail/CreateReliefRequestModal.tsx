"use client";

import { type FormEvent, useEffect, useState } from "react";
import { toast } from "sonner";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import {
  ReliefLineItemsEditor,
  parseReliefLineItems,
  type ReliefLineItemRow,
} from "@/components/admin/disasters/detail/ReliefLineItemsEditor";
import { ApiError, getApiErrorMessage } from "@/lib/api";
import { postDisasterReliefRequest } from "@/lib/disaster-operations-api";
import {
  isActiveDisasterActivation,
  RELIEF_ITEM_OPTIONS,
} from "@/lib/disaster-operations-format";
import type { DisasterShelterActivation } from "@/types/disaster-operations";

type CreateReliefRequestModalProps = {
  open: boolean;
  disasterPublicUuid: string;
  shelters: DisasterShelterActivation[];
  onClose: () => void;
  onSuccess: () => Promise<void>;
};

export function CreateReliefRequestModal({
  open,
  disasterPublicUuid,
  shelters,
  onClose,
  onSuccess,
}: CreateReliefRequestModalProps) {
  const [shelterUuid, setShelterUuid] = useState("");
  const [requestNote, setRequestNote] = useState("");
  const [items, setItems] = useState<ReliefLineItemRow[]>([
    { reliefItemCode: RELIEF_ITEM_OPTIONS[0].value, quantity: "" },
  ]);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const activeShelters = shelters.filter(
    (s) =>
      s.shelter_activation_public_uuid &&
      isActiveDisasterActivation(s.activation_status),
  );

  useEffect(() => {
    if (!open) return;
    const firstActive = shelters.find(
      (s) =>
        s.shelter_activation_public_uuid &&
        isActiveDisasterActivation(s.activation_status),
    );
    setShelterUuid(firstActive?.shelter_activation_public_uuid ?? "");
    setRequestNote("");
    setItems([{ reliefItemCode: RELIEF_ITEM_OPTIONS[0].value, quantity: "" }]);
    setSubmitError(null);
  }, [open, shelters]);

  if (!open) return null;

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (!shelterUuid) {
      setSubmitError("Select a shelter activation.");
      return;
    }
    const parsed = parseReliefLineItems(items);
    if (!parsed) {
      setSubmitError("Add at least one valid item with positive quantity.");
      return;
    }
    setIsSubmitting(true);
    setSubmitError(null);
    try {
      await postDisasterReliefRequest(disasterPublicUuid, {
        shelterActivationPublicUuid: shelterUuid,
        requestNote: requestNote.trim() || undefined,
        items: parsed.map((row) => ({
          reliefItemCode: row.reliefItemCode,
          quantityRequested: row.quantity,
        })),
      });
      toast.success("Relief request created.");
      onClose();
      await onSuccess();
    } catch (err) {
      setSubmitError(
        err instanceof ApiError
          ? getApiErrorMessage(err, err.message)
          : "Failed to create relief request.",
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4">
      <form
        onSubmit={(e) => void handleSubmit(e)}
        className="flex max-h-[90vh] w-full max-w-lg flex-col rounded-xl border border-slate-200 bg-white shadow-xl"
      >
        <div className="border-b border-slate-100 px-5 py-4">
          <h2 className="text-lg font-semibold text-slate-900">Create Relief Request</h2>
        </div>
        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-5 py-4">
          <div>
            <FieldLabel htmlFor="request-shelter" required>
              Shelter
            </FieldLabel>
            <select
              id="request-shelter"
              value={shelterUuid}
              onChange={(e) => setShelterUuid(e.target.value)}
              className={triageFieldClassName}
              disabled={isSubmitting}
            >
              {activeShelters.length === 0 ? (
                <option value="">No active shelters</option>
              ) : (
                activeShelters.map((s) => (
                  <option
                    key={s.shelter_activation_public_uuid}
                    value={s.shelter_activation_public_uuid}
                  >
                    {s.facility_name ?? "Shelter"}
                  </option>
                ))
              )}
            </select>
          </div>
          <ReliefLineItemsEditor
            items={items}
            onChange={setItems}
            quantityLabel="Qty requested"
            disabled={isSubmitting}
          />
          <div>
            <FieldLabel htmlFor="request-note">Request note</FieldLabel>
            <textarea
              id="request-note"
              value={requestNote}
              onChange={(e) => setRequestNote(e.target.value)}
              rows={2}
              className={triageFieldClassName}
              disabled={isSubmitting}
            />
          </div>
          {submitError ? <ErrorAlert message={submitError} /> : null}
        </div>
        <div className="flex justify-end gap-2 border-t border-slate-100 px-5 py-4">
          <Button type="button" variant="secondary" onClick={onClose} disabled={isSubmitting}>
            Cancel
          </Button>
          <Button
            type="submit"
            isLoading={isSubmitting}
            disabled={isSubmitting || activeShelters.length === 0}
          >
            Create request
          </Button>
        </div>
      </form>
    </div>
  );
}
