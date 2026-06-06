"use client";

import { type FormEvent, useEffect, useState } from "react";
import { toast } from "sonner";
import {
  ReliefLineItemsEditor,
  parseReliefLineItems,
  type ReliefLineItemRow,
} from "@/components/admin/disasters/detail/ReliefLineItemsEditor";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { ModalPortal } from "@/components/ui/ModalPortal";
import { ApiError, getApiErrorMessage } from "@/lib/api";
import { postAgencyReliefHubStockReceipt } from "@/lib/agency-disaster-api";
import { RELIEF_ITEM_OPTIONS } from "@/lib/disaster-operations-format";
import type { DisasterReliefHubActivation } from "@/types/disaster-operations";

type AgencyReliefHubStockReceiptModalProps = {
  open: boolean;
  disasterPublicUuid: string;
  hub: DisasterReliefHubActivation | null;
  onClose: () => void;
  onSuccess: () => Promise<void>;
};

export function AgencyReliefHubStockReceiptModal({
  open,
  disasterPublicUuid,
  hub,
  onClose,
  onSuccess,
}: AgencyReliefHubStockReceiptModalProps) {
  const [items, setItems] = useState<ReliefLineItemRow[]>([
    { reliefItemCode: RELIEF_ITEM_OPTIONS[0].value, quantity: "" },
  ]);
  const [note, setNote] = useState("");
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (!open) return;
    setItems([{ reliefItemCode: RELIEF_ITEM_OPTIONS[0].value, quantity: "" }]);
    setNote("");
    setSubmitError(null);
  }, [open]);

  if (!open || !hub?.relief_hub_public_uuid) return null;

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    const parsed = parseReliefLineItems(items);
    if (!parsed) {
      setSubmitError("Add at least one valid item with positive quantity.");
      return;
    }
    setIsSubmitting(true);
    setSubmitError(null);
    const hubUuid = hub.relief_hub_public_uuid!;
    const receiptNote = note.trim() || undefined;
    try {
      for (const row of parsed) {
        await postAgencyReliefHubStockReceipt(disasterPublicUuid, hubUuid, {
          reliefItemCode: row.reliefItemCode,
          quantityReceived: row.quantity,
          note: receiptNote,
        });
      }
      toast.success(
        parsed.length === 1
          ? "Stock receipt recorded."
          : `${parsed.length} stock receipts recorded.`,
      );
      onClose();
      await onSuccess();
    } catch (err) {
      setSubmitError(
        err instanceof ApiError
          ? getApiErrorMessage(err, err.message)
          : "Failed to record stock receipt.",
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <ModalPortal open={open}>
      <form
        onSubmit={(e) => void handleSubmit(e)}
        className="flex max-h-[90vh] w-full max-w-lg flex-col rounded-xl border border-slate-200 bg-white shadow-xl"
      >
        <div className="border-b border-slate-100 px-5 py-4">
          <h2 className="text-lg font-semibold text-slate-900">Record Stock Receipt</h2>
          <p className="mt-1 text-sm text-slate-600">{hub.facility_name}</p>
        </div>
        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-5 py-4">
          <ReliefLineItemsEditor
            items={items}
            onChange={setItems}
            quantityLabel="Qty received"
            disabled={isSubmitting}
          />
          <div>
            <FieldLabel htmlFor="agency-stock-note">Note</FieldLabel>
            <textarea
              id="agency-stock-note"
              value={note}
              onChange={(e) => setNote(e.target.value)}
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
          <Button type="submit" isLoading={isSubmitting} disabled={isSubmitting}>
            Record
          </Button>
        </div>
      </form>
    </ModalPortal>
  );
}
