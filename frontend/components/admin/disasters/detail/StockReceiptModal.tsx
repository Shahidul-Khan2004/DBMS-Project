"use client";

import { type FormEvent, useEffect, useState } from "react";
import { toast } from "sonner";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { ApiError, getApiErrorMessage } from "@/lib/api";
import { postReliefHubStockReceipt } from "@/lib/disaster-operations-api";
import { RELIEF_ITEM_OPTIONS } from "@/lib/disaster-operations-format";
import type { DisasterReliefHubActivation } from "@/types/disaster-operations";

type StockReceiptModalProps = {
  open: boolean;
  disasterPublicUuid: string;
  hub: DisasterReliefHubActivation | null;
  onClose: () => void;
  onSuccess: () => Promise<void>;
};

export function StockReceiptModal({
  open,
  disasterPublicUuid,
  hub,
  onClose,
  onSuccess,
}: StockReceiptModalProps) {
  const [reliefItemCode, setReliefItemCode] = useState<string>(
    RELIEF_ITEM_OPTIONS[0].value,
  );
  const [quantityReceived, setQuantityReceived] = useState("");
  const [note, setNote] = useState("");
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (!open) return;
    setReliefItemCode(RELIEF_ITEM_OPTIONS[0].value);
    setQuantityReceived("");
    setNote("");
    setSubmitError(null);
  }, [open]);

  if (!open || !hub?.relief_hub_public_uuid) return null;

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    const qty = Number(quantityReceived);
    if (!Number.isFinite(qty) || qty <= 0) {
      setSubmitError("Quantity must be a positive number.");
      return;
    }
    setIsSubmitting(true);
    setSubmitError(null);
    try {
      await postReliefHubStockReceipt(
        disasterPublicUuid,
        hub.relief_hub_public_uuid!,
        {
          reliefItemCode,
          quantityReceived: qty,
          note: note.trim() || undefined,
        },
      );
      toast.success("Stock receipt recorded.");
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
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4">
      <form
        onSubmit={(e) => void handleSubmit(e)}
        className="flex w-full max-w-md flex-col rounded-xl border border-slate-200 bg-white shadow-xl"
      >
        <div className="border-b border-slate-100 px-5 py-4">
          <h2 className="text-lg font-semibold text-slate-900">Record Stock Receipt</h2>
          <p className="mt-1 text-sm text-slate-600">{hub.facility_name}</p>
        </div>
        <div className="space-y-4 px-5 py-4">
          <div>
            <FieldLabel htmlFor="stock-item" required>
              Relief item
            </FieldLabel>
            <select
              id="stock-item"
              value={reliefItemCode}
              onChange={(e) => setReliefItemCode(e.target.value)}
              className={triageFieldClassName}
              disabled={isSubmitting}
            >
              {RELIEF_ITEM_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </div>
          <div>
            <FieldLabel htmlFor="stock-qty" required>
              Quantity received
            </FieldLabel>
            <input
              id="stock-qty"
              type="number"
              min={1}
              value={quantityReceived}
              onChange={(e) => setQuantityReceived(e.target.value)}
              className={triageFieldClassName}
              disabled={isSubmitting}
            />
          </div>
          <div>
            <FieldLabel htmlFor="stock-note">Note</FieldLabel>
            <textarea
              id="stock-note"
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
    </div>
  );
}
