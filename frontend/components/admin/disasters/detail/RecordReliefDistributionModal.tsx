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
import { postDisasterReliefDistribution } from "@/lib/disaster-operations-api";
import { RELIEF_ITEM_OPTIONS } from "@/lib/disaster-operations-format";
import type {
  DisasterReliefHubActivation,
  DisasterReliefRequest,
} from "@/types/disaster-operations";

type RecordReliefDistributionModalProps = {
  open: boolean;
  disasterPublicUuid: string;
  reliefRequests: DisasterReliefRequest[];
  reliefHubs: DisasterReliefHubActivation[];
  onClose: () => void;
  onSuccess: () => Promise<void>;
};

export function RecordReliefDistributionModal({
  open,
  disasterPublicUuid,
  reliefRequests,
  reliefHubs,
  onClose,
  onSuccess,
}: RecordReliefDistributionModalProps) {
  const approvedRequests = reliefRequests.filter(
    (r) => r.status_code === "approved" || r.status_code === "partially_fulfilled",
  );
  const activeHubs = reliefHubs.filter((h) => h.relief_hub_public_uuid);

  const [requestUuid, setRequestUuid] = useState("");
  const [hubUuid, setHubUuid] = useState("");
  const [note, setNote] = useState("");
  const [items, setItems] = useState<ReliefLineItemRow[]>([
    { reliefItemCode: RELIEF_ITEM_OPTIONS[0].value, quantity: "" },
  ]);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (!open) return;
    setRequestUuid(approvedRequests[0]?.relief_request_public_uuid ?? "");
    setHubUuid(activeHubs[0]?.relief_hub_public_uuid ?? "");
    setNote("");
    setItems([{ reliefItemCode: RELIEF_ITEM_OPTIONS[0].value, quantity: "" }]);
    setSubmitError(null);
  }, [open, approvedRequests, activeHubs]);

  if (!open) return null;

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (!requestUuid || !hubUuid) {
      setSubmitError("Select a relief request and source hub.");
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
      await postDisasterReliefDistribution(disasterPublicUuid, {
        reliefRequestPublicUuid: requestUuid,
        sourceHubActivationPublicUuid: hubUuid,
        items: parsed.map((row) => ({
          reliefItemCode: row.reliefItemCode,
          quantityDelivered: row.quantity,
        })),
        note: note.trim() || undefined,
      });
      toast.success("Distribution recorded.");
      onClose();
      await onSuccess();
    } catch (err) {
      setSubmitError(
        err instanceof ApiError
          ? getApiErrorMessage(err, err.message)
          : "Failed to record distribution.",
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
          <h2 className="text-lg font-semibold text-slate-900">Record Distribution</h2>
        </div>
        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-5 py-4">
          <div>
            <FieldLabel htmlFor="dist-request" required>
              Relief request
            </FieldLabel>
            <select
              id="dist-request"
              value={requestUuid}
              onChange={(e) => setRequestUuid(e.target.value)}
              className={triageFieldClassName}
              disabled={isSubmitting}
            >
              {approvedRequests.length === 0 ? (
                <option value="">No approved requests</option>
              ) : (
                approvedRequests.map((r) => (
                  <option
                    key={r.relief_request_public_uuid}
                    value={r.relief_request_public_uuid}
                  >
                    {r.request_code ?? "Request"} · {r.shelter_facility_name}
                  </option>
                ))
              )}
            </select>
          </div>
          <div>
            <FieldLabel htmlFor="dist-hub" required>
              Source relief hub
            </FieldLabel>
            <select
              id="dist-hub"
              value={hubUuid}
              onChange={(e) => setHubUuid(e.target.value)}
              className={triageFieldClassName}
              disabled={isSubmitting}
            >
              {activeHubs.length === 0 ? (
                <option value="">No relief hubs</option>
              ) : (
                activeHubs.map((h) => (
                  <option key={h.relief_hub_public_uuid} value={h.relief_hub_public_uuid}>
                    {h.facility_name ?? "Hub"}
                  </option>
                ))
              )}
            </select>
          </div>
          <ReliefLineItemsEditor
            items={items}
            onChange={setItems}
            quantityLabel="Qty delivered"
            disabled={isSubmitting}
          />
          <div>
            <FieldLabel htmlFor="dist-note">Note</FieldLabel>
            <textarea
              id="dist-note"
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
          <Button
            type="submit"
            isLoading={isSubmitting}
            disabled={
              isSubmitting ||
              approvedRequests.length === 0 ||
              activeHubs.length === 0
            }
          >
            Record distribution
          </Button>
        </div>
      </form>
    </div>
  );
}
