"use client";

import { useState } from "react";
import { toast } from "sonner";
import { CommandSectionCard } from "@/components/dispatcher/incidents/command/CommandSectionCard";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { ConfirmModal } from "@/components/ui/ConfirmModal";
import { CreateReliefRequestModal } from "@/components/admin/disasters/detail/CreateReliefRequestModal";
import { ApiError, getApiErrorMessage } from "@/lib/api";
import {
  postApproveReliefRequest,
  postRejectReliefRequest,
} from "@/lib/disaster-operations-api";
import {
  formatReliefItemLabel,
  formatReliefRequestStatusLabel,
  getActiveDisasterShelters,
} from "@/lib/disaster-operations-format";
import type { DisasterDashboardResponse, DisasterReliefRequest } from "@/types/disaster-operations";

type DisasterReliefRequestsTabProps = {
  disasterPublicUuid: string;
  dashboard: DisasterDashboardResponse;
  isReadOnly: boolean;
  onRefresh: () => Promise<void>;
};

export function DisasterReliefRequestsTab({
  disasterPublicUuid,
  dashboard,
  isReadOnly,
  onRefresh,
}: DisasterReliefRequestsTabProps) {
  const [createOpen, setCreateOpen] = useState(false);
  const [confirmAction, setConfirmAction] = useState<{
    type: "approve" | "reject";
    request: DisasterReliefRequest;
  } | null>(null);
  const [isMutating, setIsMutating] = useState(false);
  const requests = dashboard.relief_requests ?? [];

  const handleConfirmAction = async () => {
    if (!confirmAction) return;
    setIsMutating(true);
    try {
      if (confirmAction.type === "approve") {
        await postApproveReliefRequest(
          confirmAction.request.relief_request_public_uuid,
        );
        toast.success("Relief request approved.");
      } else {
        await postRejectReliefRequest(
          confirmAction.request.relief_request_public_uuid,
        );
        toast.success("Relief request rejected.");
      }
      setConfirmAction(null);
      await onRefresh();
    } catch (err) {
      toast.error(
        err instanceof ApiError
          ? getApiErrorMessage(err, err.message)
          : "Action failed.",
      );
    } finally {
      setIsMutating(false);
    }
  };

  return (
    <>
      <CommandSectionCard
        title="Relief Requests"
        headerAction={
          !isReadOnly ? (
            <Button type="button" size="sm" onClick={() => setCreateOpen(true)}>
              Create relief request
            </Button>
          ) : undefined
        }
      >
        {requests.length === 0 ? (
          <p className="text-sm text-slate-600">No relief requests.</p>
        ) : (
          <ul className="space-y-2 text-sm">
            {requests.map((req) => (
              <li
                key={req.relief_request_public_uuid}
                className="flex flex-wrap items-start justify-between gap-2 rounded-lg border border-slate-100 px-3 py-2"
              >
                <div>
                  <p className="font-medium text-slate-900">
                    {req.request_code ?? "Relief request"}
                  </p>
                  <p className="text-xs text-slate-600">
                    {req.shelter_facility_name ?? "Shelter"}
                  </p>
                  <span className="mt-1 inline-block">
                    <Badge size="compact">
                      {formatBadgeLabel(
                        formatReliefRequestStatusLabel(req.status_code),
                      )}
                    </Badge>
                  </span>
                  {req.shortages && req.shortages.length > 0 ? (
                    <ul className="mt-2 space-y-0.5 text-xs text-slate-600">
                      {req.shortages.map((s, idx) => (
                        <li key={`${s.relief_item_code ?? "item"}-${idx}`}>
                          {formatReliefItemLabel(s.relief_item_code)}: short{" "}
                          {s.quantity_short != null && s.quantity_short > 0
                            ? s.quantity_short.toLocaleString()
                            : "—"}
                        </li>
                      ))}
                    </ul>
                  ) : null}
                </div>
                {!isReadOnly && req.status_code === "submitted" ? (
                  <div className="flex flex-wrap gap-1">
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() =>
                        setConfirmAction({ type: "approve", request: req })
                      }
                    >
                      Approve
                    </Button>
                    <Button
                      type="button"
                      variant="danger"
                      size="sm"
                      onClick={() =>
                        setConfirmAction({ type: "reject", request: req })
                      }
                    >
                      Reject
                    </Button>
                  </div>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </CommandSectionCard>

      <CreateReliefRequestModal
        open={createOpen}
        disasterPublicUuid={disasterPublicUuid}
        activeShelters={getActiveDisasterShelters(dashboard.shelters ?? [])}
        onClose={() => setCreateOpen(false)}
        onSuccess={onRefresh}
      />

      <ConfirmModal
        open={confirmAction != null}
        title={
          confirmAction?.type === "approve"
            ? "Approve relief request"
            : "Reject relief request"
        }
        message={
          confirmAction?.type === "approve"
            ? `Approve request ${confirmAction.request.request_code ?? ""}?`
            : `Reject request ${confirmAction?.request.request_code ?? ""}?`
        }
        confirmLabel={confirmAction?.type === "approve" ? "Approve" : "Reject"}
        isLoading={isMutating}
        onConfirm={() => void handleConfirmAction()}
        onCancel={() => setConfirmAction(null)}
      />
    </>
  );
}
