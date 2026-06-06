"use client";

import { useState } from "react";
import { toast } from "sonner";
import { CommandSectionCard } from "@/components/dispatcher/incidents/command/CommandSectionCard";
import { AssignResponsibilityModal } from "@/components/admin/disasters/detail/AssignResponsibilityModal";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { ConfirmModal } from "@/components/ui/ConfirmModal";
import { ApiError, getApiErrorMessage } from "@/lib/api";
import { postRevokeDisasterResponsibility } from "@/lib/disaster-operations-api";
import { formatResponsibilityTypeLabel } from "@/lib/disaster-operations-format";
import type {
  DisasterDashboardResponse,
  DisasterResponsibility,
  DisasterResponsibilityType,
} from "@/types/disaster-operations";

type DisasterResponsibilitiesTabProps = {
  disasterPublicUuid: string;
  dashboard: DisasterDashboardResponse;
  isReadOnly: boolean;
  onRefresh: () => Promise<void>;
};

export function DisasterResponsibilitiesTab({
  disasterPublicUuid,
  dashboard,
  isReadOnly,
  onRefresh,
}: DisasterResponsibilitiesTabProps) {
  const [assignOpen, setAssignOpen] = useState(false);
  const [revokeTarget, setRevokeTarget] = useState<DisasterResponsibility | null>(null);
  const [isRevoking, setIsRevoking] = useState(false);
  const responsibilities = dashboard.responsibilities ?? [];

  const handleRevoke = async () => {
    if (!revokeTarget) return;
    setIsRevoking(true);
    try {
      await postRevokeDisasterResponsibility(disasterPublicUuid, {
        agencyPublicUuid: revokeTarget.agency_public_uuid,
        responsibilityType:
          revokeTarget.responsibility_type as DisasterResponsibilityType,
      });
      toast.success("Responsibility revoked.");
      setRevokeTarget(null);
      await onRefresh();
    } catch (err) {
      toast.error(
        err instanceof ApiError
          ? getApiErrorMessage(err, err.message)
          : "Failed to revoke responsibility.",
      );
    } finally {
      setIsRevoking(false);
    }
  };

  return (
    <>
      <CommandSectionCard
        title="Responsibilities"
        headerAction={
          !isReadOnly ? (
            <Button type="button" size="sm" onClick={() => setAssignOpen(true)}>
              Assign responsibility
            </Button>
          ) : undefined
        }
      >
        {responsibilities.length === 0 ? (
          <p className="text-sm text-slate-600">No agency responsibilities assigned.</p>
        ) : (
          <ul className="space-y-2 text-sm">
            {responsibilities.map((r) => (
              <li
                key={`${r.agency_public_uuid}-${r.responsibility_type}`}
                className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-100 px-3 py-2"
              >
                <div className="min-w-0">
                  <span className="font-medium text-slate-900">
                    {r.agency_name ?? "Agency"}
                  </span>
                  <span className="text-slate-600">
                    {" "}
                    · {formatResponsibilityTypeLabel(r.responsibility_type)}
                  </span>
                  {r.is_lead ? (
                    <span className="ml-2 inline-block">
                      <Badge size="compact">Lead</Badge>
                    </span>
                  ) : null}
                </div>
                {!isReadOnly ? (
                  <Button
                    type="button"
                    size="sm"
                    variant="danger"
                    onClick={() => setRevokeTarget(r)}
                  >
                    Revoke
                  </Button>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </CommandSectionCard>

      <AssignResponsibilityModal
        open={assignOpen}
        disasterPublicUuid={disasterPublicUuid}
        onClose={() => setAssignOpen(false)}
        onSuccess={onRefresh}
      />

      <ConfirmModal
        open={revokeTarget != null}
        title="Revoke responsibility"
        message={
          revokeTarget
            ? `Revoke ${formatResponsibilityTypeLabel(revokeTarget.responsibility_type)} for ${revokeTarget.agency_name ?? "this agency"}? Managed shelters or relief hubs assigned through this responsibility will be unlinked.`
            : ""
        }
        confirmLabel="Revoke"
        isLoading={isRevoking}
        onConfirm={() => void handleRevoke()}
        onCancel={() => setRevokeTarget(null)}
      />
    </>
  );
}
