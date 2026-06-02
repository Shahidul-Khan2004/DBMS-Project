"use client";

import { useState } from "react";
import { toast } from "sonner";
import { CommandSectionCard } from "@/components/dispatcher/incidents/command/CommandSectionCard";
import { DisasterActivateFacilityDialog } from "@/components/admin/disasters/detail/DisasterActivateFacilityDialog";
import { StockReceiptModal } from "@/components/admin/disasters/detail/StockReceiptModal";
import { DisasterLocationDisplay } from "@/components/admin/disasters/detail/DisasterLocationDisplay";
import { formatBadgeLabel } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { ConfirmModal } from "@/components/ui/ConfirmModal";
import { ApiError, getApiErrorMessage } from "@/lib/api";
import { postDeactivateDisasterReliefHub } from "@/lib/disaster-operations-api";
import {
  formatReliefItemLabel,
  isActiveDisasterActivation,
} from "@/lib/disaster-operations-format";
import type {
  DisasterDashboardResponse,
  DisasterReliefHubActivation,
} from "@/types/disaster-operations";
import type { AdminFacilityListItem, FacilityLocation } from "@/types/admin-facility";

type DisasterReliefHubsTabProps = {
  disasterPublicUuid: string;
  dashboard: DisasterDashboardResponse;
  facilities: AdminFacilityListItem[];
  facilityLocations: Map<string, FacilityLocation | null | undefined>;
  isReadOnly: boolean;
  onRefresh: () => Promise<void>;
  sectionTitle?: string;
  hideListActivateAction?: boolean;
  suppressActivateModal?: boolean;
  emptyMessage?: string;
};

export function DisasterReliefHubsTab({
  disasterPublicUuid,
  dashboard,
  facilities,
  facilityLocations,
  isReadOnly,
  onRefresh,
  sectionTitle = "Relief Hubs",
  hideListActivateAction = false,
  suppressActivateModal = false,
  emptyMessage,
}: DisasterReliefHubsTabProps) {
  const [activateOpen, setActivateOpen] = useState(false);
  const [stockHub, setStockHub] = useState<DisasterReliefHubActivation | null>(null);
  const [deactivateHub, setDeactivateHub] = useState<DisasterReliefHubActivation | null>(null);
  const [isDeactivating, setIsDeactivating] = useState(false);

  const inventory = dashboard.inventory_by_hub ?? [];
  const activeHubs = (dashboard.relief_hubs ?? []).filter((h) =>
    isActiveDisasterActivation(h.activation_status),
  );

  const resolvedEmptyMessage =
    emptyMessage ??
    "No active relief hubs. Reactivate a deactivated hub above, or use Activate relief hubs to add one.";

  const handleDeactivateHub = async () => {
    if (!deactivateHub?.relief_hub_public_uuid) return;
    setIsDeactivating(true);
    try {
      await postDeactivateDisasterReliefHub(
        disasterPublicUuid,
        deactivateHub.relief_hub_public_uuid,
      );
      toast.success("Relief hub deactivated.");
      setDeactivateHub(null);
      await onRefresh();
    } catch (err) {
      toast.error(
        err instanceof ApiError
          ? getApiErrorMessage(err, err.message)
          : "Failed to deactivate relief hub.",
      );
    } finally {
      setIsDeactivating(false);
    }
  };

  const renderHubRow = (h: DisasterReliefHubActivation) => {
    const location = h.facility_public_uuid
      ? facilityLocations.get(h.facility_public_uuid)
      : undefined;
    const hubInventory = inventory.filter((row) => row.facility_name === h.facility_name);

    return (
      <li
        key={h.relief_hub_public_uuid ?? h.facility_public_uuid}
        className="rounded-lg border border-slate-100 px-3 py-2.5"
      >
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 flex-1 space-y-0.5">
            <p className="font-medium text-slate-900">{h.facility_name ?? "Relief hub"}</p>
            {h.activation_status ? (
              <p className="text-xs text-slate-600">
                {formatBadgeLabel(h.activation_status)}
              </p>
            ) : null}
            {hubInventory.length > 0 ? (
              <p className="text-xs text-slate-600">
                {hubInventory
                  .map(
                    (row) =>
                      `${formatReliefItemLabel(row.item_code)}: ${row.quantity_on_hand?.toLocaleString() ?? "—"}`,
                  )
                  .join(" · ")}
              </p>
            ) : null}
            <DisasterLocationDisplay location={location} className="mt-1" compact />
          </div>
          {!isReadOnly && h.relief_hub_public_uuid ? (
            <div className="flex shrink-0 flex-col gap-1 sm:flex-row sm:flex-wrap">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => setStockHub(h)}
              >
                Record stock
              </Button>
              <Button
                type="button"
                variant="danger"
                size="sm"
                onClick={() => setDeactivateHub(h)}
              >
                Deactivate relief hub
              </Button>
            </div>
          ) : null}
        </div>
      </li>
    );
  };

  return (
    <>
      <CommandSectionCard
        title={sectionTitle}
        headerAction={
          !isReadOnly && !hideListActivateAction ? (
            <Button type="button" size="sm" onClick={() => setActivateOpen(true)}>
              Activate relief hubs
            </Button>
          ) : undefined
        }
      >
        {activeHubs.length === 0 ? (
          <p className="text-sm text-slate-600">{resolvedEmptyMessage}</p>
        ) : (
          <ul className="space-y-2 text-sm">
            {activeHubs.map((h) => renderHubRow(h))}
          </ul>
        )}
      </CommandSectionCard>

      {!suppressActivateModal ? (
        <DisasterActivateFacilityDialog
          mode="hub"
          open={activateOpen}
          disasterPublicUuid={disasterPublicUuid}
          dashboard={dashboard}
          facilities={facilities}
          onClose={() => setActivateOpen(false)}
          onSuccess={onRefresh}
        />
      ) : null}

      <StockReceiptModal
        open={stockHub != null}
        disasterPublicUuid={disasterPublicUuid}
        hub={stockHub}
        onClose={() => setStockHub(null)}
        onSuccess={onRefresh}
      />
      <ConfirmModal
        open={deactivateHub != null}
        title="Deactivate relief hub"
        message={`Deactivate ${deactivateHub?.facility_name ?? "this relief hub"}?`}
        confirmLabel="Deactivate"
        isLoading={isDeactivating}
        onConfirm={() => void handleDeactivateHub()}
        onCancel={() => setDeactivateHub(null)}
      />
    </>
  );
}
