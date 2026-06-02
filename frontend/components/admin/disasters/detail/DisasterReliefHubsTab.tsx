"use client";

import { useState } from "react";
import { CommandSectionCard } from "@/components/dispatcher/incidents/command/CommandSectionCard";
import { formatBadgeLabel } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { ActivateReliefHubModal } from "@/components/admin/disasters/detail/ActivateReliefHubModal";
import { StockReceiptModal } from "@/components/admin/disasters/detail/StockReceiptModal";
import { DisasterLocationDisplay } from "@/components/admin/disasters/detail/DisasterLocationDisplay";
import { formatReliefItemLabel } from "@/lib/disaster-operations-format";
import type {
  DisasterDashboardResponse,
  DisasterReliefHubActivation,
} from "@/types/disaster-operations";
import type { FacilityLocation } from "@/types/admin-facility";

type DisasterReliefHubsTabProps = {
  disasterPublicUuid: string;
  dashboard: DisasterDashboardResponse;
  facilityLocations: Map<string, FacilityLocation | null | undefined>;
  isReadOnly: boolean;
  onRefresh: () => Promise<void>;
};

export function DisasterReliefHubsTab({
  disasterPublicUuid,
  dashboard,
  facilityLocations,
  isReadOnly,
  onRefresh,
}: DisasterReliefHubsTabProps) {
  const [activateOpen, setActivateOpen] = useState(false);
  const [stockHub, setStockHub] = useState<DisasterReliefHubActivation | null>(null);
  const hubs = dashboard.relief_hubs ?? [];
  const inventory = dashboard.inventory_by_hub ?? [];

  return (
    <>
      <CommandSectionCard
        title="Relief Hubs"
        headerAction={
          !isReadOnly ? (
            <Button type="button" size="sm" onClick={() => setActivateOpen(true)}>
              Activate relief hub
            </Button>
          ) : undefined
        }
      >
        {hubs.length === 0 ? (
          <p className="text-sm text-slate-600">No relief hub activations.</p>
        ) : (
          <ul className="space-y-3 text-sm">
            {hubs.map((h) => {
              const location = h.facility_public_uuid
                ? facilityLocations.get(h.facility_public_uuid)
                : undefined;
              const hubInventory = inventory.filter(
                (row) => row.facility_name === h.facility_name,
              );
              return (
                <li
                  key={h.relief_hub_public_uuid ?? h.facility_public_uuid}
                  className="rounded-lg border border-slate-100 px-3 py-2"
                >
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div className="min-w-0 flex-1">
                      <p className="font-medium text-slate-900">
                        {h.facility_name ?? "Relief hub"}
                      </p>
                      {h.activation_status ? (
                        <p className="text-xs text-slate-600">
                          {formatBadgeLabel(h.activation_status)}
                        </p>
                      ) : null}
                      {hubInventory.length > 0 ? (
                        <ul className="mt-2 space-y-0.5 text-xs text-slate-600">
                          {hubInventory.map((row, idx) => (
                            <li key={`${row.item_code}-${idx}`}>
                              {formatReliefItemLabel(row.item_code)}:{" "}
                              {row.quantity_on_hand?.toLocaleString() ?? "—"} on hand
                            </li>
                          ))}
                        </ul>
                      ) : null}
                      <DisasterLocationDisplay location={location} className="mt-2" />
                    </div>
                    {!isReadOnly && h.relief_hub_public_uuid ? (
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        onClick={() => setStockHub(h)}
                      >
                        Record stock
                      </Button>
                    ) : null}
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </CommandSectionCard>

      <ActivateReliefHubModal
        open={activateOpen}
        disasterPublicUuid={disasterPublicUuid}
        onClose={() => setActivateOpen(false)}
        onSuccess={onRefresh}
      />
      <StockReceiptModal
        open={stockHub != null}
        disasterPublicUuid={disasterPublicUuid}
        hub={stockHub}
        onClose={() => setStockHub(null)}
        onSuccess={onRefresh}
      />
    </>
  );
}
