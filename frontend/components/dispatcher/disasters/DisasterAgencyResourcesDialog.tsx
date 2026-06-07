"use client";

import { useState } from "react";
import { createPortal } from "react-dom";
import { getDisasterSegmentActiveClasses } from "@/components/dispatcher/disasters/disasterColors";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import {
  formatReliefItemLabel,
  formatReliefRequestStatusLabel,
  getActiveDisasterReliefHubs,
  getActiveDisasterShelters,
} from "@/lib/disaster-operations-format";
import type { OperationsDisasterDashboard } from "@/lib/disaster-operations-types";
import type {
  DisasterReliefHubActivation,
  DisasterReliefRequest,
  DisasterShelterActivation,
} from "@/types/disaster-operations";

type ResourceTab = "shelters" | "relief_hubs" | "relief_requests";

type DisasterAgencyResourcesDialogProps = {
  open: boolean;
  dashboard: OperationsDisasterDashboard;
  onClose: () => void;
};

function formatOptionalLocation(
  record: Record<string, unknown>,
): string | null {
  const upazila = record.location_upazila_name ?? record.upazila_name;
  const district = record.district_name ?? record.location_district_name;
  const parts = [upazila, district]
    .filter((value): value is string => typeof value === "string" && value.trim().length > 0)
    .map((value) => value.trim());
  return parts.length > 0 ? parts.join(", ") : null;
}

function ShelterRow({ shelter }: { shelter: DisasterShelterActivation }) {
  const location = formatOptionalLocation(shelter as Record<string, unknown>);

  return (
    <li className="rounded-lg border border-slate-100 bg-slate-50/60 px-3 py-2 text-sm">
      <p className="font-medium text-slate-900">{shelter.facility_name ?? "Shelter"}</p>
      <p className="mt-0.5 text-xs text-slate-600">
        {shelter.latest_occupancy != null
          ? `Occupancy: ${shelter.latest_occupancy}`
          : "Occupancy not recorded"}
        {shelter.effective_capacity != null
          ? ` / ${shelter.effective_capacity} capacity`
          : ""}
      </p>
      {location ? <p className="mt-0.5 text-xs text-slate-500">{location}</p> : null}
    </li>
  );
}

function ReliefHubRow({ hub }: { hub: DisasterReliefHubActivation }) {
  const location = formatOptionalLocation(hub as Record<string, unknown>);
  const status = hub.activation_status?.trim();

  return (
    <li className="rounded-lg border border-slate-100 bg-slate-50/60 px-3 py-2 text-sm">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <p className="font-medium text-slate-900">{hub.facility_name ?? "Relief hub"}</p>
        {status ? (
          <Badge size="compact" tone="neutral">
            {formatBadgeLabel(status)}
          </Badge>
        ) : null}
      </div>
      {location ? <p className="mt-0.5 text-xs text-slate-500">{location}</p> : null}
    </li>
  );
}

function ReliefRequestRow({ request }: { request: DisasterReliefRequest }) {
  const shortages = request.shortages ?? [];

  return (
    <li className="rounded-lg border border-slate-100 bg-slate-50/60 px-3 py-2 text-sm">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <p className="font-medium text-slate-900">
          {request.request_code ?? "Relief request"}
        </p>
        <Badge size="compact" tone="neutral">
          {formatBadgeLabel(formatReliefRequestStatusLabel(request.status_code))}
        </Badge>
      </div>
      {request.shelter_facility_name ? (
        <p className="mt-0.5 text-xs text-slate-600">
          Shelter: {request.shelter_facility_name}
        </p>
      ) : null}
      {shortages.length > 0 ? (
        <ul className="mt-1.5 space-y-0.5 text-xs text-slate-600">
          {shortages.map((shortage, index) => (
            <li key={`${shortage.relief_item_code ?? "item"}-${index}`}>
              {formatReliefItemLabel(shortage.relief_item_code)}
              {shortage.quantity_short != null && shortage.quantity_short > 0
                ? `: short ${shortage.quantity_short.toLocaleString()}`
                : ""}
            </li>
          ))}
        </ul>
      ) : null}
    </li>
  );
}

export function DisasterAgencyResourcesDialog({
  open,
  dashboard,
  onClose,
}: DisasterAgencyResourcesDialogProps) {
  const [activeTab, setActiveTab] = useState<ResourceTab>("shelters");

  const shelters = getActiveDisasterShelters(dashboard.shelters ?? []);
  const reliefHubs = getActiveDisasterReliefHubs(dashboard.relief_hubs ?? []);
  const reliefRequests = dashboard.relief_requests ?? [];

  const tabOptions: { value: ResourceTab; label: string }[] = [
    { value: "shelters", label: `Shelters (${shelters.length})` },
    { value: "relief_hubs", label: `Relief Hubs (${reliefHubs.length})` },
    { value: "relief_requests", label: `Relief Requests (${reliefRequests.length})` },
  ];

  if (!open) return null;

  const dialog = (
    <div
      className="fixed inset-0 z-[60] flex items-center justify-center bg-black/40 px-4 py-6"
      onClick={onClose}
    >
      <div
        className="flex max-h-[min(90vh,720px)] w-full max-w-2xl flex-col rounded-xl border border-slate-200 bg-white shadow-xl"
        role="dialog"
        aria-labelledby="agency-resources-title"
        aria-modal="true"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="shrink-0 border-b border-slate-100 px-5 py-4">
          <h2 id="agency-resources-title" className="text-lg font-semibold text-slate-900">
            Agency Resources
          </h2>
          <p className="mt-0.5 text-xs text-slate-600">
            Read-only shelter, relief hub, and relief request details for this disaster.
          </p>
        </div>

        <div className="shrink-0 border-b border-slate-100 px-5 py-3">
          <div
            role="tablist"
            aria-label="Agency resource categories"
            className="inline-flex max-w-full flex-wrap gap-1 rounded-lg border border-slate-200 bg-slate-50/80 p-1"
          >
            {tabOptions.map((option) => {
              const isActive = activeTab === option.value;
              return (
                <button
                  key={option.value}
                  type="button"
                  role="tab"
                  aria-selected={isActive}
                  onClick={() => setActiveTab(option.value)}
                  className={`inline-flex shrink-0 cursor-pointer items-center rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
                    isActive
                      ? getDisasterSegmentActiveClasses()
                      : "text-slate-600 hover:bg-slate-100 hover:text-slate-900"
                  }`}
                >
                  {option.label}
                </button>
              );
            })}
          </div>
        </div>

        <div
          className="min-h-0 flex-1 overflow-y-auto overscroll-y-contain px-5 py-4"
          role="tabpanel"
        >
          {activeTab === "shelters" ? (
            shelters.length === 0 ? (
              <p className="text-sm text-slate-600">No active shelters for this disaster.</p>
            ) : (
              <ul className="space-y-2">
                {shelters.map((shelter) => (
                  <ShelterRow
                    key={
                      shelter.shelter_activation_public_uuid ??
                      shelter.facility_public_uuid
                    }
                    shelter={shelter}
                  />
                ))}
              </ul>
            )
          ) : null}

          {activeTab === "relief_hubs" ? (
            reliefHubs.length === 0 ? (
              <p className="text-sm text-slate-600">No active relief hubs for this disaster.</p>
            ) : (
              <ul className="space-y-2">
                {reliefHubs.map((hub) => (
                  <ReliefHubRow
                    key={hub.relief_hub_public_uuid ?? hub.facility_public_uuid}
                    hub={hub}
                  />
                ))}
              </ul>
            )
          ) : null}

          {activeTab === "relief_requests" ? (
            reliefRequests.length === 0 ? (
              <p className="text-sm text-slate-600">No relief requests for this disaster.</p>
            ) : (
              <ul className="space-y-2">
                {reliefRequests.map((request) => (
                  <ReliefRequestRow
                    key={request.relief_request_public_uuid}
                    request={request}
                  />
                ))}
              </ul>
            )
          ) : null}
        </div>

        <div className="flex shrink-0 justify-end border-t border-slate-100 px-5 py-4">
          <Button type="button" variant="secondary" onClick={onClose}>
            Close
          </Button>
        </div>
      </div>
    </div>
  );

  if (typeof document === "undefined") return null;
  return createPortal(dialog, document.body);
}
