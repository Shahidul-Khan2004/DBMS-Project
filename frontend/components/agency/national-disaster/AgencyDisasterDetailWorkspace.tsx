"use client";

import { useMemo, useState } from "react";
import { AgencyCreateReliefRequestModal } from "@/components/agency/national-disaster/AgencyCreateReliefRequestModal";
import { AgencyReliefHubStockReceiptModal } from "@/components/agency/national-disaster/AgencyReliefHubStockReceiptModal";
import { AgencyShelterOccupancyModal } from "@/components/agency/national-disaster/AgencyShelterOccupancyModal";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { EmptyState } from "@/components/ui/StatusState";
import { AgencySkeletonBlock } from "@/components/agency/AgencySkeletonBlock";
import {
  formatDisasterEventTypeLabel,
  formatDisasterSeverityLabel,
  formatDisasterStatusLabel,
  formatReliefHubInventorySummary,
  formatReliefItemLabel,
  formatReliefRequestStatusLabel,
  getActiveDisasterShelters,
  getReliefHubInventoryRowsForActivation,
  isActiveDisasterActivation,
} from "@/lib/disaster-operations-format";
import type {
  AgencyDisasterDetailResponse,
  AgencyDisasterIncidentsResponse,
} from "@/types/agency-disaster";
import type {
  DisasterReliefHubActivation,
  DisasterShelterActivation,
} from "@/types/disaster-operations";

type TabId = "overview" | "shelters" | "relief-hubs" | "relief" | "incidents";

const TABS: Array<{ id: TabId; label: string }> = [
  { id: "overview", label: "Overview" },
  { id: "shelters", label: "My Shelters" },
  { id: "relief-hubs", label: "My Relief Hubs" },
  { id: "relief", label: "Relief Requests" },
  { id: "incidents", label: "Linked Incidents" },
];

export function AgencyDisasterDetailWorkspace({
  disasterPublicUuid,
  detail,
  incidents,
  loading,
  incidentsLoading,
  onRefresh,
}: {
  disasterPublicUuid: string;
  detail: AgencyDisasterDetailResponse | null;
  incidents: AgencyDisasterIncidentsResponse | null;
  loading: boolean;
  incidentsLoading: boolean;
  onRefresh: () => Promise<void>;
}) {
  const [activeTab, setActiveTab] = useState<TabId>("overview");
  const [occupancyShelter, setOccupancyShelter] =
    useState<DisasterShelterActivation | null>(null);
  const [reliefModalOpen, setReliefModalOpen] = useState(false);
  const [stockHub, setStockHub] = useState<DisasterReliefHubActivation | null>(null);

  const activeShelters = useMemo(
    () => getActiveDisasterShelters(detail?.shelters ?? []),
    [detail?.shelters],
  );

  const activeReliefHubs = useMemo(
    () =>
      (detail?.relief_hubs ?? []).filter((hub) =>
        isActiveDisasterActivation(hub.activation_status),
      ),
    [detail?.relief_hubs],
  );

  if (loading) {
    return (
      <div className="space-y-3" aria-busy="true">
        <AgencySkeletonBlock className="h-10 w-full" />
        <AgencySkeletonBlock className="h-48 w-full" />
      </div>
    );
  }

  if (!detail) {
    return (
      <EmptyState
        title="Disaster unavailable"
        description="This disaster is not assigned to your agency or could not be loaded."
      />
    );
  }

  const disaster = detail.disaster;

  return (
    <>
      <div className="flex h-full min-h-0 flex-1 flex-col overflow-hidden">
        <header className="mb-3 shrink-0">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              <h2 className="text-xl font-semibold text-slate-900">{disaster.title}</h2>
              <p className="mt-0.5 text-sm text-slate-600">{disaster.event_code}</p>
            </div>
            <div className="flex flex-wrap gap-2">
              <Badge size="compact" tone="neutral">
                {formatBadgeLabel(
                  formatDisasterEventTypeLabel(
                    disaster.event_type_code,
                    disaster.event_type_name,
                  ),
                )}
              </Badge>
              {disaster.severity_level ? (
                <Badge size="compact" tone="warning">
                  {formatBadgeLabel(formatDisasterSeverityLabel(disaster.severity_level))}
                </Badge>
              ) : null}
              <Badge size="compact" tone="active">
                {formatBadgeLabel(formatDisasterStatusLabel(disaster.status_code))}
              </Badge>
            </div>
          </div>
        </header>

        <div className="mb-3 flex shrink-0 flex-wrap gap-1 border-b border-slate-200 pb-2">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id)}
              className={`rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
                activeTab === tab.id
                  ? "bg-[#002D62] text-white"
                  : "text-slate-600 hover:bg-slate-100"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto overscroll-y-contain pr-0.5 [scrollbar-width:thin]">
          {activeTab === "overview" ? (
            <div className="space-y-4">
              {disaster.public_guidance ? (
                <section className="rounded-xl border border-slate-200/80 bg-slate-50/80 p-4">
                  <h3 className="text-sm font-semibold text-slate-900">Public guidance</h3>
                  <p className="mt-2 text-sm text-slate-700">{disaster.public_guidance}</p>
                </section>
              ) : null}
              <section className="rounded-xl border border-slate-200/80 bg-white p-4">
                <h3 className="text-sm font-semibold text-slate-900">Affected areas</h3>
                {detail.affected_areas.length === 0 ? (
                  <p className="mt-2 text-sm text-slate-600">No affected areas recorded.</p>
                ) : (
                  <ul className="mt-2 space-y-2">
                    {detail.affected_areas.map((area) => (
                      <li
                        key={area.affected_area_public_uuid}
                        className="rounded-lg border border-slate-100 px-3 py-2 text-sm"
                      >
                        <p className="font-medium text-slate-900">
                          {area.upazila_name}, {area.district_name}
                        </p>
                        {area.impact_level ? (
                          <p className="text-xs text-slate-600">
                            Impact: {area.impact_level}
                          </p>
                        ) : null}
                      </li>
                    ))}
                  </ul>
                )}
              </section>
              {detail.declarations.length > 0 ? (
                <section className="rounded-xl border border-slate-200/80 bg-white p-4">
                  <h3 className="text-sm font-semibold text-slate-900">Declarations</h3>
                  <ul className="mt-2 space-y-2">
                    {detail.declarations.map((decl) => (
                      <li
                        key={decl.public_uuid}
                        className="rounded-lg border border-slate-100 px-3 py-2 text-sm"
                      >
                        <p className="font-medium text-slate-900">{decl.title}</p>
                        {decl.public_guidance ? (
                          <p className="mt-1 text-xs text-slate-600">{decl.public_guidance}</p>
                        ) : null}
                      </li>
                    ))}
                  </ul>
                </section>
              ) : null}
            </div>
          ) : null}

          {activeTab === "shelters" ? (
            <section className="space-y-3">
              {detail.shelters.length === 0 ? (
                <EmptyState
                  title="No managed shelters"
                  description="Your agency has no shelters assigned to this disaster yet. A coordinator must assign a managing agency after activation."
                />
              ) : (
                detail.shelters.map((shelter) => (
                  <div
                    key={shelter.shelter_activation_public_uuid}
                    className="rounded-xl border border-slate-200/80 bg-white p-4"
                  >
                    <div className="flex flex-wrap items-start justify-between gap-2">
                      <div>
                        <p className="text-sm font-semibold text-slate-900">
                          {shelter.facility_name}
                        </p>
                        <p className="mt-0.5 text-xs text-slate-600">
                          Status: {shelter.activation_status ?? "—"}
                        </p>
                      </div>
                      {shelter.activation_status === "active" ? (
                        <Button
                          type="button"
                          size="sm"
                          variant="outline"
                          onClick={() => setOccupancyShelter(shelter)}
                        >
                          Record occupancy
                        </Button>
                      ) : null}
                    </div>
                    <div className="mt-3 flex flex-wrap gap-3 text-xs text-slate-600">
                      {shelter.effective_capacity != null ? (
                        <span>Capacity: {shelter.effective_capacity.toLocaleString()}</span>
                      ) : null}
                      {shelter.latest_occupancy != null ? (
                        <span>Occupancy: {shelter.latest_occupancy.toLocaleString()}</span>
                      ) : null}
                      {shelter.available_capacity != null ? (
                        <span>
                          Available: {shelter.available_capacity.toLocaleString()}
                        </span>
                      ) : null}
                    </div>
                  </div>
                ))
              )}
            </section>
          ) : null}

          {activeTab === "relief-hubs" ? (
            <section className="space-y-3">
              {activeReliefHubs.length === 0 ? (
                <EmptyState
                  title="No managed relief hubs"
                  description="Your agency has no relief hubs assigned to this disaster yet. A coordinator must assign relief management responsibility and link hubs after activation."
                />
              ) : (
                activeReliefHubs.map((hub) => {
                  const hubInventory = getReliefHubInventoryRowsForActivation(
                    detail.inventory_by_hub ?? [],
                    hub,
                  );
                  const inventorySummary = formatReliefHubInventorySummary(hubInventory);

                  return (
                    <div
                      key={hub.relief_hub_public_uuid}
                      className="rounded-xl border border-slate-200/80 bg-white p-4"
                    >
                      <div className="flex flex-wrap items-start justify-between gap-2">
                        <div>
                          <p className="text-sm font-semibold text-slate-900">
                            {hub.facility_name}
                          </p>
                          <p className="mt-0.5 text-xs text-slate-600">
                            Status: {hub.activation_status ?? "—"}
                          </p>
                          {inventorySummary ? (
                            <p className="mt-1 text-xs text-slate-600">{inventorySummary}</p>
                          ) : (
                            <p className="mt-1 text-xs text-slate-600">No stock recorded yet.</p>
                          )}
                        </div>
                        <Button
                          type="button"
                          size="sm"
                          variant="outline"
                          onClick={() => setStockHub(hub)}
                        >
                          Record stock
                        </Button>
                      </div>
                    </div>
                  );
                })
              )}
            </section>
          ) : null}

          {activeTab === "relief" ? (
            <section className="space-y-3">
              <div className="flex justify-end">
                <Button
                  type="button"
                  size="sm"
                  onClick={() => setReliefModalOpen(true)}
                  disabled={activeShelters.length === 0}
                >
                  Create relief request
                </Button>
              </div>
              {detail.relief_requests.length === 0 ? (
                <EmptyState
                  title="No relief requests"
                  description="Submit a relief request for one of your agency-managed shelters."
                />
              ) : (
                detail.relief_requests.map((request) => (
                  <div
                    key={request.relief_request_public_uuid}
                    className="rounded-xl border border-slate-200/80 bg-white p-4"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <p className="text-sm font-semibold text-slate-900">
                        {request.request_code}
                      </p>
                      <Badge size="compact" tone="neutral">
                        {formatBadgeLabel(
                          formatReliefRequestStatusLabel(request.status_code),
                        )}
                      </Badge>
                    </div>
                    <p className="mt-1 text-xs text-slate-600">
                      Shelter: {request.shelter_facility_name ?? "—"}
                    </p>
                    {request.shortages && request.shortages.length > 0 ? (
                      <ul className="mt-2 space-y-1 text-xs text-slate-600">
                        {request.shortages.map((item) => (
                          <li key={`${request.relief_request_public_uuid}-${item.relief_item_code}`}>
                            {formatReliefItemLabel(item.relief_item_code)} — short{" "}
                            {item.quantity_short ?? 0}
                          </li>
                        ))}
                      </ul>
                    ) : null}
                  </div>
                ))
              )}
            </section>
          ) : null}

          {activeTab === "incidents" ? (
            <section className="space-y-3">
              {incidentsLoading ? (
                <AgencySkeletonBlock className="h-24 w-full" />
              ) : (incidents?.incidents.length ?? 0) === 0 ? (
                <EmptyState
                  title="No linked incidents"
                  description="No disaster-linked incidents involve your agency participation yet."
                />
              ) : (
                incidents?.incidents.map((incident) => (
                  <div
                    key={incident.incident_public_uuid}
                    className="rounded-xl border border-slate-200/80 bg-white p-4"
                  >
                    <p className="text-sm font-semibold text-slate-900">
                      {incident.title ?? incident.incident_code}
                    </p>
                    <p className="mt-0.5 text-xs text-slate-600">{incident.incident_code}</p>
                    <div className="mt-2 flex flex-wrap gap-2">
                      {incident.incident_status ? (
                        <Badge size="compact" tone="neutral">
                          {formatBadgeLabel(incident.incident_status)}
                        </Badge>
                      ) : null}
                      {incident.participation_status ? (
                        <Badge size="compact" tone="active">
                          {formatBadgeLabel(incident.participation_status)}
                        </Badge>
                      ) : null}
                    </div>
                  </div>
                ))
              )}
            </section>
          ) : null}
        </div>
      </div>

      <AgencyShelterOccupancyModal
        open={occupancyShelter != null}
        disasterPublicUuid={disasterPublicUuid}
        shelter={occupancyShelter}
        onClose={() => setOccupancyShelter(null)}
        onSuccess={onRefresh}
      />

      <AgencyCreateReliefRequestModal
        open={reliefModalOpen}
        disasterPublicUuid={disasterPublicUuid}
        activeShelters={activeShelters}
        onClose={() => setReliefModalOpen(false)}
        onSuccess={onRefresh}
      />

      <AgencyReliefHubStockReceiptModal
        open={stockHub != null}
        disasterPublicUuid={disasterPublicUuid}
        hub={stockHub}
        onClose={() => setStockHub(null)}
        onSuccess={onRefresh}
      />
    </>
  );
}
