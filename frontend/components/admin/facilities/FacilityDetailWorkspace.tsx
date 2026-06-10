"use client";

import dynamic from "next/dynamic";
import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { CommandSectionCard } from "@/components/dispatcher/incidents/command/CommandSectionCard";
import { FacilityCapabilitiesPanel } from "@/components/admin/facilities/FacilityCapabilitiesPanel";
import { FacilityDefaultCapacitiesPanel } from "@/components/admin/facilities/FacilityDefaultCapacitiesPanel";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { ConfirmModal } from "@/components/ui/ConfirmModal";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import { ApiError, getApiErrorMessage } from "@/lib/api";
import {
  activateAdminFacility,
  deactivateAdminFacility,
  getAdminFacility,
} from "@/lib/admin-facility-api";
import {
  formatFacilityAddressText,
  formatFacilityLocationSummary,
  formatFacilityTypeLabel,
} from "@/lib/admin-facility-format";
import { nationalDisasterFacilitiesPath } from "@/lib/admin-national-disaster-routes";
import type { AdminFacility } from "@/types/admin-facility";
import { toast } from "sonner";

const MAP_PREVIEW_HEIGHT_CLASS = "h-full min-h-[200px]";

const ReportedLocationMapPreview = dynamic(
  () =>
    import("@/components/dispatcher/triage/ReportedLocationMapPreview").then(
      (mod) => ({ default: mod.ReportedLocationMapPreview }),
    ),
  {
    ssr: false,
    loading: () => (
      <div
        className={`${MAP_PREVIEW_HEIGHT_CLASS} w-full animate-pulse rounded-lg bg-slate-100`}
      />
    ),
  },
);

type FacilityDetailWorkspaceProps = {
  facilityPublicUuid: string;
};

export function FacilityDetailWorkspace({
  facilityPublicUuid,
}: FacilityDetailWorkspaceProps) {
  const [facility, setFacility] = useState<AdminFacility | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isMutating, setIsMutating] = useState(false);
  const [confirmDeactivateOpen, setConfirmDeactivateOpen] = useState(false);
  const [confirmActivateOpen, setConfirmActivateOpen] = useState(false);

  const loadFacility = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await getAdminFacility(facilityPublicUuid);
      setFacility(data.facility);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to load facility.",
      );
      setFacility(null);
    } finally {
      setIsLoading(false);
    }
  }, [facilityPublicUuid]);

  useEffect(() => {
    void loadFacility();
  }, [loadFacility]);

  const handleDeactivate = async () => {
    if (!facility) return;

    setIsMutating(true);
    try {
      const response = await deactivateAdminFacility(facility.publicUuid);
      setFacility(response.facility);
      setConfirmDeactivateOpen(false);
      toast.success("Facility deactivated.");
    } catch (err) {
      const message =
        err instanceof ApiError
          ? getApiErrorMessage(err, err.message)
          : "Failed to deactivate facility.";
      toast.error(message);
    } finally {
      setIsMutating(false);
    }
  };

  const handleActivate = async () => {
    if (!facility) return;

    setIsMutating(true);
    try {
      const response = await activateAdminFacility(facility.publicUuid);
      setFacility(response.facility);
      setConfirmActivateOpen(false);
      toast.success("Facility activated.");
    } catch (err) {
      const message =
        err instanceof ApiError
          ? getApiErrorMessage(err, err.message)
          : "Failed to activate facility.";
      toast.error(message);
    } finally {
      setIsMutating(false);
    }
  };

  if (isLoading && !facility) {
    return <LoadingSkeleton lines={8} />;
  }

  if (error && !facility) {
    return (
      <div className="space-y-4">
        <Link
          href={nationalDisasterFacilitiesPath()}
          className="text-sm font-medium text-[#002D62] hover:underline"
        >
          ← Facility Registry
        </Link>
        <ErrorAlert message={error} />
      </div>
    );
  }

  if (!facility) return null;

  const location = facility.location;

  return (
    <>
      <div className="flex min-h-0 flex-1 flex-col gap-4 lg:overflow-y-auto">
        <div className="shrink-0 space-y-1">
          <Link
            href={nationalDisasterFacilitiesPath()}
            className="text-sm font-medium text-[#002D62] hover:underline"
          >
            ← Facility Registry
          </Link>
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-xl font-semibold text-slate-900">
              {facility.name}
            </h2>
            <Badge
              size="compact"
              tone={facility.isActive ? "active" : "inactive"}
            >
              {facility.isActive ? "Active" : "Inactive"}
            </Badge>
            <span className="text-sm text-slate-600">{facility.facilityCode}</span>
          </div>
        </div>

        <CommandSectionCard
          title="Overview"
          headerAction={
            facility.isActive ? (
              <Button
                type="button"
                variant="secondary"
                size="sm"
                disabled={isMutating}
                onClick={() => setConfirmDeactivateOpen(true)}
              >
                Deactivate facility
              </Button>
            ) : (
              <Button
                type="button"
                variant="secondary"
                size="sm"
                disabled={isMutating}
                onClick={() => setConfirmActivateOpen(true)}
              >
                Activate facility
              </Button>
            )
          }
        >
          {location ? (
            <div className="grid gap-4 lg:grid-cols-2 lg:items-stretch lg:gap-5">
              <dl className="grid content-start gap-3 text-sm">
                <div>
                  <dt className="text-xs font-medium text-slate-500">Type</dt>
                  <dd className="mt-0.5 text-slate-900">
                    {formatFacilityTypeLabel(facility.facilityTypeCode)}
                  </dd>
                </div>
                <div>
                  <dt className="text-xs font-medium text-slate-500">
                    Location
                  </dt>
                  <dd className="mt-1.5 grid gap-3">
                    <div>
                      <span className="text-xs font-medium text-slate-500">
                        Address
                      </span>
                      <p className="mt-0.5 text-sm text-slate-900">
                        {formatFacilityAddressText(location.addressText) ?? "—"}
                      </p>
                    </div>
                    <div>
                      <span className="text-xs font-medium text-slate-500">
                        Administrative area
                      </span>
                      <p className="mt-0.5 text-sm text-slate-900">
                        {location.adminAreaLabel?.trim() || "—"}
                      </p>
                    </div>
                  </dd>
                </div>
              </dl>
              <div className="min-h-[200px] lg:min-h-0 lg:h-full">
                <ReportedLocationMapPreview
                  previewKey={facility.publicUuid}
                  latitude={location.latitude}
                  longitude={location.longitude}
                  addressText={location.addressText ?? undefined}
                  placeName={location.placeName ?? undefined}
                  className={MAP_PREVIEW_HEIGHT_CLASS}
                  heightClassName={MAP_PREVIEW_HEIGHT_CLASS}
                />
              </div>
            </div>
          ) : (
            <dl className="grid gap-3 text-sm sm:grid-cols-2">
              <div>
                <dt className="text-xs font-medium text-slate-500">Type</dt>
                <dd className="mt-0.5 text-slate-900">
                  {formatFacilityTypeLabel(facility.facilityTypeCode)}
                </dd>
              </div>
              <div className="sm:col-span-2">
                <dt className="text-xs font-medium text-slate-500">Location</dt>
                <dd className="mt-0.5 text-sm text-slate-900">
                  {formatFacilityLocationSummary(location) ??
                    "No location recorded"}
                </dd>
              </div>
            </dl>
          )}
        </CommandSectionCard>

        <div className="grid min-h-0 gap-4 lg:grid-cols-2">
          <FacilityCapabilitiesPanel
            facility={facility}
            onUpdated={setFacility}
          />
          <FacilityDefaultCapacitiesPanel
            facility={facility}
            onUpdated={setFacility}
          />
        </div>
      </div>

      <ConfirmModal
        open={confirmDeactivateOpen}
        title="Deactivate facility"
        message="This facility will no longer appear in disaster activation eligibility. Existing records are preserved."
        confirmLabel="Deactivate"
        isLoading={isMutating}
        onConfirm={() => void handleDeactivate()}
        onCancel={() => setConfirmDeactivateOpen(false)}
      />

      <ConfirmModal
        open={confirmActivateOpen}
        title="Activate facility"
        message="This facility will appear in disaster activation eligibility again. Existing records are preserved."
        confirmLabel="Activate"
        isLoading={isMutating}
        onConfirm={() => void handleActivate()}
        onCancel={() => setConfirmActivateOpen(false)}
      />
    </>
  );
}
