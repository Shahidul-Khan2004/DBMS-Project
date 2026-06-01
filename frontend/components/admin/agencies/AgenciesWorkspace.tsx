"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { AdminPageHeader } from "@/components/admin/AdminPageHeader";
import { AgenciesToolbar } from "@/components/admin/agencies/AgenciesToolbar";
import { AgencyCategorySwitcher } from "@/components/admin/agencies/AgencyCategorySwitcher";
import { AgencyDetailDrawer } from "@/components/admin/agencies/AgencyDetailDrawer";
import { AgencyListRow } from "@/components/admin/agencies/AgencyListRow";
import { AddRepresentativeDialog } from "@/components/admin/agencies/AddRepresentativeDialog";
import { OnboardAgencyDialog } from "@/components/admin/agencies/OnboardAgencyDialog";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import {
  buildAgencyCategoryOptions,
  filterAdminAgencyNetworkAgencies,
  getAgencyListHeading,
  isAdminAgencyNetworkCategoryCode,
} from "@/lib/admin-agency-types";
import { listAdminAgencies } from "@/lib/admin-agency-api";
import type { AdminAgencyListItem } from "@/types/admin-agency";

const PAGE_LIMIT = 100;

export function AgenciesWorkspace() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const agencyFromQuery = searchParams.get("agency");

  const [agencies, setAgencies] = useState<AdminAgencyListItem[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedUuid, setSelectedUuid] = useState<string | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [onboardOpen, setOnboardOpen] = useState(false);
  const [postOnboardLinkAgency, setPostOnboardLinkAgency] =
    useState<AdminAgencyListItem | null>(null);
  const [selectedAgencyType, setSelectedAgencyType] = useState("all");

  const loadAgencies = useCallback(async (nextOffset: number) => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await listAdminAgencies({
        limit: PAGE_LIMIT,
        offset: nextOffset,
      });
      setAgencies(data.agencies);
      setTotal(data.total);
      setOffset(data.offset);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to load agencies.",
      );
      setAgencies([]);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadAgencies(offset);
  }, [offset, loadAgencies]);

  useEffect(() => {
    if (!agencyFromQuery?.trim()) return;
    setSelectedUuid(agencyFromQuery.trim());
    setDrawerOpen(true);
  }, [agencyFromQuery]);

  useEffect(() => {
    if (!isAdminAgencyNetworkCategoryCode(selectedAgencyType)) {
      setSelectedAgencyType("all");
    }
  }, [selectedAgencyType]);

  const networkAgencies = useMemo(
    () => filterAdminAgencyNetworkAgencies(agencies),
    [agencies],
  );

  const categoryOptions = useMemo(
    () => buildAgencyCategoryOptions(agencies),
    [agencies],
  );

  const visibleAgencies = useMemo(() => {
    if (selectedAgencyType === "all") return networkAgencies;
    return networkAgencies.filter(
      (agency) => agency.agency_type_code === selectedAgencyType,
    );
  }, [networkAgencies, selectedAgencyType]);

  const listHeading = useMemo(
    () => getAgencyListHeading(selectedAgencyType, visibleAgencies.length),
    [selectedAgencyType, visibleAgencies.length],
  );

  const handleSelectAgencyType = useCallback(
    (code: string) => {
      setSelectedAgencyType(code);
      if (offset !== 0) {
        setOffset(0);
      }
    },
    [offset],
  );

  const openDrawer = (uuid: string) => {
    setSelectedUuid(uuid);
    setDrawerOpen(true);
    const params = new URLSearchParams(searchParams.toString());
    params.set("agency", uuid);
    router.replace(`/dashboard/admin/agencies?${params.toString()}`, {
      scroll: false,
    });
  };

  const closeDrawer = useCallback(() => {
    setDrawerOpen(false);
    setSelectedUuid(null);
    const params = new URLSearchParams(searchParams.toString());
    params.delete("agency");
    const query = params.toString();
    router.replace(
      query
        ? `/dashboard/admin/agencies?${query}`
        : "/dashboard/admin/agencies",
      { scroll: false },
    );
  }, [router, searchParams]);

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2 lg:overflow-hidden">
      <AdminPageHeader
        title="Agencies"
        subtitle="Onboard agencies, manage representatives, and maintain agency access."
        action={
          <AgenciesToolbar
            resultLabel={listHeading.subtitle}
            total={total}
            limit={PAGE_LIMIT}
            offset={offset}
            isLoading={isLoading}
            onRefresh={() => void loadAgencies(offset)}
            onPrev={() => setOffset((o) => Math.max(0, o - PAGE_LIMIT))}
            onNext={() => setOffset((o) => o + PAGE_LIMIT)}
            onOnboard={() => setOnboardOpen(true)}
          />
        }
      />

      <div className="mb-4 w-full min-w-0 shrink-0">
        <AgencyCategorySwitcher
          options={categoryOptions}
          selectedCode={selectedAgencyType}
          onSelect={handleSelectAgencyType}
          disabled={isLoading}
        />
      </div>

      {error ? (
        <ErrorAlert message={error} />
      ) : null}

      <div className="flex min-h-0 flex-1 flex-col rounded-xl border border-slate-200/80 bg-white shadow-sm lg:overflow-hidden">
        <div className="min-h-0 flex-1 overflow-y-auto overscroll-y-contain p-3 lg:p-4">
          {isLoading && agencies.length === 0 ? (
            <LoadingSkeleton lines={6} />
          ) : !isLoading && agencies.length === 0 ? (
            <p className="py-8 text-center text-sm text-slate-600">
              No agencies found.
            </p>
          ) : visibleAgencies.length === 0 ? (
            <p className="py-8 text-center text-sm text-slate-600">
              No agencies found for this type.
            </p>
          ) : (
            <ul className="space-y-2">
              {visibleAgencies.map((agency) => (
                <AgencyListRow
                  key={agency.public_uuid}
                  agency={agency}
                  selected={selectedUuid === agency.public_uuid && drawerOpen}
                  onSelect={openDrawer}
                />
              ))}
            </ul>
          )}
        </div>
      </div>

      <AgencyDetailDrawer
        open={drawerOpen}
        agencyPublicUuid={selectedUuid}
        onOpenChange={(open) => {
          if (!open) closeDrawer();
          else setDrawerOpen(true);
        }}
        onMutated={() => void loadAgencies(offset)}
      />

      <OnboardAgencyDialog
        open={onboardOpen}
        onClose={() => setOnboardOpen(false)}
        onSuccess={(result) => {
          if (
            selectedAgencyType !== "all" &&
            selectedAgencyType !== result.agencyTypeCode
          ) {
            setSelectedAgencyType(result.agencyTypeCode);
          }
          setOffset(0);
          void loadAgencies(0);
          if (result.openLinkRepresentative) {
            setPostOnboardLinkAgency(result.agency);
          }
        }}
      />

      <AddRepresentativeDialog
        open={postOnboardLinkAgency !== null}
        agencyPublicUuid={postOnboardLinkAgency?.public_uuid ?? null}
        agencyName={postOnboardLinkAgency?.name}
        agencyCode={postOnboardLinkAgency?.agency_code}
        onClose={() => setPostOnboardLinkAgency(null)}
        onSuccess={() => setPostOnboardLinkAgency(null)}
      />
    </div>
  );
}
