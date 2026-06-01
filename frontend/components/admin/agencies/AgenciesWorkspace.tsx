"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { AdminPageHeader } from "@/components/admin/AdminPageHeader";
import { AgenciesToolbar } from "@/components/admin/agencies/AgenciesToolbar";
import { AgencyCategorySwitcher } from "@/components/admin/agencies/AgencyCategorySwitcher";
import { AgencyDetailDrawer } from "@/components/admin/agencies/AgencyDetailDrawer";
import { AgencyListRow } from "@/components/admin/agencies/AgencyListRow";
import { OnboardAgencyDialog } from "@/components/admin/agencies/OnboardAgencyDialog";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import {
  buildAgencyCategoryOptions,
  getAgencyListHeading,
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

  const categoryOptions = useMemo(
    () => buildAgencyCategoryOptions(agencies),
    [agencies],
  );

  const visibleAgencies = useMemo(
    () =>
      selectedAgencyType === "all"
        ? agencies
        : agencies.filter(
            (agency) => agency.agency_type_code === selectedAgencyType,
          ),
    [agencies, selectedAgencyType],
  );

  const listHeading = useMemo(
    () => getAgencyListHeading(selectedAgencyType, visibleAgencies.length),
    [selectedAgencyType, visibleAgencies.length],
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
      />

      <div className="mb-3 flex shrink-0 flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        {agencies.length > 0 ? (
          <AgencyCategorySwitcher
            options={categoryOptions}
            selectedCode={selectedAgencyType}
            onSelect={setSelectedAgencyType}
            disabled={isLoading}
          />
        ) : null}
        <AgenciesToolbar
          resultLabel={listHeading.subtitle}
          total={total}
          limit={PAGE_LIMIT}
          offset={offset}
          isLoading={isLoading}
          className={agencies.length === 0 ? "lg:ml-auto" : ""}
          onRefresh={() => void loadAgencies(offset)}
          onPrev={() => setOffset((o) => Math.max(0, o - PAGE_LIMIT))}
          onNext={() => setOffset((o) => o + PAGE_LIMIT)}
          onOnboard={() => setOnboardOpen(true)}
        />
      </div>

      {error ? (
        <ErrorAlert message={error} />
      ) : null}

      <div className="flex min-h-0 flex-1 flex-col rounded-xl border border-slate-200/80 bg-white shadow-sm lg:overflow-hidden">
        <div className="min-h-0 flex-1 overflow-y-auto overscroll-y-contain p-3 lg:p-4">
          {isLoading && agencies.length === 0 ? (
            <LoadingSkeleton lines={6} />
          ) : agencies.length === 0 ? (
            <p className="py-8 text-center text-sm text-slate-600">
              No agencies found.
            </p>
          ) : visibleAgencies.length === 0 ? (
            <p className="py-8 text-center text-sm text-slate-600">
              No agencies found in this category.
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
        onSuccess={() => void loadAgencies(0)}
      />
    </div>
  );
}
