"use client";

import Link from "next/link";
import { use } from "react";
import { AgencyDashboardPage } from "@/components/agency/AgencyDashboardPage";
import { AgencyDisasterDetailWorkspace } from "@/components/agency/national-disaster/AgencyDisasterDetailWorkspace";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { agencyNationalDisasterLandingPath } from "@/lib/agency-national-disaster-routes";
import { useAgencyDisasterDetail } from "@/lib/hooks/use-agency-disaster-detail";

export default function AgencyNationalDisasterDetailPage({
  params,
}: {
  params: Promise<{ disasterPublicUuid: string }>;
}) {
  const { disasterPublicUuid } = use(params);
  const { detail, incidents, loading, incidentsLoading, error, refreshAll } =
    useAgencyDisasterDetail(disasterPublicUuid);

  return (
    <AgencyDashboardPage>
      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        <div className="mb-3 flex shrink-0 flex-wrap items-center justify-between gap-3">
          <Link
            href={agencyNationalDisasterLandingPath()}
            className="text-sm font-medium text-[#002D62] hover:underline"
          >
            ← Back to disasters
          </Link>
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={loading}
            onClick={() => void refreshAll()}
          >
            Refresh
          </Button>
        </div>

        {error ? (
          <div className="mb-3 shrink-0">
            <ErrorAlert message={error} />
          </div>
        ) : null}

        <section className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-2xl border border-slate-200/80 bg-white p-4 shadow-sm">
          <AgencyDisasterDetailWorkspace
            disasterPublicUuid={disasterPublicUuid}
            detail={detail}
            incidents={incidents}
            loading={loading}
            incidentsLoading={incidentsLoading}
            onRefresh={refreshAll}
          />
        </section>
      </div>
    </AgencyDashboardPage>
  );
}
