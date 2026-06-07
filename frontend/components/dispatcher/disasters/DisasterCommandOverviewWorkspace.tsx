"use client";

import Link from "next/link";
import { ArrowLeft } from "lucide-react";
import { DisasterActivityPanel } from "@/components/dispatcher/disasters/DisasterActivityPanel";
import { DisasterAffectedAreasPanel } from "@/components/dispatcher/disasters/DisasterAffectedAreasPanel";
import { DisasterCommandHeader } from "@/components/dispatcher/disasters/DisasterCommandHeader";
import { DisasterOverviewPanel } from "@/components/dispatcher/disasters/DisasterOverviewPanel";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { EmptyState } from "@/components/ui/StatusState";
import { dispatcherNationalDisasterLandingPath } from "@/lib/dispatcher-national-disaster-routes";
import { useDisasterCommandDashboard } from "@/lib/hooks/use-disaster-command-dashboard";

export function DisasterCommandOverviewWorkspace({
  disasterPublicUuid,
}: {
  disasterPublicUuid: string;
}) {
  const { dashboard, loading, error, refresh } =
    useDisasterCommandDashboard(disasterPublicUuid);

  if (loading) {
    return (
      <div className="space-y-3" aria-busy="true">
        <div className="h-10 animate-pulse rounded-lg bg-slate-100" />
        <div className="h-64 animate-pulse rounded-xl bg-slate-100" />
      </div>
    );
  }

  if (error || !dashboard) {
    return (
      <div className="space-y-3">
        <Link
          href={dispatcherNationalDisasterLandingPath()}
          className="inline-flex items-center gap-1 text-sm font-medium text-[#002D62] hover:text-[#006747]"
        >
          <ArrowLeft className="h-4 w-4" aria-hidden />
          National Disaster
        </Link>
        {error ? <ErrorAlert message={error} /> : null}
        <EmptyState
          title="Disaster unavailable"
          description="This disaster could not be loaded."
        />
      </div>
    );
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
      <DisasterCommandHeader
        mode="overview"
        disasterPublicUuid={disasterPublicUuid}
        dashboard={dashboard}
        actions={
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={loading}
            onClick={() => void refresh()}
          >
            Refresh
          </Button>
        }
      />

      <div className="mt-4 grid min-h-0 flex-1 gap-4 overflow-hidden lg:grid-cols-[minmax(420px,48fr)_minmax(460px,52fr)]">
        <section className="min-h-0 overflow-hidden">
          <DisasterOverviewPanel dashboard={dashboard} className="h-full" />
        </section>

        <section className="grid min-h-0 grid-rows-[minmax(0,1fr)_minmax(0,1fr)] gap-4 overflow-hidden">
          <DisasterAffectedAreasPanel
            dashboard={dashboard}
            className="min-h-0 h-full"
            previewMode
          />
          <DisasterActivityPanel
            dashboard={dashboard}
            className="min-h-0 h-full"
            previewMode
            compactHeader
          />
        </section>
      </div>
    </div>
  );
}
