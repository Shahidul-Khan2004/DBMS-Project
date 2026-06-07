"use client";

import Link from "next/link";
import { useState } from "react";
import { ArrowLeft } from "lucide-react";
import { AddReportToDisasterDialog } from "@/components/dispatcher/disasters/AddReportToDisasterDialog";
import { DisasterCommandHeader } from "@/components/dispatcher/disasters/DisasterCommandHeader";
import { DisasterContextCard } from "@/components/dispatcher/disasters/DisasterContextCard";
import { DisasterReportsIncidentsPanel } from "@/components/dispatcher/disasters/DisasterReportsIncidentsPanel";
import { LinkExistingIncidentToDisasterDialog } from "@/components/dispatcher/disasters/LinkExistingIncidentToDisasterDialog";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { EmptyState } from "@/components/ui/StatusState";
import { dispatcherNationalDisasterLandingPath } from "@/lib/dispatcher-national-disaster-routes";
import { useDisasterCommandDashboard } from "@/lib/hooks/use-disaster-command-dashboard";

export function DisasterCommandLinkReportsWorkspace({
  disasterPublicUuid,
}: {
  disasterPublicUuid: string;
}) {
  const { dashboard, loading, error, refresh } =
    useDisasterCommandDashboard(disasterPublicUuid);
  const [addReportOpen, setAddReportOpen] = useState(false);
  const [linkIncidentOpen, setLinkIncidentOpen] = useState(false);
  const [preselectedReportUuid, setPreselectedReportUuid] = useState<string | null>(
    null,
  );

  const openAddReport = (reportPublicUuid?: string) => {
    setPreselectedReportUuid(reportPublicUuid ?? null);
    setAddReportOpen(true);
  };

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
    <div className="flex min-h-0 flex-1 flex-col lg:overflow-hidden">
      <DisasterCommandHeader
        mode="link-reports"
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

      <div className="mt-4 grid min-h-0 flex-1 gap-4 overflow-hidden lg:grid-cols-[minmax(300px,32fr)_minmax(720px,68fr)] lg:overflow-hidden">
        <aside className="min-h-0 overflow-hidden">
          <DisasterContextCard dashboard={dashboard} />
        </aside>

        <main className="min-h-0 flex flex-col overflow-hidden">
          <DisasterReportsIncidentsPanel
            className="min-h-0 flex-1"
            dashboard={dashboard}
            disasterPublicUuid={disasterPublicUuid}
            onAddReport={openAddReport}
            onLinkIncident={() => setLinkIncidentOpen(true)}
            onRefresh={refresh}
          />
        </main>
      </div>

      <AddReportToDisasterDialog
        open={addReportOpen}
        disasterPublicUuid={disasterPublicUuid}
        dashboard={dashboard}
        preselectedReportPublicUuid={preselectedReportUuid}
        onClose={() => {
          setAddReportOpen(false);
          setPreselectedReportUuid(null);
        }}
        onSuccess={refresh}
      />

      <LinkExistingIncidentToDisasterDialog
        open={linkIncidentOpen}
        mode="pick-incident"
        disasterPublicUuid={disasterPublicUuid}
        dashboard={dashboard}
        onClose={() => setLinkIncidentOpen(false)}
        onSuccess={refresh}
      />
    </div>
  );
}
