"use client";

import { Suspense, use } from "react";
import { AdminDashboardPage } from "@/components/admin/AdminDashboardPage";
import { FacilityDetailWorkspace } from "@/components/admin/facilities";
import { NationalDisasterWorkspaceFrame } from "@/components/admin/national-disaster/NationalDisasterWorkspaceFrame";
import { PageLoading } from "@/components/ui/StatusState";

function FacilityDetailPageContent({
  params,
}: {
  params: Promise<{ facilityPublicUuid: string }>;
}) {
  const { facilityPublicUuid } = use(params);

  return (
    <AdminDashboardPage
      loadingLabel="Loading facility"
      scrollContent
    >
      <NationalDisasterWorkspaceFrame>
        <FacilityDetailWorkspace facilityPublicUuid={facilityPublicUuid} />
      </NationalDisasterWorkspaceFrame>
    </AdminDashboardPage>
  );
}

export default function NationalDisasterFacilityDetailPage({
  params,
}: {
  params: Promise<{ facilityPublicUuid: string }>;
}) {
  return (
    <Suspense fallback={<PageLoading label="Loading facility" />}>
      <FacilityDetailPageContent params={params} />
    </Suspense>
  );
}
