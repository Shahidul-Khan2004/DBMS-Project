"use client";

import { Suspense, use } from "react";
import { AdminDashboardPage } from "@/components/admin/AdminDashboardPage";
import { FacilityDetailWorkspace } from "@/components/admin/facilities";
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
      <FacilityDetailWorkspace facilityPublicUuid={facilityPublicUuid} />
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
