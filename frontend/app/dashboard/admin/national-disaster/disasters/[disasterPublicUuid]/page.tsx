"use client";

import { Suspense, use } from "react";
import { AdminDashboardPage } from "@/components/admin/AdminDashboardPage";
import { DisasterDetailWorkspace } from "@/components/admin/disasters";
import { PageLoading } from "@/components/ui/StatusState";

function DisasterDetailPageContent({
  params,
}: {
  params: Promise<{ disasterPublicUuid: string }>;
}) {
  const { disasterPublicUuid } = use(params);

  return (
    <AdminDashboardPage loadingLabel="Loading disaster command">
      <DisasterDetailWorkspace disasterPublicUuid={disasterPublicUuid} />
    </AdminDashboardPage>
  );
}

export default function NationalDisasterDetailPage({
  params,
}: {
  params: Promise<{ disasterPublicUuid: string }>;
}) {
  return (
    <Suspense fallback={<PageLoading label="Loading disaster command" />}>
      <DisasterDetailPageContent params={params} />
    </Suspense>
  );
}
