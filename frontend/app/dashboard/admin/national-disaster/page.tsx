"use client";

import { Suspense } from "react";
import { AdminDashboardPage } from "@/components/admin/AdminDashboardPage";
import { NationalDisasterLandingWorkspace } from "@/components/admin/national-disaster/NationalDisasterLandingWorkspace";
import { PageLoading } from "@/components/ui/StatusState";

function NationalDisasterLandingPageContent() {
  return (
    <AdminDashboardPage loadingLabel="Loading national disaster management">
      <NationalDisasterLandingWorkspace />
    </AdminDashboardPage>
  );
}

export default function NationalDisasterLandingPage() {
  return (
    <Suspense fallback={<PageLoading label="Loading national disaster management" />}>
      <NationalDisasterLandingPageContent />
    </Suspense>
  );
}
