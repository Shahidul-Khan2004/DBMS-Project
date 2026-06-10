"use client";

import { Suspense } from "react";
import { AdminDashboardPage } from "@/components/admin/AdminDashboardPage";
import { NationalDisasterLandingWorkspace } from "@/components/admin/national-disaster/NationalDisasterLandingWorkspace";
import { NationalDisasterWorkspaceFrame } from "@/components/admin/national-disaster/NationalDisasterWorkspaceFrame";
import { PageLoading } from "@/components/ui/StatusState";

function NationalDisasterLandingPageContent() {
  return (
    <AdminDashboardPage loadingLabel="Loading national disaster management">
      <NationalDisasterWorkspaceFrame showSectionSwitch>
        <NationalDisasterLandingWorkspace />
      </NationalDisasterWorkspaceFrame>
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
