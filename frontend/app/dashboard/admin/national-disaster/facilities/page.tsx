"use client";

import { Suspense } from "react";
import { AdminDashboardPage } from "@/components/admin/AdminDashboardPage";
import { FacilityRegistryWorkspace } from "@/components/admin/facilities/FacilityRegistryWorkspace";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import { PageLoading } from "@/components/ui/StatusState";

function FacilityRegistryPageInner() {
  return <FacilityRegistryWorkspace />;
}

function FacilityRegistryPageContent() {
  return (
    <AdminDashboardPage loadingLabel="Loading facility registry">
      <Suspense fallback={<LoadingSkeleton lines={6} />}>
        <FacilityRegistryPageInner />
      </Suspense>
    </AdminDashboardPage>
  );
}

export default function FacilityRegistryPage() {
  return (
    <Suspense fallback={<PageLoading label="Loading facility registry" />}>
      <FacilityRegistryPageContent />
    </Suspense>
  );
}
