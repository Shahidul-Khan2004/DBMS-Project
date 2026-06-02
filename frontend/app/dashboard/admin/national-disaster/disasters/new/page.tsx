"use client";

import { Suspense } from "react";
import { AdminDashboardPage } from "@/components/admin/AdminDashboardPage";
import { DeclareDisasterWizard } from "@/components/admin/disasters";
import { PageLoading } from "@/components/ui/StatusState";

function DeclareDisasterPageContent() {
  return (
    <AdminDashboardPage
      loadingLabel="Loading declaration wizard"
      scrollContent
    >
      <DeclareDisasterWizard />
    </AdminDashboardPage>
  );
}

export default function NationalDisasterDeclarePage() {
  return (
    <Suspense fallback={<PageLoading label="Loading declaration wizard" />}>
      <DeclareDisasterPageContent />
    </Suspense>
  );
}
