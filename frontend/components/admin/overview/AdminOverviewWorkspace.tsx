"use client";

import { AdminPageHeader } from "@/components/admin/AdminPageHeader";
import { AdminWorkflowCard } from "@/components/admin/overview/AdminWorkflowCard";
import { ADMIN_WORKFLOW_AREAS } from "@/components/admin/overview/adminWorkflowRoutes";

export function AdminOverviewWorkspace() {
  return (
    <div className="flex w-full flex-col gap-5">
      <AdminPageHeader
        title="Command Center"
        subtitle="Manage platform access, agency readiness, reports, and emergency administration workflows."
      />

      <section className="w-full">
        <div className="mb-5">
          <h3 className="text-base font-semibold text-slate-900">
            Admin Workflow Areas
          </h3>
          <p className="mt-1 text-sm text-slate-600">
            Choose the area you want to manage.
          </p>
        </div>
        <div className="grid w-full auto-rows-fr gap-5 sm:grid-cols-2">
          {ADMIN_WORKFLOW_AREAS.map((area) => (
            <AdminWorkflowCard key={area.id} area={area} />
          ))}
        </div>
      </section>
    </div>
  );
}
