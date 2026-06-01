"use client";

import { Badge } from "@/components/ui/Badge";
import { formatBangladeshTime } from "@/lib/datetime";
import type { ServiceCaseAssignment } from "@/types/service-case";

function sortAssignments(assignments: ServiceCaseAssignment[]) {
  const active = assignments.filter(
    (row) =>
      row.assignment_status === "active" &&
      (row.ended_at == null || row.ended_at === ""),
  );
  const prior = assignments.filter((row) => !active.includes(row));
  return [...active, ...prior];
}

type ServiceCaseAssignmentTabProps = {
  assignments: ServiceCaseAssignment[];
};

export function ServiceCaseAssignmentTab({
  assignments,
}: ServiceCaseAssignmentTabProps) {
  if (assignments.length === 0) {
    return (
      <p className="text-sm text-slate-600">No assignments recorded for this case.</p>
    );
  }

  const sorted = sortAssignments(assignments);

  return (
    <ul className="divide-y divide-slate-100">
      {sorted.map((assignment) => {
        const isActive =
          assignment.assignment_status === "active" &&
          (assignment.ended_at == null || assignment.ended_at === "");
        const assigneeName =
          assignment.assigned_to?.full_name?.trim() || "Assigned operator";

        return (
          <li key={String(assignment.id)} className="py-3 first:pt-0 last:pb-0">
            <div className="flex flex-wrap items-start justify-between gap-2">
              <div className="min-w-0">
                <p className="text-sm font-semibold text-slate-900">
                  {assigneeName}
                </p>
                {isActive ? (
                  <p className="mt-0.5 text-xs font-medium text-[#006747]">
                    Current assignment
                  </p>
                ) : null}
              </div>
              <Badge tone={assignment.assignment_status}>
                {assignment.assignment_status.replace(/_/g, " ")}
              </Badge>
            </div>
            <dl className="mt-2 grid gap-1 text-xs text-slate-600">
              {assignment.assigned_at ? (
                <div>
                  <span className="font-medium text-slate-500">Assigned </span>
                  {formatBangladeshTime(assignment.assigned_at)}
                </div>
              ) : null}
              {assignment.ended_at ? (
                <div>
                  <span className="font-medium text-slate-500">Ended </span>
                  {formatBangladeshTime(assignment.ended_at)}
                </div>
              ) : null}
              {assignment.note?.trim() ? (
                <div>
                  <span className="font-medium text-slate-500">Note </span>
                  {assignment.note}
                </div>
              ) : null}
            </dl>
          </li>
        );
      })}
    </ul>
  );
}
