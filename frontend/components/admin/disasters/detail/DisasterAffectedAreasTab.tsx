"use client";

import { useState } from "react";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { EditAffectedAreaModal } from "@/components/admin/disasters/detail/EditAffectedAreaModal";
import { formatAffectedAreaLabel } from "@/lib/disaster-operations-format";
import type { DisasterAffectedArea, DisasterDashboardResponse } from "@/types/disaster-operations";

type DisasterAffectedAreasTabProps = {
  disasterPublicUuid: string;
  dashboard: DisasterDashboardResponse;
  isReadOnly: boolean;
  onRefresh: () => Promise<void>;
};

export function DisasterAffectedAreasTab({
  disasterPublicUuid,
  dashboard,
  isReadOnly,
  onRefresh,
}: DisasterAffectedAreasTabProps) {
  const [editArea, setEditArea] = useState<DisasterAffectedArea | null>(null);
  const areas = dashboard.affected_areas ?? [];

  return (
    <>
      <div className="mb-3">
        <h3 className="text-sm font-semibold text-slate-900">Affected Areas</h3>
        <p className="mt-0.5 text-xs text-slate-600">
          {areas.length} upazila record(s)
        </p>
      </div>

      {areas.length === 0 ? (
        <p className="text-sm text-slate-600">No affected areas recorded.</p>
      ) : (
        <ul className="space-y-2">
          {areas.map((area) => (
            <li
              key={area.affected_area_public_uuid}
              className="flex flex-wrap items-start justify-between gap-2 rounded-lg border border-slate-100 px-3 py-2 text-sm"
            >
              <div className="min-w-0 flex-1">
                <p className="font-medium text-slate-900">
                  {formatAffectedAreaLabel(area)}
                </p>
                {area.impact_level ? (
                  <p className="mt-0.5 text-xs text-slate-600">
                    Impact: {formatBadgeLabel(area.impact_level)}
                  </p>
                ) : null}
                {area.estimated_affected_people != null ? (
                  <p className="mt-0.5 text-xs text-slate-600">
                    Est. affected:{" "}
                    {area.estimated_affected_people.toLocaleString()}
                  </p>
                ) : null}
                <div className="mt-1 flex flex-wrap gap-1">
                  {area.shelter_support_required ? (
                    <Badge size="compact">Shelter needed</Badge>
                  ) : null}
                  {area.relief_support_required ? (
                    <Badge size="compact">Relief needed</Badge>
                  ) : null}
                </div>
                {area.assessment_note ? (
                  <p className="mt-1 text-xs text-slate-500">{area.assessment_note}</p>
                ) : null}
              </div>
              {!isReadOnly ? (
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => setEditArea(area)}
                >
                  Edit assessment
                </Button>
              ) : null}
            </li>
          ))}
        </ul>
      )}

      <EditAffectedAreaModal
        open={editArea != null}
        disasterPublicUuid={disasterPublicUuid}
        area={editArea}
        onClose={() => setEditArea(null)}
        onSuccess={onRefresh}
      />
    </>
  );
}
