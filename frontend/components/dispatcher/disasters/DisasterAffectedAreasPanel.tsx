"use client";

import { useState } from "react";
import { AffectedAreasDialog } from "@/components/dispatcher/disasters/AffectedAreasDialog";
import {
  DisasterAffectedAreasList,
  getAffectedAreaKey,
} from "@/components/dispatcher/disasters/DisasterAffectedAreasList";
import { DisasterOverviewSectionCard } from "@/components/dispatcher/disasters/DisasterOverviewSectionCard";
import { Badge } from "@/components/ui/Badge";
import { formatDisasterImpactLevel } from "@/lib/disaster-operations-format";
import type { OperationsDisasterDashboard } from "@/lib/disaster-operations-types";
import type { DisasterAffectedArea } from "@/types/disaster-operations";

function ViewMoreButton({
  onClick,
  label = "View more",
}: {
  onClick: () => void;
  label?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="cursor-pointer text-sm font-semibold text-[#006747] hover:text-[#00543A]"
    >
      {label}
    </button>
  );
}

function getSupportLabel(area: DisasterAffectedArea): string | null {
  const flags: string[] = [];
  if (area.shelter_support_required) flags.push("Shelter");
  if (area.relief_support_required) flags.push("Relief");
  if (flags.length === 0) return null;
  return `${flags.join(" · ")} support`;
}

function AffectedAreaPreviewRow({ area }: { area: DisasterAffectedArea }) {
  const supportLabel = getSupportLabel(area);

  return (
    <li className="flex items-start justify-between gap-4 py-2">
      <div className="min-w-0">
        <p className="truncate text-sm font-semibold text-slate-900">
          {area.upazila_name?.trim() || "Unknown upazila"}
        </p>
        <p className="text-xs text-slate-600">
          {area.district_name?.trim() || "Unknown district"}
        </p>
        {supportLabel ? (
          <p className="mt-0.5 text-xs text-slate-500">{supportLabel}</p>
        ) : null}
      </div>

      <div className="shrink-0 text-right">
        {area.impact_level ? (
          <Badge size="compact" tone="warning">
            {formatDisasterImpactLevel(area.impact_level)}
          </Badge>
        ) : null}
        {area.estimated_affected_people != null ? (
          <p className="mt-1 text-xs text-slate-600">
            ~{area.estimated_affected_people.toLocaleString()} affected
          </p>
        ) : null}
      </div>
    </li>
  );
}

export function DisasterAffectedAreasPanel({
  dashboard,
  className = "",
  previewMode = false,
  previewLimit,
}: {
  dashboard: OperationsDisasterDashboard;
  className?: string;
  previewMode?: boolean;
  previewLimit?: number;
}) {
  const [dialogOpen, setDialogOpen] = useState(false);
  const areas = dashboard.affected_areas ?? [];
  const effectivePreviewLimit = previewLimit ?? (previewMode ? 1 : 3);
  const previewAreas = areas.slice(0, effectivePreviewLimit);
  const remainingAreas = Math.max(areas.length - previewAreas.length, 0);

  return (
    <>
      <DisasterOverviewSectionCard
        title="Affected Areas"
        className={className}
        fillBody={!previewMode}
        previewMode={previewMode}
        right={
          areas.length > 0 ? (
            <ViewMoreButton onClick={() => setDialogOpen(true)} />
          ) : null
        }
      >
        {areas.length === 0 ? (
          <p className="text-sm text-slate-600">No affected areas recorded.</p>
        ) : previewMode ? (
          <>
            <ul className="divide-y divide-slate-100">
              {previewAreas.map((area) => (
                <AffectedAreaPreviewRow
                  key={getAffectedAreaKey(area)}
                  area={area}
                />
              ))}
            </ul>
            {remainingAreas > 0 ? (
              <div className="mt-auto pt-2">
                <p className="border-t border-slate-100 pt-2 text-xs text-slate-500">
                  Showing {previewAreas.length} of {areas.length} areas.
                </p>
              </div>
            ) : null}
          </>
        ) : (
          <>
            <DisasterAffectedAreasList areas={previewAreas} compact />
            {remainingAreas > 0 ? (
              <p className="mt-2 shrink-0 text-xs text-slate-500">
                Showing {previewAreas.length} of {areas.length} areas
              </p>
            ) : null}
          </>
        )}
      </DisasterOverviewSectionCard>

      <AffectedAreasDialog
        open={dialogOpen}
        dashboard={dashboard}
        onClose={() => setDialogOpen(false)}
      />
    </>
  );
}
