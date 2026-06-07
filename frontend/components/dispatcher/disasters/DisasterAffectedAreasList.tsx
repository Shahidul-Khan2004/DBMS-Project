"use client";

import { Badge } from "@/components/ui/Badge";
import { formatDisasterImpactLevel } from "@/lib/disaster-operations-format";
import type { DisasterAffectedArea } from "@/types/disaster-operations";

export function getAffectedAreaKey(area: DisasterAffectedArea): string {
  return (
    area.affected_area_public_uuid ||
    String(area.admin_area_id ?? "") ||
    `${area.upazila_name ?? "unknown"}-${area.district_name ?? "unknown"}`
  );
}

function SupportFlags({ area }: { area: DisasterAffectedArea }) {
  const flags: string[] = [];
  if (area.shelter_support_required) flags.push("Shelter");
  if (area.relief_support_required) flags.push("Relief");
  if (flags.length === 0) return null;
  return (
    <span className="text-xs text-slate-500">{flags.join(" · ")} support</span>
  );
}

export function DisasterAffectedAreasList({
  areas,
  compact = false,
}: {
  areas: DisasterAffectedArea[];
  compact?: boolean;
}) {
  return (
    <ul className="divide-y divide-slate-100">
      {areas.map((area) => (
        <li
          key={getAffectedAreaKey(area)}
          className={`flex items-start justify-between gap-4 ${compact ? "py-2" : "py-3"}`}
        >
          <div className="min-w-0">
            <p className="text-sm font-medium text-slate-900">
              {area.upazila_name?.trim() || "Unknown upazila"}
            </p>
            <p className="mt-0.5 text-xs text-slate-600">
              {area.district_name?.trim() || "Unknown district"}
            </p>
            <SupportFlags area={area} />
          </div>
          <div className="flex shrink-0 flex-col items-end gap-1">
            {area.impact_level ? (
              <Badge size="compact" tone="warning">
                {formatDisasterImpactLevel(area.impact_level)}
              </Badge>
            ) : null}
            {area.estimated_affected_people != null ? (
              <span className="text-xs text-slate-600">
                ~{area.estimated_affected_people.toLocaleString()} affected
              </span>
            ) : null}
          </div>
        </li>
      ))}
    </ul>
  );
}
