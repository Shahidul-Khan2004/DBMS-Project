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
    <span className="mt-0.5 block text-xs text-slate-500">
      {flags.join(" · ")} support
    </span>
  );
}

function SupportBadges({ area }: { area: DisasterAffectedArea }) {
  if (!area.shelter_support_required && !area.relief_support_required) {
    return null;
  }

  return (
    <div className="mt-1 flex flex-wrap gap-1">
      {area.shelter_support_required ? (
        <Badge size="compact">Shelter needed</Badge>
      ) : null}
      {area.relief_support_required ? (
        <Badge size="compact">Relief needed</Badge>
      ) : null}
    </div>
  );
}

function DisasterAffectedAreaRow({
  area,
  compact = false,
  detailed = false,
}: {
  area: DisasterAffectedArea;
  compact?: boolean;
  detailed?: boolean;
}) {
  if (detailed) {
    return (
      <li
        className={`flex items-start justify-between gap-4 ${compact ? "py-2.5" : "py-3"}`}
      >
        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium text-slate-900">
            {area.upazila_name?.trim() || "Unknown upazila"}
          </p>
          <p className="mt-0.5 text-xs text-slate-600">
            {area.district_name?.trim() || "Unknown district"}
          </p>
          {area.estimated_affected_people != null ? (
            <p className="mt-0.5 text-xs text-slate-600">
              Est. affected: {area.estimated_affected_people.toLocaleString()}
            </p>
          ) : null}
          <SupportBadges area={area} />
          {area.assessment_note ? (
            <p className="mt-1 text-xs text-slate-500">{area.assessment_note}</p>
          ) : null}
        </div>
        {area.impact_level ? (
          <div className="shrink-0">
            <Badge size="compact" tone="warning">
              {formatDisasterImpactLevel(area.impact_level)}
            </Badge>
          </div>
        ) : null}
      </li>
    );
  }

  return (
    <li
      className={`flex items-start justify-between gap-4 ${compact ? "py-2" : "py-3"}`}
    >
      <div className="min-w-0">
        <p
          className={`truncate text-sm ${compact ? "font-semibold" : "font-medium"} text-slate-900`}
        >
          {area.upazila_name?.trim() || "Unknown upazila"}
        </p>
        <p className="text-xs text-slate-600">
          {area.district_name?.trim() || "Unknown district"}
        </p>
        <SupportFlags area={area} />
      </div>
      <div className={`shrink-0 ${compact ? "text-right" : "flex flex-col items-end gap-1"}`}>
        {area.impact_level ? (
          <Badge size="compact" tone="warning">
            {formatDisasterImpactLevel(area.impact_level)}
          </Badge>
        ) : null}
        {area.estimated_affected_people != null ? (
          <p className={`text-xs text-slate-600 ${compact ? "mt-1" : ""}`}>
            ~{area.estimated_affected_people.toLocaleString()} affected
          </p>
        ) : null}
      </div>
    </li>
  );
}

export function DisasterAffectedAreasList({
  areas,
  compact = false,
  detailed = false,
  limit,
}: {
  areas: DisasterAffectedArea[];
  compact?: boolean;
  detailed?: boolean;
  limit?: number;
}) {
  const visibleAreas =
    limit != null && limit >= 0 ? areas.slice(0, limit) : areas;

  return (
    <ul className="divide-y divide-slate-100">
      {visibleAreas.map((area) => (
        <DisasterAffectedAreaRow
          key={getAffectedAreaKey(area)}
          area={area}
          compact={compact}
          detailed={detailed}
        />
      ))}
    </ul>
  );
}
