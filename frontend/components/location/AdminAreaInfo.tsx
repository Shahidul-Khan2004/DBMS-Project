"use client";

import { useEffect, useState } from "react";
import { fetchAdministrativeAreaById } from "@/lib/admin-area-api";
import type { AdministrativeAreaDetail } from "@/types/admin-area";

type AdminAreaInfoProps = {
  adminAreaId?: number | null;
  className?: string;
  /** When true, shows labeled rows (Upazila, District, Division) instead of one line. */
  detailed?: boolean;
};

function formatAdminAreaLines(detail: AdministrativeAreaDetail): string[] {
  const lines: string[] = [];
  if (detail.union) {
    lines.push(`Union: ${detail.union.name}`);
  }
  if (detail.upazila) {
    lines.push(`Upazila: ${detail.upazila.name}`);
  }
  if (detail.district) {
    lines.push(`District: ${detail.district.name}`);
  }
  if (detail.division) {
    lines.push(`Division: ${detail.division.name}`);
  }
  return lines;
}

export function AdminAreaInfo({
  adminAreaId,
  className = "",
  detailed = false,
}: AdminAreaInfoProps) {
  const [detail, setDetail] = useState<AdministrativeAreaDetail | null>(null);

  useEffect(() => {
    if (adminAreaId == null) {
      setDetail(null);
      return;
    }

    let cancelled = false;
    void fetchAdministrativeAreaById(adminAreaId).then((next) => {
      if (!cancelled) {
        setDetail(next);
      }
    });

    return () => {
      cancelled = true;
    };
  }, [adminAreaId]);

  if (adminAreaId == null || !detail) {
    return null;
  }

  if (detailed) {
    const lines = formatAdminAreaLines(detail);
    if (lines.length === 0) {
      return null;
    }

    return (
      <div className={`space-y-0.5 ${className}`.trim()}>
        {lines.map((line) => (
          <p key={line} className="text-xs text-slate-500">
            {line}
          </p>
        ))}
      </div>
    );
  }

  const label = detail.hierarchyPath.trim();
  if (!label) {
    return null;
  }

  return (
    <p className={`text-xs text-slate-500 ${className}`.trim()}>{label}</p>
  );
}
