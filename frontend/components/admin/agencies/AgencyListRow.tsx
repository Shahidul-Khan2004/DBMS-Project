"use client";

import { ChevronRight } from "lucide-react";
import { getDispatcherClickableCardRowClasses } from "@/components/dispatcher/listRowHoverStyles";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { formatAdminAgencyTypeLabel } from "@/lib/admin-agency-types";
import { formatBangladeshTime } from "@/lib/datetime";
import type { AdminAgencyListItem } from "@/types/admin-agency";

type AgencyListRowProps = {
  agency: AdminAgencyListItem;
  selected?: boolean;
  onSelect: (agencyPublicUuid: string) => void;
};

export function AgencyListRow({
  agency,
  selected = false,
  onSelect,
}: AgencyListRowProps) {
  return (
    <li>
      <button
        type="button"
        onClick={() => onSelect(agency.public_uuid)}
        className={`group flex w-full flex-wrap items-center justify-between gap-3 rounded-xl border px-4 py-3 text-left focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-[#002D62] ${getDispatcherClickableCardRowClasses({ selected })}`}
      >
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-slate-900">{agency.name}</p>
          <p className="mt-0.5 text-xs text-slate-600">{agency.agency_code}</p>
          <p className="mt-1 text-xs text-slate-500">
            Updated {formatBangladeshTime(agency.updated_at)}
          </p>
        </div>
        <div className="flex shrink-0 flex-wrap items-center gap-2">
          <Badge size="compact" tone="neutral">
            {formatBadgeLabel(
              formatAdminAgencyTypeLabel(agency.agency_type_code),
            )}
          </Badge>
          <Badge size="compact" tone={agency.is_active ? "success" : "neutral"}>
            {agency.is_active ? "Active" : "Inactive"}
          </Badge>
          <span className="flex items-center gap-0.5 text-xs font-medium text-[#002D62]">
            Manage agency
            <ChevronRight
              className="h-4 w-4 transition-transform group-hover:translate-x-0.5"
              aria-hidden
            />
          </span>
        </div>
      </button>
    </li>
  );
}
