"use client";

import { useState } from "react";
import { DisasterActivityDialog } from "@/components/dispatcher/disasters/DisasterActivityDialog";
import {
  DisasterActivityPreviewRow,
  getDisasterActivityPreviewItems,
  getDisasterActivityTotalCount,
  hasDisasterActivity,
} from "@/components/dispatcher/disasters/disaster-activity-content";
import { DisasterOverviewSectionCard } from "@/components/dispatcher/disasters/DisasterOverviewSectionCard";
import type { OperationsDisasterDashboard } from "@/lib/disaster-operations-types";

function ViewDetailsButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="cursor-pointer text-sm font-semibold text-[#006747] hover:text-[#00543A]"
    >
      View details
    </button>
  );
}

export function DisasterActivityPanel({
  dashboard,
  includeAudit = true,
  className = "",
  previewMode = false,
  previewLimit,
  compactHeader = false,
}: {
  dashboard: OperationsDisasterDashboard;
  includeAudit?: boolean;
  className?: string;
  previewMode?: boolean;
  previewLimit?: number;
  compactHeader?: boolean;
}) {
  const [dialogOpen, setDialogOpen] = useState(false);
  const hasActivity = hasDisasterActivity(dashboard, includeAudit);
  const effectivePreviewLimit = previewLimit ?? (previewMode ? 1 : 3);
  const previewItems = getDisasterActivityPreviewItems(
    dashboard,
    includeAudit,
    effectivePreviewLimit,
  );
  const totalCount = getDisasterActivityTotalCount(dashboard, includeAudit);
  const remainingActivity = Math.max(totalCount - previewItems.length, 0);

  const subtitle = compactHeader || previewMode
    ? undefined
    : includeAudit
      ? "Declarations, status changes, and audit"
      : "Declarations and status changes";

  return (
    <>
      <DisasterOverviewSectionCard
        title="Disaster Activity"
        subtitle={subtitle}
        className={className}
        fillBody={!previewMode}
        previewMode={previewMode}
        right={hasActivity ? <ViewDetailsButton onClick={() => setDialogOpen(true)} /> : null}
      >
        {!hasActivity ? (
          <p className="text-sm text-slate-600">No disaster activity recorded.</p>
        ) : previewMode ? (
          <>
            <ul className="divide-y divide-slate-100">
              {previewItems.map((item, index) => (
                <DisasterActivityPreviewRow
                  key={
                    item.kind === "declaration"
                      ? item.data.public_uuid
                      : item.kind === "status"
                        ? `status-${item.data.recorded_at}-${item.index}`
                        : `audit-${item.data.id ?? item.data.created_at}-${index}`
                  }
                  item={item}
                  flattened
                />
              ))}
            </ul>
            {remainingActivity > 0 ? (
              <div className="mt-auto pt-2">
                <p className="border-t border-slate-100 pt-2 text-xs text-slate-500">
                  {remainingActivity} more{" "}
                  {remainingActivity === 1 ? "entry" : "entries"} available
                </p>
              </div>
            ) : null}
          </>
        ) : (
          <>
            <ul className="divide-y divide-slate-100">
              {previewItems.map((item, index) => (
                <DisasterActivityPreviewRow
                  key={
                    item.kind === "declaration"
                      ? item.data.public_uuid
                      : item.kind === "status"
                        ? `status-${item.data.recorded_at}-${item.index}`
                        : `audit-${item.data.id ?? item.data.created_at}-${index}`
                  }
                  item={item}
                />
              ))}
            </ul>
            {remainingActivity > 0 ? (
              <p className="mt-2 shrink-0 text-xs text-slate-500">
                {remainingActivity} more{" "}
                {remainingActivity === 1 ? "entry" : "entries"} available
              </p>
            ) : null}
          </>
        )}
      </DisasterOverviewSectionCard>

      <DisasterActivityDialog
        open={dialogOpen}
        dashboard={dashboard}
        includeAudit={includeAudit}
        onClose={() => setDialogOpen(false)}
      />
    </>
  );
}

/** Mini activity card for Link Reports left column */
export function DisasterActivityMiniCard({
  dashboard,
}: {
  dashboard: OperationsDisasterDashboard;
}) {
  return <DisasterActivityPanel dashboard={dashboard} includeAudit={false} />;
}
