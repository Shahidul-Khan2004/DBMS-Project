"use client";

import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";

export function ServiceCaseDetailSkeleton() {
  return (
    <div className="flex min-h-0 flex-1 flex-col gap-1 xl:gap-1.5 xl:overflow-hidden">
      <div className="shrink-0">
        <LoadingSkeleton lines={1} />
      </div>
      <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 xl:grid-cols-[minmax(0,55fr)_minmax(0,45fr)] xl:items-stretch xl:gap-3 xl:overflow-hidden">
        <div className="flex min-h-0 flex-col gap-3 xl:min-h-0 xl:overflow-hidden">
          <div className="shrink-0 space-y-1 rounded-xl border border-slate-200/90 bg-white p-3 shadow-sm sm:p-4">
            <LoadingSkeleton lines={2} />
          </div>
          <div className="min-h-[200px] rounded-xl border border-slate-200/90 bg-white p-3 shadow-sm sm:p-4 xl:min-h-0 xl:flex xl:h-full xl:flex-col">
            <LoadingSkeleton lines={8} />
          </div>
        </div>
        <div className="min-h-[200px] rounded-xl border border-slate-200/90 bg-white p-3 shadow-sm sm:p-4 xl:min-h-0 xl:h-full xl:flex xl:flex-col">
          <LoadingSkeleton lines={8} />
        </div>
      </div>
    </div>
  );
}
