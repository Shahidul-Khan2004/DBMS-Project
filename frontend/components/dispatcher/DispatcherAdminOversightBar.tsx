"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { Badge } from "@/components/ui/Badge";
import { isSystemAdminOversight } from "@/lib/dispatcher-access";
import { getAuthSession } from "@/lib/auth-store";

export function DispatcherAdminOversightBar() {
  const [showOversight, setShowOversight] = useState(false);

  useEffect(() => {
    const { userRole } = getAuthSession();
    queueMicrotask(() => setShowOversight(isSystemAdminOversight(userRole)));
  }, []);

  if (!showOversight) {
    return null;
  }

  return (
    <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-b border-slate-200/80 bg-[#EFF6FF]/90 px-4 py-2 backdrop-blur-sm sm:px-6 lg:px-8">
      <Link
        href="/dashboard/admin"
        className="text-sm font-medium text-[#006747] transition hover:text-[#002D62] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#006747]/30 focus-visible:ring-offset-1"
      >
        ← Back to System Admin Console
      </Link>
      <Badge tone="active">Admin Oversight</Badge>
    </div>
  );
}
