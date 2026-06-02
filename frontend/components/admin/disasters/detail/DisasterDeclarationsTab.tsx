"use client";

import { useState } from "react";
import { CommandSectionCard } from "@/components/dispatcher/incidents/command/CommandSectionCard";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { DeclarationAmendmentModal } from "@/components/admin/disasters/detail/DeclarationAmendmentModal";
import { hasInitialDeclaration } from "@/lib/disaster-operations-format";
import type { DisasterDashboardResponse } from "@/types/disaster-operations";
import { formatBangladeshTime } from "@/lib/datetime";

type DisasterDeclarationsTabProps = {
  disasterPublicUuid: string;
  dashboard: DisasterDashboardResponse;
  isReadOnly: boolean;
  onRefresh: () => Promise<void>;
};

export function DisasterDeclarationsTab({
  disasterPublicUuid,
  dashboard,
  isReadOnly,
  onRefresh,
}: DisasterDeclarationsTabProps) {
  const [amendOpen, setAmendOpen] = useState(false);
  const declarations = dashboard.declarations ?? [];
  const canAmend = hasInitialDeclaration(declarations);

  return (
    <>
      <CommandSectionCard
        title="Declarations"
        headerAction={
          !isReadOnly && canAmend ? (
            <Button type="button" size="sm" onClick={() => setAmendOpen(true)}>
              Issue amendment
            </Button>
          ) : undefined
        }
      >
        {declarations.length === 0 ? (
          <p className="text-sm text-slate-600">No declarations on record.</p>
        ) : (
          <ul className="space-y-3">
            {declarations.map((decl) => (
              <li
                key={decl.public_uuid}
                className="rounded-lg border border-slate-100 px-3 py-2 text-sm"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <p className="font-medium text-slate-900">{decl.title}</p>
                  {decl.declaration_kind ? (
                    <Badge size="compact">
                      {formatBadgeLabel(decl.declaration_kind)}
                    </Badge>
                  ) : null}
                </div>
                {decl.issued_at ? (
                  <p className="mt-0.5 text-xs text-slate-500">
                    Issued {formatBangladeshTime(decl.issued_at)}
                  </p>
                ) : null}
                {decl.public_guidance ? (
                  <p className="mt-2 text-xs text-slate-700">{decl.public_guidance}</p>
                ) : null}
                {decl.legal_reference ? (
                  <p className="mt-1 text-xs text-slate-500">
                    Legal: {decl.legal_reference}
                  </p>
                ) : null}
                {decl.reason ? (
                  <p className="mt-1 text-xs text-slate-500">Reason: {decl.reason}</p>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </CommandSectionCard>

      <DeclarationAmendmentModal
        open={amendOpen}
        disasterPublicUuid={disasterPublicUuid}
        onClose={() => setAmendOpen(false)}
        onSuccess={onRefresh}
      />
    </>
  );
}
