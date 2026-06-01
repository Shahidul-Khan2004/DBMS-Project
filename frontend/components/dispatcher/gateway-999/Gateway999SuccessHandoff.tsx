"use client";

import { BadgeCheck } from "lucide-react";
import type { Gateway999Handoff } from "@/components/dispatcher/gateway-999/types";
import { Button } from "@/components/ui/Button";

type Gateway999SuccessHandoffProps = {
  handoff: Gateway999Handoff;
  onOpenDetail: () => void;
  onStartAnother: () => void;
};

function getPrimaryLabel(kind: Gateway999Handoff["kind"]): string {
  if (kind === "service_case") return "Open Service Case";
  return "Open Incident Command";
}

export function Gateway999SuccessHandoff({
  handoff,
  onOpenDetail,
  onStartAnother,
}: Gateway999SuccessHandoffProps) {
  const canOpenDetail = Boolean(handoff.detailHref);

  return (
    <div className="space-y-4">
      <div className="flex items-start gap-3">
        <span className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200">
          <BadgeCheck className="h-5 w-5" aria-hidden />
        </span>
        <div className="min-w-0">
          <h2 className="text-base font-semibold text-slate-900">{handoff.message}</h2>
          <p className="mt-1 text-sm text-slate-600">{handoff.summary}</p>
        </div>
      </div>

      <section className="rounded-lg border border-slate-100 bg-slate-50/60 p-3 text-sm">
        <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
          {handoff.routeLabel}
        </p>
        {handoff.intakeReportCode ? (
          <p className="mt-1 text-xs text-slate-600">
            Intake report:{" "}
            <span className="font-mono font-medium text-slate-900">
              {handoff.intakeReportCode}
            </span>
          </p>
        ) : null}
        {handoff.entityCode ? (
          <p className="mt-1 font-mono text-sm font-medium text-slate-900">
            {handoff.entityCode}
          </p>
        ) : null}
        {handoff.entityTitle ? (
          <p className="mt-1 font-medium text-slate-900">{handoff.entityTitle}</p>
        ) : null}
      </section>

      {handoff.missingUuidMessage ? (
        <p className="text-sm text-amber-800">{handoff.missingUuidMessage}</p>
      ) : null}

      <div className="flex flex-wrap gap-2">
        <Button
          type="button"
          variant="primary"
          size="sm"
          onClick={onOpenDetail}
          disabled={!canOpenDetail}
        >
          {getPrimaryLabel(handoff.kind)}
        </Button>
        <Button type="button" variant="secondary" size="sm" onClick={onStartAnother}>
          Start Another 999 Intake
        </Button>
      </div>
    </div>
  );
}
