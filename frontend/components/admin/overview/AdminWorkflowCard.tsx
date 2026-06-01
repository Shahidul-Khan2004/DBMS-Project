"use client";

import Link from "next/link";
import type { LucideIcon } from "lucide-react";
import { ArrowRight } from "lucide-react";
import type { AdminWorkflowArea } from "@/components/admin/overview/adminWorkflowRoutes";
import { Badge } from "@/components/ui/Badge";
import {
  getDispatcherClickableCardRowClasses,
  getDispatcherSelectableRowClasses,
} from "@/components/dispatcher/listRowHoverStyles";

const CARD_LAYOUT =
  "flex flex-col rounded-xl border p-5 shadow-sm lg:min-h-[180px] lg:max-h-[190px] lg:p-5";

type AdminWorkflowCardProps = {
  area: AdminWorkflowArea;
};

function WorkflowCardIcon({ icon: Icon }: { icon: LucideIcon }) {
  return (
    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-[#E8F2FF] text-[#002D62]">
      <Icon className="h-5 w-5" aria-hidden />
    </div>
  );
}

function WorkflowCardHeader({
  icon,
  availability,
}: {
  icon: LucideIcon;
  availability: AdminWorkflowArea["availability"];
}) {
  return (
    <div className="flex items-start justify-between gap-3">
      <WorkflowCardIcon icon={icon} />
      <Badge
        tone={availability === "available" ? "active" : "inactive"}
        size="compact"
      >
        {availability === "available" ? "Available" : "Coming Later"}
      </Badge>
    </div>
  );
}

function WorkflowCardBody({
  title,
  description,
}: {
  title: string;
  description: string;
}) {
  return (
    <>
      <h4 className="mt-2 text-base font-semibold text-slate-900">{title}</h4>
      <p className="mt-1 line-clamp-2 text-sm leading-snug text-slate-600">
        {description}
      </p>
    </>
  );
}

function AvailableWorkflowFooter({
  primaryActionLabel,
  secondaryActionLabel,
}: {
  primaryActionLabel: string;
  secondaryActionLabel?: string;
}) {
  return (
    <div className="mt-2 flex flex-col gap-0.5">
      <span className="inline-flex items-center gap-1.5 text-sm font-semibold text-[#002D62]">
        {primaryActionLabel}
        <ArrowRight
          className="h-4 w-4 transition-transform group-hover:translate-x-0.5"
          aria-hidden
        />
      </span>
      {secondaryActionLabel ? (
        <span className="text-xs font-medium text-slate-500">
          {secondaryActionLabel}
        </span>
      ) : null}
    </div>
  );
}

function DisabledWorkflowFooter({ label }: { label: string }) {
  return (
    <p className="mt-2 text-sm font-medium text-slate-500">{label}</p>
  );
}

export function AdminWorkflowCard({ area }: AdminWorkflowCardProps) {
  const {
    title,
    description,
    icon,
    availability,
    href,
    primaryActionLabel,
    secondaryActionLabel,
  } = area;

  if (availability === "coming_later") {
    return (
      <article
        aria-disabled="true"
        className={`${CARD_LAYOUT} ${getDispatcherSelectableRowClasses({ disabled: true, variant: "card" })}`}
      >
        <WorkflowCardHeader icon={icon} availability={availability} />
        <WorkflowCardBody title={title} description={description} />
        <DisabledWorkflowFooter label={primaryActionLabel} />
      </article>
    );
  }

  if (!href) {
    return null;
  }

  return (
    <Link
      href={href}
      className={`group ${CARD_LAYOUT} focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#002D62] ${getDispatcherClickableCardRowClasses()}`}
    >
      <WorkflowCardHeader icon={icon} availability={availability} />
      <WorkflowCardBody title={title} description={description} />
      <AvailableWorkflowFooter
        primaryActionLabel={primaryActionLabel}
        secondaryActionLabel={secondaryActionLabel}
      />
    </Link>
  );
}
