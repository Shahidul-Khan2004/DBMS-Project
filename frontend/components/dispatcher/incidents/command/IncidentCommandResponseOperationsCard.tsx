"use client";

import { useEffect, useRef, useState } from "react";
import { CommandSectionCard } from "@/components/dispatcher/incidents/command/CommandSectionCard";
import { ResponseTimingTabBody } from "@/components/dispatcher/incidents/command/ResponseTimingTabBody";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { formatBangladeshTime, formatBangladeshTimeOfDay } from "@/lib/datetime";
import type {
  DispatchStatusAction,
  IncidentDispatch,
  ParticipatingAgency,
} from "@/types/incident-command";

type ResponseOperationsTab = "agencies" | "dispatches" | "timing";

type DispatchBoardAction = {
  label: string;
  targetStatus: DispatchStatusAction;
  variant?: "primary" | "danger";
};

function getDefaultTab(agencies: ParticipatingAgency[]): ResponseOperationsTab {
  if (agencies.length === 0) {
    return "agencies";
  }
  return "dispatches";
}

function agencyKey(agency: ParticipatingAgency) {
  return agency.agencyPublicUuid || `${agency.agencyName}-${agency.joinedAt}`;
}

function dispatchRowKey(dispatch: IncidentDispatch) {
  return (
    dispatch.publicUuid || `${dispatch.unitCode}-${dispatch.assignedAt ?? "unknown"}`
  );
}

const TERMINAL_DISPATCH_STATUSES = new Set(["completed", "cancelled"]);

function isTerminalDispatchStatus(status: string): boolean {
  return TERMINAL_DISPATCH_STATUSES.has(status);
}

function sortDispatchesForDisplay(
  dispatches: IncidentDispatch[],
): IncidentDispatch[] {
  return [...dispatches].sort(
    (a, b) =>
      Number(isTerminalDispatchStatus(a.dispatchStatus)) -
      Number(isTerminalDispatchStatus(b.dispatchStatus)),
  );
}

function getDispatchActions(
  dispatchStatus: string,
  incidentIsTerminal: boolean,
): DispatchBoardAction[] {
  if (incidentIsTerminal) {
    return [];
  }

  switch (dispatchStatus) {
    case "assigned":
      return [
        { label: "Mark Dispatched", targetStatus: "dispatched" },
        {
          label: "Cancel Dispatch",
          targetStatus: "cancelled",
          variant: "danger",
        },
      ];
    case "dispatched":
      return [
        { label: "Mark Arrived", targetStatus: "arrived" },
        {
          label: "Cancel Dispatch",
          targetStatus: "cancelled",
          variant: "danger",
        },
      ];
    case "arrived":
      return [
        { label: "Mark Completed", targetStatus: "completed" },
        {
          label: "Cancel Dispatch",
          targetStatus: "cancelled",
          variant: "danger",
        },
      ];
    default:
      return [];
  }
}

function tabButtonClass(isActive: boolean) {
  return `inline-flex items-center gap-1 rounded-lg px-2.5 py-1.5 text-xs font-semibold transition-colors ${
    isActive
      ? "bg-[#E8F2FF] text-[#002D62]"
      : "text-slate-600 hover:bg-slate-100 hover:text-slate-900"
  }`;
}

function ParticipatingAgencyRow({ agency }: { agency: ParticipatingAgency }) {
  return (
    <li className="py-2.5 first:pt-0 last:pb-0">
      <div className="flex items-start justify-between gap-3">
        <p className="min-w-0 flex-1 text-sm font-semibold text-slate-900">
          {agency.agencyName}
        </p>
        <div className="flex shrink-0 flex-wrap items-center justify-end gap-1.5">
          {agency.isLeadAgency ? (
            <span className="inline-flex shrink-0 rounded-full bg-[#002D62]/10 px-2 py-0.5 text-[11px] font-semibold text-[#002D62]">
              Lead Agency
            </span>
          ) : null}
          <Badge tone={agency.participationStatus}>
            {agency.participationStatusLabel}
          </Badge>
        </div>
      </div>
      <p className="mt-0.5 text-xs text-slate-500">
        {agency.agencyTypeLabel}
        <span className="text-slate-400"> · </span>
        Joined {formatBangladeshTime(agency.joinedAt)}
      </p>
    </li>
  );
}

function ParticipatingAgenciesTabBody({
  agencies,
}: {
  agencies: ParticipatingAgency[];
}) {
  if (agencies.length === 0) {
    return (
      <div className="space-y-1">
        <p className="text-sm text-slate-600">
          No participating agencies assigned yet.
        </p>
        <p className="text-sm text-slate-500">
          Assign an agency to begin coordinating response resources.
        </p>
      </div>
    );
  }

  return (
    <ul className="divide-y divide-slate-200">
      {agencies.map((agency) => (
        <ParticipatingAgencyRow key={agencyKey(agency)} agency={agency} />
      ))}
    </ul>
  );
}

function getLatestProgressMilestone(dispatch: IncidentDispatch): {
  label: string;
  at: string;
} | null {
  if (dispatch.completedAt?.trim()) {
    return { label: "Completed", at: dispatch.completedAt };
  }
  if (dispatch.cancelledAt?.trim()) {
    return { label: "Cancelled", at: dispatch.cancelledAt };
  }
  if (dispatch.arrivedAt?.trim()) {
    return { label: "Arrived", at: dispatch.arrivedAt };
  }
  if (dispatch.dispatchedAt?.trim()) {
    return { label: "Dispatched", at: dispatch.dispatchedAt };
  }
  return null;
}

function DispatchRow({
  dispatch,
  incidentIsTerminal,
  onStatusAction,
  openMenuKey,
  onToggleMenu,
  showGroupDivider = false,
}: {
  dispatch: IncidentDispatch;
  incidentIsTerminal: boolean;
  onStatusAction: (
    dispatch: IncidentDispatch,
    targetStatus: DispatchStatusAction,
  ) => void;
  openMenuKey: string | null;
  onToggleMenu: (key: string) => void;
  showGroupDivider?: boolean;
}) {
  const rowKey = dispatchRowKey(dispatch);
  const isMenuOpen = openMenuKey === rowKey;
  const actions = getDispatchActions(
    dispatch.dispatchStatus,
    incidentIsTerminal,
  );
  const latestMilestone = getLatestProgressMilestone(dispatch);

  const timingParts: string[] = [];
  if (dispatch.assignedAt?.trim()) {
    timingParts.push(
      `Assigned ${formatBangladeshTimeOfDay(dispatch.assignedAt)}`,
    );
  }
  if (latestMilestone) {
    timingParts.push(
      `${latestMilestone.label} ${formatBangladeshTimeOfDay(latestMilestone.at)}`,
    );
  }
  const timingLine = timingParts.join(" · ");

  return (
    <li
      className={`py-2.5 first:pt-0 last:pb-0${showGroupDivider ? " border-t border-slate-200" : ""}`}
    >
      <div className="flex items-start justify-between gap-3">
        <p className="min-w-0 flex-1 text-sm font-semibold text-slate-900">
          {dispatch.unitName}
        </p>
        <div className="flex shrink-0 flex-wrap items-center justify-end gap-1.5">
          <Badge tone={dispatch.priorityLevel}>
            {dispatch.priorityLevelLabel}
          </Badge>
          <Badge tone={dispatch.dispatchStatus}>
            {dispatch.dispatchStatusLabel}
          </Badge>
          {actions.length > 0 ? (
            <div className="relative shrink-0">
              <button
                type="button"
                className="inline-flex h-7 w-7 items-center justify-center rounded-md text-sm text-slate-500 transition-colors hover:bg-slate-100 hover:text-slate-700"
                aria-label={`More actions for ${dispatch.unitName}`}
                aria-expanded={isMenuOpen}
                onClick={() => onToggleMenu(rowKey)}
              >
                ⋯
              </button>
              {isMenuOpen ? (
                <div className="absolute right-0 z-10 mt-1 w-44 rounded-lg border border-slate-200 bg-white p-1 shadow-lg">
                  {actions.map((action) => (
                    <button
                      key={action.label}
                      type="button"
                      className={
                        action.variant === "danger"
                          ? "block w-full rounded-md px-2 py-1.5 text-left text-xs text-[#991B1B] transition-colors hover:bg-[#FEF2F2]"
                          : "block w-full rounded-md px-2 py-1.5 text-left text-xs text-slate-700 transition-colors hover:bg-slate-100"
                      }
                      onClick={() => {
                        onStatusAction(dispatch, action.targetStatus);
                        onToggleMenu(rowKey);
                      }}
                    >
                      {action.label}
                    </button>
                  ))}
                </div>
              ) : null}
            </div>
          ) : null}
        </div>
      </div>
      <p className="mt-0.5 text-xs text-slate-600">
        {dispatch.unitCode} · {dispatch.unitTypeLabel} ·{" "}
        {dispatch.owningAgencyName}
      </p>
      {timingLine ? (
        <p className="mt-1 text-xs text-slate-500">{timingLine}</p>
      ) : null}
    </li>
  );
}

function UnitDispatchesTabBody({
  agencies,
  dispatches,
  incidentIsTerminal,
  onDispatchStatusAction,
  openMenuKey,
  onToggleMenu,
}: {
  agencies: ParticipatingAgency[];
  dispatches: IncidentDispatch[];
  incidentIsTerminal: boolean;
  onDispatchStatusAction: (
    dispatch: IncidentDispatch,
    targetStatus: DispatchStatusAction,
  ) => void;
  openMenuKey: string | null;
  onToggleMenu: (key: string) => void;
}) {
  if (agencies.length === 0) {
    return (
      <div className="space-y-1">
        <p className="text-sm text-slate-600">No units can be dispatched yet.</p>
        <p className="text-sm text-slate-500">
          Assign a participating agency before dispatching units.
        </p>
      </div>
    );
  }

  if (dispatches.length === 0) {
    return (
      <div className="space-y-1">
        <p className="text-sm text-slate-600">
          No units dispatched for this incident yet.
        </p>
        <p className="text-sm text-slate-500">
          Select an available unit from a participating agency to begin response
          deployment.
        </p>
      </div>
    );
  }

  const displayDispatches = sortDispatchesForDisplay(dispatches);

  return (
    <ul className="divide-y divide-slate-200">
      {displayDispatches.map((dispatch, index) => {
        const showGroupDivider =
          index > 0 &&
          isTerminalDispatchStatus(dispatch.dispatchStatus) &&
          !isTerminalDispatchStatus(
            displayDispatches[index - 1]!.dispatchStatus,
          );

        return (
          <DispatchRow
            key={dispatchRowKey(dispatch)}
            dispatch={dispatch}
            incidentIsTerminal={incidentIsTerminal}
            onStatusAction={onDispatchStatusAction}
            openMenuKey={openMenuKey}
            onToggleMenu={onToggleMenu}
            showGroupDivider={showGroupDivider}
          />
        );
      })}
    </ul>
  );
}

export function IncidentCommandResponseOperationsCard({
  incidentPublicUuid,
  agencies,
  dispatches,
  canAssignAgency,
  assignAgencyDisabledReason,
  canDispatchUnits,
  dispatchDisabledReason,
  incidentIsTerminal,
  opsMutationGeneration,
  onAssignAgency,
  onDispatchUnit,
  onDispatchStatusAction,
  className = "",
}: {
  incidentPublicUuid: string;
  agencies: ParticipatingAgency[];
  dispatches: IncidentDispatch[];
  canAssignAgency: boolean;
  assignAgencyDisabledReason?: string;
  canDispatchUnits: boolean;
  dispatchDisabledReason?: string;
  incidentIsTerminal: boolean;
  opsMutationGeneration: number;
  onAssignAgency: () => void;
  onDispatchUnit: () => void;
  onDispatchStatusAction: (
    dispatch: IncidentDispatch,
    targetStatus: DispatchStatusAction,
  ) => void;
  className?: string;
}) {
  const assignAgencyDisabled = !canAssignAgency;
  const dispatchDisabled = !canDispatchUnits;
  const [activeTab, setActiveTab] = useState<ResponseOperationsTab>(() =>
    getDefaultTab(agencies),
  );
  const [openMenuKey, setOpenMenuKey] = useState<string | null>(null);
  const prevAgencyCountRef = useRef(agencies.length);

  useEffect(() => {
    const prev = prevAgencyCountRef.current;
    if (agencies.length > prev) {
      setActiveTab("dispatches");
    } else if (agencies.length === 0) {
      setActiveTab("agencies");
    }
    prevAgencyCountRef.current = agencies.length;
  }, [agencies.length]);

  const agenciesTabLabel = `Participating Agencies ${agencies.length}`;
  const dispatchesTabLabel = `Unit Dispatches ${dispatches.length}`;

  function handleTabChange(tab: ResponseOperationsTab) {
    setActiveTab(tab);
    setOpenMenuKey(null);
  }

  function handleToggleMenu(key: string) {
    setOpenMenuKey((current) => (current === key ? null : key));
  }

  return (
    <CommandSectionCard
      title="Response Operations"
      subtitle="Coordinate agencies and deployed response units."
      headerAction={
        <div className="flex flex-wrap items-center gap-2">
          <Button
            type="button"
            variant="secondary"
            size="sm"
            disabled={assignAgencyDisabled}
            title={
              assignAgencyDisabled ? assignAgencyDisabledReason : undefined
            }
            onClick={assignAgencyDisabled ? undefined : onAssignAgency}
          >
            + Assign Agency
          </Button>
          <Button
            type="button"
            variant="secondary"
            size="sm"
            disabled={dispatchDisabled}
            title={dispatchDisabled ? dispatchDisabledReason : undefined}
            onClick={dispatchDisabled ? undefined : onDispatchUnit}
          >
            + Dispatch Unit
          </Button>
        </div>
      }
      className={className}
      fillHeight
      bodyClassName="flex min-h-0 flex-1 flex-col"
    >
      <div className="flex min-h-0 flex-1 flex-col">
        <div className="mb-3 flex shrink-0 flex-wrap items-center gap-2 border-b border-slate-200 pb-2">
          <button
            type="button"
            className={tabButtonClass(activeTab === "agencies")}
            onClick={() => handleTabChange("agencies")}
            aria-pressed={activeTab === "agencies"}
          >
            <span>Participating Agencies</span>
            <span className="rounded-full bg-slate-100 px-1.5 py-0.5 text-[11px] leading-none text-slate-700">
              {agencies.length}
            </span>
            <span className="sr-only">{agenciesTabLabel}</span>
          </button>
          <button
            type="button"
            className={tabButtonClass(activeTab === "dispatches")}
            onClick={() => handleTabChange("dispatches")}
            aria-pressed={activeTab === "dispatches"}
          >
            <span>Unit Dispatches</span>
            <span className="rounded-full bg-slate-100 px-1.5 py-0.5 text-[11px] leading-none text-slate-700">
              {dispatches.length}
            </span>
            <span className="sr-only">{dispatchesTabLabel}</span>
          </button>
          <button
            type="button"
            className={tabButtonClass(activeTab === "timing")}
            onClick={() => handleTabChange("timing")}
            aria-pressed={activeTab === "timing"}
          >
            <span>Response Timing</span>
          </button>
        </div>

        {activeTab === "agencies" ? (
          <div className="min-h-0 flex-1 overflow-y-auto overscroll-y-contain pr-0.5">
            <ParticipatingAgenciesTabBody agencies={agencies} />
          </div>
        ) : activeTab === "dispatches" ? (
          <div className="min-h-0 flex-1 overflow-y-auto overscroll-y-contain pr-0.5">
            <UnitDispatchesTabBody
              agencies={agencies}
              dispatches={dispatches}
              incidentIsTerminal={incidentIsTerminal}
              onDispatchStatusAction={onDispatchStatusAction}
              openMenuKey={openMenuKey}
              onToggleMenu={handleToggleMenu}
            />
          </div>
        ) : (
          <div className="min-h-0 flex-1 overflow-y-auto overscroll-y-contain pr-0.5">
            <ResponseTimingTabBody
              incidentPublicUuid={incidentPublicUuid}
              isActive={activeTab === "timing"}
              opsMutationGeneration={opsMutationGeneration}
            />
          </div>
        )}
      </div>
    </CommandSectionCard>
  );
}
