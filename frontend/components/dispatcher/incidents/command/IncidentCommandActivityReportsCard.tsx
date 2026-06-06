"use client";



import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type FormEvent,
} from "react";
import { toast } from "sonner";

import { getDispatcherClickableInsetRowClasses } from "@/components/dispatcher/listRowHoverStyles";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { AddDispatcherNoteDialog } from "@/components/dispatcher/incidents/command/AddDispatcherNoteDialog";

import { LinkReportToIncidentDialog } from "@/components/dispatcher/incidents/command/LinkReportToIncidentDialog";

import { CommandSectionCard } from "@/components/dispatcher/incidents/command/CommandSectionCard";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";

import { Badge } from "@/components/ui/Badge";

import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";

import {

  formatBangladeshTime,

  formatBangladeshTimeOfDay,

} from "@/lib/datetime";

import { sortNewestFirst } from "@/lib/sort";
import { getAuthz } from "@/lib/auth-store";
import { mapUnlinkReportFromIncidentError } from "@/lib/incident-command-api-errors";
import { unlinkIntakeReportFromIncident } from "@/lib/operations-incident-api";

import type {

  IncidentActivityTimelineItem,

  LinkedIntakeReport,

  TimelinePreviewItem,

} from "@/types/incident-command";



type ActivityTab = "timeline" | "linkedReports" | "dispatcherNotes";



function getDefaultTab(

  timelineItems: IncidentActivityTimelineItem[],

  reports: LinkedIntakeReport[],

): ActivityTab {

  if (timelineItems.length > 0) {

    return "timeline";

  }

  if (reports.length > 0) {

    return "linkedReports";

  }

  return "timeline";

}



function reportRowKey(report: LinkedIntakeReport) {

  return `${report.intakeReportCode}-${report.linkedAt}-${report.linkType}`;

}



function noteRowKey(note: TimelinePreviewItem) {

  return `${note.id}-${note.eventTime}`;

}



function canShowUnlinkAction(

  report: LinkedIntakeReport,

  canUnlinkReports: boolean,

  incidentIsTerminal: boolean,

) {

  return (

    canUnlinkReports &&

    !incidentIsTerminal &&

    report.linkType !== "primary_report"

  );

}



function ActivityTimelineRow({

  item,

  isLast,

}: {

  item: IncidentActivityTimelineItem;

  isLast: boolean;

}) {

  const showBadge = Boolean(item.badgeLabel?.trim());



  return (

    <li className="grid grid-cols-[16px_minmax(0,1fr)] gap-x-2 pb-2.5 last:pb-0">

      <div className="relative flex justify-center">

        <span

          aria-hidden

          className={

            isLast

              ? "absolute left-1/2 top-0 h-[0.5rem] w-px -translate-x-1/2 bg-slate-200"

              : "absolute bottom-0 left-1/2 top-[0.5rem] w-px -translate-x-1/2 bg-slate-200"

          }

        />

        <span

          aria-hidden

          className="relative z-10 mt-1 h-1.5 w-1.5 shrink-0 rounded-full border border-white bg-slate-400 ring-1 ring-slate-200"

        />

      </div>

      <div className="min-w-0">

        <div className="flex items-start justify-between gap-2">

          <p className="min-w-0 flex-1 text-sm font-medium leading-5 text-slate-900">

            {item.title}

          </p>

          <time

            dateTime={item.occurredAt}

            className="shrink-0 text-xs text-slate-500"

          >

            {formatBangladeshTimeOfDay(item.occurredAt)}

          </time>

        </div>

        {showBadge ? (

          <div className="mt-0.5">

            <Badge tone={item.badgeTone}>{item.badgeLabel}</Badge>

          </div>

        ) : null}

        {item.description ? (

          <p className="mt-0.5 text-xs leading-5 text-slate-600">

            {item.description}

          </p>

        ) : null}

      </div>

    </li>

  );

}



function DispatcherNoteRow({ note }: { note: TimelinePreviewItem }) {

  const showDescription = Boolean(note.eventDescription?.trim());



  return (

    <li className="py-2.5 first:pt-0 last:pb-0">

      <div className="min-w-0">

        <div className="flex flex-wrap items-start justify-between gap-2">

          <p className="min-w-0 flex-1 text-sm font-semibold text-slate-900">

            {note.eventTitle}

          </p>

          <Badge tone="neutral">Dispatcher Note</Badge>

        </div>

        {showDescription ? (

          <p className="mt-1 text-xs leading-5 text-slate-600">

            {note.eventDescription}

          </p>

        ) : null}

        <p className="mt-1 text-xs text-slate-500">

          {formatBangladeshTime(note.eventTime)}

        </p>

      </div>

    </li>

  );

}



export function IncidentCommandActivityReportsCard({

  activityTimeline,

  reports,

  timelinePreview,

  incidentPublicUuid,

  incidentTitle,

  incidentIsTerminal,

  onRefreshDetail,

  onViewReportDetails,

  onReportUnlinked,

  className = "",

}: {

  activityTimeline: IncidentActivityTimelineItem[];

  reports: LinkedIntakeReport[];

  timelinePreview: TimelinePreviewItem[];

  incidentPublicUuid: string;

  incidentTitle: string;

  incidentIsTerminal: boolean;

  onRefreshDetail: () => Promise<void>;

  onViewReportDetails: (report: LinkedIntakeReport) => void;

  onReportUnlinked: (reportPublicUuid: string) => Promise<void>;

  className?: string;

}) {

  const [activeTab, setActiveTab] = useState<ActivityTab>(() =>

    getDefaultTab(activityTimeline, reports),

  );

  const [addNoteOpen, setAddNoteOpen] = useState(false);

  const [linkReportOpen, setLinkReportOpen] = useState(false);

  const [canUnlinkReports, setCanUnlinkReports] = useState(false);

  const [unlinkTarget, setUnlinkTarget] =
    useState<LinkedIntakeReport | null>(null);

  const [unlinkReason, setUnlinkReason] = useState("");

  const [unlinkError, setUnlinkError] = useState<string | null>(null);

  const [unlinkingReportUuid, setUnlinkingReportUuid] = useState<string | null>(
    null,
  );



  useEffect(() => {

    setCanUnlinkReports(

      Boolean(getAuthz()?.permissions?.includes("incident.update_status")),

    );

  }, []);



  useEffect(() => {

    if (!unlinkTarget) return;

    setUnlinkReason("");

    setUnlinkError(null);

  }, [unlinkTarget]);



  const dispatcherNotes = useMemo(

    () =>

      sortNewestFirst(

        timelinePreview.filter((entry) => entry.eventType === "operator_note"),

        (note) => [note.eventTime],

      ),

    [timelinePreview],

  );



  const dispatcherNotesCount = useMemo(

    () =>

      timelinePreview.filter((entry) => entry.eventType === "operator_note")

        .length,

    [timelinePreview],

  );



  const handleNoteAdded = useCallback(async () => {

    await onRefreshDetail();

    setActiveTab("dispatcherNotes");

  }, [onRefreshDetail]);



  const handleReportLinked = useCallback(async () => {

    await onRefreshDetail();

    setActiveTab("linkedReports");

  }, [onRefreshDetail]);



  const closeUnlinkDialog = useCallback(() => {

    if (unlinkingReportUuid) return;

    setUnlinkTarget(null);

    setUnlinkReason("");

    setUnlinkError(null);

  }, [unlinkingReportUuid]);



  const handleUnlinkReport = useCallback(

    async (event: FormEvent<HTMLFormElement>) => {

      event.preventDefault();

      if (!unlinkTarget || unlinkingReportUuid) return;

      const trimmedReason = unlinkReason.trim();

      if (!trimmedReason) {

        setUnlinkError("Reason is required.");

        return;

      }

      setUnlinkingReportUuid(unlinkTarget.intakePublicUuid);

      setUnlinkError(null);

      try {

        await unlinkIntakeReportFromIncident(

          incidentPublicUuid,

          unlinkTarget.intakePublicUuid,

          { reason: trimmedReason },

        );

        toast.success("Report link removed.");

        setUnlinkTarget(null);

        setUnlinkReason("");

        await onReportUnlinked(unlinkTarget.intakePublicUuid);

      } catch (err) {

        setUnlinkError(mapUnlinkReportFromIncidentError(err));

      } finally {

        setUnlinkingReportUuid(null);

      }

    },

    [

      incidentPublicUuid,

      onReportUnlinked,

      unlinkReason,

      unlinkTarget,

      unlinkingReportUuid,

    ],

  );



  const linkedReportUuids = useMemo(

    () => reports.map((report) => report.intakePublicUuid).filter(Boolean),

    [reports],

  );



  const linkedReportsTabLabel = `Linked Reports ${reports.length}`;

  const timelineTabLabel = `Timeline ${activityTimeline.length}`;

  const dispatcherNotesTabLabel = `Dispatcher Notes ${dispatcherNotesCount}`;



  return (

    <>

      <CommandSectionCard

        title="Activity & Reports"

        headerAction={

          <div className="flex flex-wrap items-center gap-2">

            <Button

              type="button"

              variant="secondary"

              size="sm"

              onClick={() => setAddNoteOpen(true)}

            >

              + Add Note

            </Button>

            <Button

              type="button"

              variant="secondary"

              size="sm"

              onClick={() => setLinkReportOpen(true)}

            >

              + Link Report

            </Button>

          </div>

        }

        className={className}

        fillHeight

      >

        <div className="flex min-h-0 flex-1 flex-col">

          <div className="mb-3 flex shrink-0 flex-wrap items-center gap-2 border-b border-slate-200 pb-2">

            <button

              type="button"

              className={`inline-flex items-center gap-1 rounded-lg px-2.5 py-1.5 text-xs font-semibold transition-colors ${

                activeTab === "timeline"

                  ? "bg-[#E8F2FF] text-[#002D62]"

                  : "text-slate-600 hover:bg-slate-100 hover:text-slate-900"

              }`}

              onClick={() => setActiveTab("timeline")}

              aria-pressed={activeTab === "timeline"}

            >

              <span>Timeline</span>

              <span className="rounded-full bg-slate-100 px-1.5 py-0.5 text-[11px] leading-none text-slate-700">

                {activityTimeline.length}

              </span>

              <span className="sr-only">{timelineTabLabel}</span>

            </button>

            <button

              type="button"

              className={`inline-flex items-center gap-1 rounded-lg px-2.5 py-1.5 text-xs font-semibold transition-colors ${

                activeTab === "linkedReports"

                  ? "bg-[#E8F2FF] text-[#002D62]"

                  : "text-slate-600 hover:bg-slate-100 hover:text-slate-900"

              }`}

              onClick={() => setActiveTab("linkedReports")}

              aria-pressed={activeTab === "linkedReports"}

            >

              <span>Linked Reports</span>

              <span className="rounded-full bg-slate-100 px-1.5 py-0.5 text-[11px] leading-none text-slate-700">

                {reports.length}

              </span>

              <span className="sr-only">{linkedReportsTabLabel}</span>

            </button>

            <button

              type="button"

              className={`inline-flex items-center gap-1 rounded-lg px-2.5 py-1.5 text-xs font-semibold transition-colors ${

                activeTab === "dispatcherNotes"

                  ? "bg-[#E8F2FF] text-[#002D62]"

                  : "text-slate-600 hover:bg-slate-100 hover:text-slate-900"

              }`}

              onClick={() => setActiveTab("dispatcherNotes")}

              aria-pressed={activeTab === "dispatcherNotes"}

            >

              <span>Dispatcher Notes</span>

              <span className="rounded-full bg-slate-100 px-1.5 py-0.5 text-[11px] leading-none text-slate-700">

                {dispatcherNotesCount}

              </span>

              <span className="sr-only">{dispatcherNotesTabLabel}</span>

            </button>

          </div>



          {activeTab === "timeline" ? (

            <div className="min-h-0 flex-1 overflow-y-auto overscroll-y-contain px-3">

              {activityTimeline.length === 0 ? (

                <p className="text-sm text-slate-600">

                  No timeline activity recorded yet.

                </p>

              ) : (

                <ol className="space-y-0">

                  {activityTimeline.map((item, index) => (

                    <ActivityTimelineRow

                      key={item.key}

                      item={item}

                      isLast={index === activityTimeline.length - 1}

                    />

                  ))}

                </ol>

              )}

            </div>

          ) : activeTab === "linkedReports" ? (

            <div className="min-h-0 flex-1 overflow-y-auto overscroll-y-contain pr-0.5">

              {reports.length === 0 ? (

                <p className="text-sm text-slate-600">

                  No intake reports linked to this incident.

                </p>

              ) : (

                <ul className="divide-y divide-slate-200">

                  {reports.map((report) => {
                    const key = reportRowKey(report);
                    const isUnlinking =
                      unlinkingReportUuid === report.intakePublicUuid;
                    const showUnlink = canShowUnlinkAction(
                      report,
                      canUnlinkReports,
                      incidentIsTerminal,
                    );

                    return (
                      <li
                        key={key}
                        className="flex items-start gap-2 py-2.5 first:pt-0 last:pb-0"
                      >
                        <button
                          type="button"
                          className={`flex min-w-0 flex-1 cursor-pointer items-start gap-3 rounded-lg border border-transparent px-1 py-0 text-left ${getDispatcherClickableInsetRowClasses()} hover:border-[#006747]/20`}
                          aria-label={`View intake report details for ${report.summary}, ${report.intakeReportCode}`}
                          onClick={() => onViewReportDetails(report)}
                        >
                          <div className="min-w-0 flex-1">
                            <p className="truncate text-sm font-semibold text-slate-900">
                              {report.summary}
                            </p>
                            <div className="mt-1 flex flex-wrap items-center gap-2">
                              <Badge tone={report.linkType}>
                                {report.linkTypeLabel}
                              </Badge>
                              <span className="text-xs text-slate-500">
                                {report.intakeReportCode}
                              </span>
                            </div>
                            <p className="mt-1 text-xs text-slate-500">
                              Linked {formatBangladeshTime(report.linkedAt)}
                            </p>
                          </div>
                          <span className="shrink-0 pt-0.5 text-xs text-slate-400">
                            View →
                          </span>
                        </button>
                        {showUnlink ? (
                          <button
                            type="button"
                            className="mt-0.5 inline-flex h-8 shrink-0 items-center justify-center rounded-lg border border-slate-200 bg-white px-2.5 text-xs font-semibold text-slate-600 transition-colors hover:border-[#002D62]/25 hover:bg-[#EFF6FF] hover:text-[#002D62] disabled:cursor-not-allowed disabled:opacity-60"
                            aria-label={`Unlink intake report ${report.intakeReportCode} from this incident`}
                            disabled={Boolean(unlinkingReportUuid)}
                            onClick={() => setUnlinkTarget(report)}
                          >
                            {isUnlinking ? "Unlinking..." : "Unlink"}
                          </button>
                        ) : null}
                      </li>
                    );
                  })}

                </ul>

              )}

            </div>

          ) : (

            <div className="min-h-0 flex-1 overflow-y-auto overscroll-y-contain pr-0.5">

              {dispatcherNotes.length === 0 ? (

                <p className="text-sm text-slate-600">

                  No dispatcher notes recorded yet.

                  <br />

                  Add a note to record an operational observation or decision.

                </p>

              ) : (

                <ul className="divide-y divide-slate-200">

                  {dispatcherNotes.map((note) => (

                    <DispatcherNoteRow key={noteRowKey(note)} note={note} />

                  ))}

                </ul>

              )}

            </div>

          )}

        </div>

      </CommandSectionCard>



      {unlinkTarget ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4">
          <form
            onSubmit={(event) => void handleUnlinkReport(event)}
            className="flex w-full max-w-md flex-col rounded-xl border border-slate-200 bg-white shadow-xl"
          >
            <div className="border-b border-slate-100 px-5 py-4">
              <h2 className="text-lg font-semibold text-slate-900">
                Remove Report Link
              </h2>
              <p className="mt-1 text-sm leading-6 text-slate-600">
                This removes the association between{" "}
                <span className="font-semibold text-slate-800">
                  {unlinkTarget.intakeReportCode}
                </span>{" "}
                and this incident. The report itself will remain in the
                system.
              </p>
            </div>

            <div className="space-y-4 px-5 py-4">
              <div>
                <FieldLabel htmlFor="incident-report-unlink-reason" required>
                  Reason
                </FieldLabel>
                <textarea
                  id="incident-report-unlink-reason"
                  value={unlinkReason}
                  onChange={(event) => {
                    setUnlinkReason(event.target.value);
                    setUnlinkError(null);
                  }}
                  rows={3}
                  maxLength={500}
                  className={triageFieldClassName}
                  disabled={Boolean(unlinkingReportUuid)}
                />
                <p className="mt-1 text-xs text-slate-500">
                  Required for the incident audit trail.
                </p>
              </div>

              {unlinkError ? <ErrorAlert message={unlinkError} /> : null}
            </div>

            <div className="flex justify-end gap-2 border-t border-slate-100 px-5 py-4">
              <Button
                type="button"
                variant="secondary"
                onClick={closeUnlinkDialog}
                disabled={Boolean(unlinkingReportUuid)}
              >
                Cancel
              </Button>
              <Button
                type="submit"
                variant="outline"
                isLoading={Boolean(unlinkingReportUuid)}
                disabled={Boolean(unlinkingReportUuid)}
              >
                {unlinkingReportUuid ? "Unlinking..." : "Remove Link"}
              </Button>
            </div>
          </form>
        </div>
      ) : null}



      <AddDispatcherNoteDialog

        open={addNoteOpen}

        incidentPublicUuid={incidentPublicUuid}

        onClose={() => setAddNoteOpen(false)}

        onSuccess={handleNoteAdded}

      />



      <LinkReportToIncidentDialog

        open={linkReportOpen}

        incidentPublicUuid={incidentPublicUuid}

        incidentTitle={incidentTitle}

        linkedReportUuids={linkedReportUuids}

        onClose={() => setLinkReportOpen(false)}

        onSuccess={handleReportLinked}

      />

    </>

  );

}

