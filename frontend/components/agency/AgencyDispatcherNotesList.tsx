"use client";

import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/StatusState";
import { AgencySkeletonBlock } from "@/components/agency/AgencySkeletonBlock";
import { formatReadableLabel } from "@/lib/agency-dispatch-utils";
import { formatRelativeAge } from "@/lib/format-relative-age";
import type { AgencyNote } from "@/types/agency";

export function AgencyDispatcherNotesList({
  notes,
  loading,
}: {
  notes: AgencyNote[];
  loading: boolean;
}) {
  if (loading) {
    return (
      <div className="space-y-3" aria-busy="true">
        <AgencySkeletonBlock className="h-14 w-full" />
        <AgencySkeletonBlock className="h-14 w-full" />
      </div>
    );
  }

  if (notes.length === 0) {
    return (
      <EmptyState
        title="No dispatcher notes"
        description="Dispatcher notes for this incident will appear here."
      />
    );
  }

  return (
    <div className="space-y-3">
      <p className="text-xs text-slate-500">Notes shared by dispatchers for this incident.</p>
      <ul className="space-y-2">
        {notes.map((note) => (
          <li
            key={note.id}
            className="rounded-lg border border-slate-200/90 bg-white px-3 py-2.5"
          >
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone="neutral">{formatReadableLabel(note.event_type)}</Badge>
              <span className="text-xs text-slate-500">
                {formatRelativeAge(note.event_time)}
              </span>
            </div>
            <p className="mt-1 text-sm font-medium text-slate-900">{note.event_title}</p>
            {note.event_description ? (
              <p className="mt-1 text-sm text-slate-700">{note.event_description}</p>
            ) : null}
          </li>
        ))}
      </ul>
    </div>
  );
}
