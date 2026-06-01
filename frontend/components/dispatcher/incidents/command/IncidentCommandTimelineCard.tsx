"use client";

import { CommandPlaceholderAction } from "@/components/dispatcher/incidents/command/CommandPlaceholderAction";
import { CommandSectionCard } from "@/components/dispatcher/incidents/command/CommandSectionCard";
import { formatBangladeshTime } from "@/lib/datetime";
import type { TimelinePreviewItem } from "@/types/incident-command";

const ADD_NOTE_MESSAGE =
  "Operational notes will be available in a later phase.";

export function IncidentCommandTimelineCard({
  items,
  className = "",
}: {
  items: TimelinePreviewItem[];
  className?: string;
}) {
  return (
    <CommandSectionCard
      title="Operational Timeline"
      headerAction={
        <CommandPlaceholderAction
          label="+ Add Note"
          comingSoonMessage={ADD_NOTE_MESSAGE}
        />
      }
      className={className}
      fillHeight
      scrollableBody
    >
      {items.length === 0 ? (
        <p className="text-sm text-slate-600">
          No timeline activity recorded yet.
        </p>
      ) : (
        <ol className="relative space-y-0 border-l border-slate-200 pl-3.5">
          {items.map((item, index) => (
            <li
              key={`${item.eventTime}-${item.eventTitle}-${index}`}
              className="relative pb-4 last:pb-0"
            >
              <span
                className="absolute -left-[1.15rem] top-1 h-2 w-2 rounded-full border-2 border-white bg-slate-400 ring-1 ring-slate-200"
                aria-hidden
              />
              <p className="text-sm font-semibold text-slate-900">
                {item.eventTitle}
              </p>
              <p className="mt-0.5 text-xs text-slate-600">
                {item.eventTypeLabel}
              </p>
              {item.eventDescription ? (
                <p className="mt-0.5 text-xs leading-5 text-slate-700">
                  {item.eventDescription}
                </p>
              ) : null}
              <p className="mt-0.5 text-xs text-slate-500">
                {formatBangladeshTime(item.eventTime)}
              </p>
            </li>
          ))}
        </ol>
      )}
    </CommandSectionCard>
  );
}
