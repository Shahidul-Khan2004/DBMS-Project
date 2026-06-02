"use client";

import { useMemo } from "react";
import { CommandSectionCard } from "@/components/dispatcher/incidents/command/CommandSectionCard";
import { ServiceCaseCorrespondenceEntry } from "@/components/dispatcher/service-cases/detail/ServiceCaseCorrespondenceEntry";
import { canSendDispatcherCitizenMessage } from "@/components/dispatcher/service-cases/detail/serviceCaseActions";
import { sortServiceCaseMessagesNewestFirst } from "@/components/dispatcher/service-cases/detail/sortServiceCaseMessages";
import { Button } from "@/components/ui/Button";
import { isServiceCaseFinal } from "@/lib/service-case-status";
import type { ServiceCaseMessageResult } from "@/types/service-case";

type ServiceCaseCommunicationPanelProps = {
  className?: string;
  messages: ServiceCaseMessageResult[];
  statusCode: string | null | undefined;
  onSendResponse: () => void;
};

export function ServiceCaseCommunicationPanel({
  className = "",
  messages,
  statusCode,
  onSendResponse,
}: ServiceCaseCommunicationPanelProps) {
  const terminal = isServiceCaseFinal(statusCode);
  const isSubmitted = statusCode === "submitted";
  const isAwaitingUserResponse = statusCode === "awaiting_user_response";
  const canSendMessage = canSendDispatcherCitizenMessage(statusCode);
  const sendActionLabel = isAwaitingUserResponse
    ? "Send Follow-up"
    : "Send Response";

  const displayMessages = useMemo(
    () => sortServiceCaseMessagesNewestFirst(messages),
    [messages],
  );

  const awaitingStrip =
    !terminal && isAwaitingUserResponse ? (
      <div
        className="min-w-0 break-words rounded-md border border-[#006747]/15 bg-[#006747]/[0.04] px-3 py-2"
        role="status"
      >
        <p className="flex min-w-0 flex-wrap items-baseline gap-x-2 gap-y-0.5 text-xs leading-5">
          <span className="shrink-0 font-medium text-slate-800">
            Waiting for citizen response
          </span>
          <span className="hidden text-slate-300 sm:inline" aria-hidden>
            ·
          </span>
          <span className="min-w-0 text-slate-600">
            An official response has been sent. This case returns to Under Review
            when the citizen replies.
          </span>
        </p>
      </div>
    ) : null;

  const showSubmittedEmptyGuidance =
    !terminal && isSubmitted && displayMessages.length === 0;

  const showEmptyMessagesCopy =
    !terminal &&
    !isSubmitted &&
    displayMessages.length === 0;

  return (
    <CommandSectionCard
      title="Citizen Communication"
      fillHeight
      className={`min-h-0 flex-1 xl:h-full xl:overflow-hidden !p-3 sm:!p-4 ${className}`.trim()}
      bodyClassName="mt-2 flex min-h-0 flex-1 flex-col overflow-hidden"
      belowHeader={awaitingStrip}
      headerAction={
        canSendMessage ? (
          <Button type="button" variant="secondary" size="sm" onClick={onSendResponse}>
            {sendActionLabel}
          </Button>
        ) : null
      }
    >
      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        <div className="min-h-0 min-w-0 flex-1 xl:overflow-y-auto xl:overscroll-y-contain">
          {terminal ? (
            <p className="text-sm text-slate-600">
              This case is complete and no longer accepts new responses.
            </p>
          ) : null}

          {showSubmittedEmptyGuidance ? (
            <p className="text-sm text-slate-600" role="status">
              Start review to send an official response.
            </p>
          ) : null}

          {showEmptyMessagesCopy ? (
            <p className="text-sm text-slate-600">No messages in this case yet.</p>
          ) : null}

          {displayMessages.length > 0 ? (
            <ul className="relative min-w-0 space-y-1 border-l border-slate-200/80 pl-2.5">
              {displayMessages.map((message) => (
                <ServiceCaseCorrespondenceEntry key={message.id} message={message} />
              ))}
            </ul>
          ) : terminal && displayMessages.length === 0 ? (
            <p className="text-sm text-slate-600">No messages in this case yet.</p>
          ) : null}
        </div>
      </div>
    </CommandSectionCard>
  );
}
