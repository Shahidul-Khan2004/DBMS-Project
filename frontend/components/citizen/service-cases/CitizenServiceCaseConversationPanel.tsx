"use client";

import { Headphones, RefreshCw, Send } from "lucide-react";
import {
  getCitizenServiceCaseMessageAuthor,
  getCitizenServiceCaseMessageStyles,
  getCitizenServiceCaseMessageSubjectFallback,
  isCitizenSentMessage,
  normalizeCitizenServiceCaseMessage,
} from "@/components/citizen/service-cases/citizenServiceCaseMessageUtils";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import { MessageBanner } from "@/components/ui/StatusState";
import { formatBangladeshTime } from "@/lib/datetime";
import type { ServiceCaseMessageResult } from "@/types/service-case";

type CitizenServiceCaseConversationPanelProps = {
  messages: ServiceCaseMessageResult[];
  messagesLoading: boolean;
  messagesError: string | null;
  canReply: boolean;
  isTerminal: boolean;
  isEscalated: boolean;
  onRefresh: () => void;
  onSendMessage: () => void;
};

export function CitizenServiceCaseConversationPanel({
  messages,
  messagesLoading,
  messagesError,
  canReply,
  isTerminal,
  isEscalated,
  onRefresh,
  onSendMessage,
}: CitizenServiceCaseConversationPanelProps) {
  return (
    <div className="flex h-full min-h-[320px] flex-col overflow-hidden rounded-2xl border border-slate-200/80 bg-white shadow-sm xl:min-h-0">
      <div className="shrink-0 border-b border-slate-200/80 px-4 py-3">
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <h2 className="text-sm font-semibold text-slate-900">Conversation</h2>
            <p className="mt-0.5 text-xs text-slate-600">
              Messages between you and the operations team.
            </p>
          </div>
          <div className="flex shrink-0 flex-wrap items-center justify-end gap-2">
            <Button
              type="button"
              variant="secondary"
              size="sm"
              onClick={onRefresh}
              disabled={messagesLoading}
            >
              <RefreshCw className="h-4 w-4" aria-hidden />
              Refresh
            </Button>
            {canReply ? (
              <Button type="button" size="sm" onClick={onSendMessage}>
                <Send className="h-4 w-4" aria-hidden />
                Send Message
              </Button>
            ) : null}
          </div>
        </div>
        {!canReply ? (
          <MessageBanner tone="info" className="mt-2">
            {isEscalated
              ? "This service case has been escalated to an emergency response and cannot receive new replies."
              : isTerminal
                ? "This service case is final and cannot receive new replies."
                : "Replies are not available for this service case status."}
          </MessageBanner>
        ) : null}
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto overscroll-y-contain px-4 py-3">
        {messagesLoading ? (
          <LoadingSkeleton lines={4} />
        ) : messagesError ? (
          <ErrorAlert message={messagesError} />
        ) : messages.length === 0 ? (
          <div className="rounded-xl border border-dashed border-[#002D62]/15 bg-[#F8FBFF] px-4 py-5 text-center">
            <p className="text-sm font-semibold text-[#002D62]">No messages yet</p>
            <p className="mt-1 text-sm text-[#42547A]">
              Case messages from you and the operations team will appear here.
            </p>
          </div>
        ) : (
          <ul className="space-y-3">
            {messages.map((message) => {
              const parsed = normalizeCitizenServiceCaseMessage(message);
              const fromCitizen = isCitizenSentMessage(message);
              const styles = getCitizenServiceCaseMessageStyles(message);
              const subjectFallback = getCitizenServiceCaseMessageSubjectFallback(
                message.message_type,
              );

              const avatar = fromCitizen ? (
                <div
                  className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-full text-sm font-bold ${styles.avatar}`}
                  aria-hidden
                >
                  You
                </div>
              ) : (
                <div
                  className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-full ${styles.avatar}`}
                  aria-hidden
                >
                  <Headphones className="h-5 w-5" />
                </div>
              );

              return (
                <li key={message.id} className={`flex gap-2 ${styles.row}`}>
                  {styles.avatarPosition === "left" ? avatar : null}
                  <div
                    className={`max-w-[min(78%,36rem)] rounded-2xl px-4 py-3 ${styles.bubble}`}
                  >
                    <p className="text-sm font-bold text-[#002D62]">
                      {getCitizenServiceCaseMessageAuthor(message)}
                    </p>
                    {parsed.subject && parsed.subject !== subjectFallback ? (
                      <p className="mt-1 text-sm font-semibold text-gray-900">
                        {parsed.subject}
                      </p>
                    ) : null}
                    <p className="mt-1 whitespace-pre-wrap text-sm leading-6 text-gray-700">
                      {parsed.body || "No additional message body."}
                    </p>
                    <p className="mt-2 text-xs text-[#60739A]">
                      {formatBangladeshTime(message.created_at)}
                    </p>
                  </div>
                  {styles.avatarPosition === "right" ? avatar : null}
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </div>
  );
}
