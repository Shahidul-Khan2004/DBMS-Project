"use client";

import {
  getServiceCaseCorrespondenceStyles,
  getServiceCaseMessageBody,
  getServiceCaseMessageRoleLabel,
} from "@/components/dispatcher/service-cases/detail/serviceCaseMessageUtils";
import { formatBangladeshTime } from "@/lib/datetime";
import type { ServiceCaseMessageResult } from "@/types/service-case";

type ServiceCaseCorrespondenceEntryProps = {
  message: ServiceCaseMessageResult;
};

export function ServiceCaseCorrespondenceEntry({
  message,
}: ServiceCaseCorrespondenceEntryProps) {
  const styles = getServiceCaseCorrespondenceStyles(message);
  const body = getServiceCaseMessageBody(message);
  const subject = message.subject?.trim() || "Message";
  const senderName = message.sender?.full_name?.trim();

  return (
    <li
      className={`min-w-0 rounded-md border px-2.5 py-1.5 ${styles.entry}`}
    >
      <div className="flex min-w-0 items-center justify-between gap-2">
        <span
          className={`inline-flex shrink-0 items-center rounded px-1.5 py-0 text-[10px] font-medium ring-1 ${styles.badge}`}
        >
          {getServiceCaseMessageRoleLabel(message)}
        </span>
        {message.created_at ? (
          <time
            className="shrink-0 text-[11px] tabular-nums text-slate-500"
            dateTime={message.created_at}
          >
            {formatBangladeshTime(message.created_at)}
          </time>
        ) : null}
      </div>

      <p className="mt-0.5 min-w-0 break-words text-sm font-medium text-slate-900">
        {subject}
      </p>

      {senderName ? (
        <p className="mt-0.5 text-[11px] text-slate-500">{senderName}</p>
      ) : null}

      {message.is_internal ? (
        <span className="mt-0.5 inline-flex rounded-full bg-amber-50 px-1.5 py-0 text-[10px] font-semibold text-amber-800">
          Internal
        </span>
      ) : null}

      {body ? (
        <p
          className={`mt-0.5 line-clamp-3 min-w-0 break-words whitespace-pre-wrap text-xs leading-5 ${styles.body}`}
        >
          {body}
        </p>
      ) : null}
    </li>
  );
}
