import type { ServiceCaseMessageResult } from "@/types/service-case";

export function isCitizenSentMessage(message: ServiceCaseMessageResult) {
  return message.message_type === "user_message";
}

export function getCitizenServiceCaseMessageAuthor(
  message: ServiceCaseMessageResult,
) {
  if (message.message_type === "admin_reply") return "Dispatcher";
  if (message.message_type === "user_message") return "You";
  if (message.message_type === "system_note") return "System";
  return "System";
}

export function getCitizenServiceCaseMessageSubjectFallback(
  messageType: string | null | undefined,
) {
  if (messageType === "admin_reply") return "Dispatcher message";
  if (messageType === "user_message") return "Your message";
  if (messageType === "system_note") return "System update";
  return "Message";
}

export function normalizeCitizenServiceCaseMessage(message: ServiceCaseMessageResult) {
  if (message.subject !== undefined || message.body !== undefined) {
    const subject = message.subject?.trim();
    const body = message.body?.trim();

    return {
      subject: subject || getCitizenServiceCaseMessageSubjectFallback(message.message_type),
      body: body || null,
    };
  }

  const rawBody = message.message_body?.trim();
  if (!rawBody) {
    return {
      subject: "Message",
      body: null,
    };
  }

  const [subjectLine, ...rest] = rawBody.split(/\r?\n\r?\n/);
  const subject = subjectLine.replace(/^Subject:\s*/i, "").trim();
  return {
    subject: subject || "Message",
    body: rest.join("\n\n").trim() || null,
  };
}

export function getCitizenServiceCaseMessageStyles(message: ServiceCaseMessageResult) {
  if (isCitizenSentMessage(message)) {
    return {
      row: "justify-end",
      bubble: "bg-[#EFF6FF]",
      avatar: "bg-[#0B3FE8] text-white",
      avatarPosition: "right" as const,
    };
  }

  return {
    row: "justify-start",
    bubble: "border border-slate-200/80 bg-white",
    avatar: "bg-[#0B3FE8] text-white",
    avatarPosition: "left" as const,
  };
}
