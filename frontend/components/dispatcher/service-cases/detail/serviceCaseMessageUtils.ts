import { formatBadgeLabel } from "@/components/ui/Badge";
import type { ServiceCaseMessageResult } from "@/types/service-case";

export function getServiceCaseMessageRoleLabel(
  message: ServiceCaseMessageResult,
): string {
  if (message.message_type === "admin_reply") return "Dispatcher";
  if (message.message_type === "user_message") return "Citizen";
  if (message.message_type === "system_note") return "System Note";
  return formatBadgeLabel(message.message_type);
}

export function isDispatcherMessage(message: ServiceCaseMessageResult) {
  return message.message_type === "admin_reply";
}

export function getServiceCaseMessageBody(
  message: ServiceCaseMessageResult,
): string | null {
  const body = message.body?.trim();
  return body || null;
}

export function getServiceCaseCorrespondenceStyles(
  message: ServiceCaseMessageResult,
): { entry: string; badge: string; body: string } {
  if (message.message_type === "admin_reply") {
    return {
      entry: "border-[#002D62]/12 bg-[#E8F2FF]/25",
      badge: "bg-[#E8F2FF] text-[#002D62] ring-[#002D62]/15",
      body: "text-slate-600",
    };
  }
  if (message.message_type === "system_note") {
    return {
      entry: "border-slate-200/60 bg-slate-50/90",
      badge: "bg-slate-100 text-slate-600 ring-slate-200/80",
      body: "text-slate-500",
    };
  }
  return {
    entry: "border-slate-200/80 bg-white",
    badge: "bg-slate-50 text-slate-700 ring-slate-200/80",
    body: "text-slate-600",
  };
}
