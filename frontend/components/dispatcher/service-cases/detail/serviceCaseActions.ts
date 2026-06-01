import { isServiceCaseFinal } from "@/lib/service-case-status";



export type ServiceCasePrimaryAction =

  | "start_review"

  | "send_response"

  | "send_follow_up"

  | "resolve"

  | "escalate";



export type ServiceCaseOverflowAction =

  | "resume_internal_review"

  | "close"

  | "cancel";



export type ServiceCaseStatusActionTarget =

  | "under_review"

  | "closed"

  | "cancelled";



export function canSendDispatcherCitizenMessage(

  statusCode: string | null | undefined,

): boolean {

  return (

    statusCode === "under_review" || statusCode === "awaiting_user_response"

  );

}



export function getServiceCasePrimaryActions(

  statusCode: string | null | undefined,

): ServiceCasePrimaryAction[] {

  if (!statusCode || isServiceCaseFinal(statusCode)) return [];



  switch (statusCode) {

    case "submitted":

      return ["start_review", "resolve", "escalate"];

    case "under_review":

      return ["resolve", "escalate"];

    case "awaiting_user_response":

      return ["resolve", "escalate"];

    default:

      return [];

  }

}



export function getServiceCaseOverflowActions(

  statusCode: string | null | undefined,

): ServiceCaseOverflowAction[] {

  if (!statusCode || isServiceCaseFinal(statusCode)) return [];



  switch (statusCode) {

    case "submitted":

      return ["cancel"];

    case "under_review":

      return ["close", "cancel"];

    case "awaiting_user_response":

      return ["resume_internal_review", "close", "cancel"];

    default:

      return [];

  }

}



export function primaryActionLabel(action: ServiceCasePrimaryAction): string {

  switch (action) {

    case "start_review":

      return "Start Review";

    case "send_response":

      return "Send Response";

    case "send_follow_up":

      return "Send Follow-up";

    case "resolve":

      return "Resolve Case";

    case "escalate":

      return "Escalate to Emergency";

  }

}



export function overflowActionLabel(action: ServiceCaseOverflowAction): string {

  switch (action) {

    case "resume_internal_review":

      return "Resume Internal Review";

    case "close":

      return "Close Case";

    case "cancel":

      return "Cancel Case";

  }

}



export function primaryActionOpensMessageDialog(

  action: ServiceCasePrimaryAction,

): boolean {

  return action === "send_response" || action === "send_follow_up";

}



export function primaryActionToStatusTarget(

  action: ServiceCasePrimaryAction,

): ServiceCaseStatusActionTarget | null {

  switch (action) {

    case "start_review":

      return "under_review";

    default:

      return null;

  }

}



export function overflowActionToStatusTarget(

  action: ServiceCaseOverflowAction,

): ServiceCaseStatusActionTarget {

  switch (action) {

    case "resume_internal_review":

      return "under_review";

    case "close":

      return "closed";

    case "cancel":

      return "cancelled";

  }

}



export function resumeInternalReviewDialogCopy(): {

  title: string;

  description: string;

  confirmLabel: string;

} {

  return {

    title: "Resume internal review?",

    description:

      "Use this when work must continue before the citizen responds.",

    confirmLabel: "Resume Internal Review",

  };

}



export function startReviewDialogDescription(): string {

  return "Begin active review of this submitted case.";

}



export function statusActionDialogDescription(

  target: ServiceCaseStatusActionTarget,

): string {

  switch (target) {

    case "under_review":

      return "Move this case back into active review.";

    case "closed":

      return "Close this case without a formal resolution record.";

    case "cancelled":

      return "Cancel this case. This action cannot be undone.";

  }

}


