import { getIntakeColumnCountClasses } from "@/components/dispatcher/intake/intakeStatusStyles";
import { getServiceCaseColumnCountClasses } from "@/components/dispatcher/service-cases/priorityStyles";

export type CommandCenterColumn = "triage" | "incidents" | "service_cases";

const INCIDENTS_COLUMN_COUNT_CLASSES =
  "bg-[#EFF6FF] text-[#002D62] ring-1 ring-[#002D62]/15";

export function getCommandCenterColumnCountClasses(
  column: CommandCenterColumn,
): string {
  switch (column) {
    case "triage":
      return getIntakeColumnCountClasses();
    case "incidents":
      return INCIDENTS_COLUMN_COUNT_CLASSES;
    case "service_cases":
      return getServiceCaseColumnCountClasses();
    default:
      return INCIDENTS_COLUMN_COUNT_CLASSES;
  }
}
