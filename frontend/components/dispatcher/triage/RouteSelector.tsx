import { RequiredMarker } from "@/components/dispatcher/FieldLabel";
import type { RouteMode } from "@/components/dispatcher/triage/types";
import type { RouteChoice } from "@/components/dispatcher/triage/triageReviewRouteUtils";

const PRIMARY_ROUTE_BUTTONS: {
  mode: Extract<
    RouteChoice,
    "service_case" | "emergency_incident" | "existing_incident"
  >;
  label: string;
}[] = [
  { mode: "service_case", label: "Service Case" },
  { mode: "emergency_incident", label: "New Emergency Incident" },
  { mode: "existing_incident", label: "Existing Incident" },
];

const DISMISS_ROUTE_BUTTONS: {
  mode: Extract<RouteChoice, "duplicate" | "false_report">;
  label: string;
}[] = [
  { mode: "duplicate", label: "Duplicate" },
  { mode: "false_report", label: "False Report" },
];

function routeModeToChoice(mode: RouteMode): RouteChoice | null {
  if (
    mode === "service_case" ||
    mode === "emergency_incident" ||
    mode === "existing_incident" ||
    mode === "duplicate" ||
    mode === "false_report"
  ) {
    return mode;
  }
  if (mode === "success_service_case") return "service_case";
  if (mode === "success_emergency_incident") return "emergency_incident";
  if (mode === "success_existing_incident") return "existing_incident";
  if (mode === "success_duplicate") return "duplicate";
  if (mode === "success_false_report") return "false_report";
  return null;
}

interface RouteSelectorProps {
  routeMode: RouteMode;
  onSelect: (mode: RouteChoice) => void;
  disabled?: boolean;
  title?: string;
  subtitle?: string;
  required?: boolean;
  showDisasterRoute?: boolean;
  onOpenDisasterDialog?: () => void;
  disasterRouteDisabled?: boolean;
  showDismissRoutes?: boolean;
}

export function RouteSelector({
  routeMode,
  onSelect,
  disabled = false,
  title = "Route Report",
  subtitle = "Choose the appropriate routing decision.",
  required = false,
  showDisasterRoute = false,
  onOpenDisasterDialog,
  disasterRouteDisabled = false,
  showDismissRoutes = false,
}: RouteSelectorProps) {
  const activeChoice = routeModeToChoice(routeMode);
  const routeButtons = showDismissRoutes
    ? [...PRIMARY_ROUTE_BUTTONS, ...DISMISS_ROUTE_BUTTONS]
    : PRIMARY_ROUTE_BUTTONS;

  return (
    <section>
      <h4 className="text-sm font-semibold text-slate-900">
        {title}
        {required ? <RequiredMarker /> : null}
      </h4>
      <p className="mt-0.5 text-xs text-slate-600">{subtitle}</p>
      <div className="mt-1.5 flex flex-wrap gap-1.5">
        {routeButtons.map((button) => {
          const isActive = activeChoice === button.mode;
          const isDismissRoute =
            button.mode === "duplicate" || button.mode === "false_report";
          return (
            <button
              key={button.mode}
              type="button"
              disabled={disabled}
              onClick={() => onSelect(button.mode)}
              className={`rounded-lg border px-2.5 py-1 text-sm font-medium transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#002D62] disabled:cursor-not-allowed disabled:opacity-60 ${
                isActive
                  ? isDismissRoute
                    ? "border-slate-600 bg-slate-600 text-white shadow-sm"
                    : "border-[#002D62] bg-[#002D62] text-white shadow-sm"
                  : isDismissRoute
                    ? "border-slate-200 bg-white text-slate-600 hover:border-slate-400 hover:bg-slate-50"
                    : "border-slate-200 bg-white text-slate-700 hover:border-[#002D62]/30 hover:bg-[#EFF6FF]/60"
              }`}
            >
              {button.label}
            </button>
          );
        })}
        {showDisasterRoute && onOpenDisasterDialog ? (
          <button
            type="button"
            disabled={disabled || disasterRouteDisabled}
            onClick={onOpenDisasterDialog}
            className="rounded-lg border border-[#006747] bg-white px-2.5 py-1 text-sm font-medium text-[#006747] transition-colors hover:border-[#00543A] hover:bg-[#F0F7F4] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#006747] disabled:cursor-not-allowed disabled:opacity-60"
          >
            Add to National Disaster
          </button>
        ) : null}
      </div>
      {showDisasterRoute && onOpenDisasterDialog ? (
        <p className="mt-1.5 text-xs text-slate-600">
          Route this report through an emergency incident and attach it to an
          active disaster protocol.
        </p>
      ) : null}
    </section>
  );
}
