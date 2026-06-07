import { RequiredMarker } from "@/components/dispatcher/FieldLabel";
import type { RouteMode } from "@/components/dispatcher/triage/types";

type RouteChoice = Extract<
  RouteMode,
  "service_case" | "emergency_incident" | "existing_incident"
>;

const ROUTE_BUTTONS: { mode: RouteChoice; label: string }[] = [
  { mode: "service_case", label: "Service Case" },
  { mode: "emergency_incident", label: "New Emergency Incident" },
  { mode: "existing_incident", label: "Existing Incident" },
];

function routeModeToChoice(mode: RouteMode): RouteChoice | null {
  if (
    mode === "service_case" ||
    mode === "emergency_incident" ||
    mode === "existing_incident"
  ) {
    return mode;
  }
  if (mode === "success_service_case") return "service_case";
  if (mode === "success_emergency_incident") return "emergency_incident";
  if (mode === "success_existing_incident") return "existing_incident";
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
}: RouteSelectorProps) {
  const activeChoice = routeModeToChoice(routeMode);

  return (
    <section>
      <h4 className="text-sm font-semibold text-slate-900">
        {title}
        {required ? <RequiredMarker /> : null}
      </h4>
      <p className="mt-0.5 text-xs text-slate-600">{subtitle}</p>
      <div className="mt-1.5 flex flex-wrap gap-1.5">
        {ROUTE_BUTTONS.map((button) => {
          const isActive = activeChoice === button.mode;
          return (
            <button
              key={button.mode}
              type="button"
              disabled={disabled}
              onClick={() => onSelect(button.mode)}
              className={`rounded-lg border px-2.5 py-1 text-sm font-medium transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#002D62] disabled:cursor-not-allowed disabled:opacity-60 ${
                isActive
                  ? "border-[#002D62] bg-[#002D62] text-white shadow-sm"
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
