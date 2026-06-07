export const DISPATCHER_OPS_TABS = [
  { label: "Command Center", href: "/dashboard/dispatcher" },
  { label: "Triage Queue", href: "/dashboard/dispatcher/intake-reports" },
  { label: "Active Incidents", href: "/dashboard/dispatcher/incidents" },
  { label: "Service Cases", href: "/dashboard/dispatcher/service-cases" },
  { label: "Archive", href: "/dashboard/dispatcher/archive" },
] as const;

export function isDispatcherOpsTabActive(pathname: string, href: string): boolean {
  if (href === "/dashboard/dispatcher") {
    return pathname === href;
  }
  return pathname === href || pathname.startsWith(`${href}/`);
}

export function isGateway999Route(pathname: string): boolean {
  return pathname.startsWith("/dashboard/dispatcher/gateway-999");
}

export function isDispatcherNationalDisasterRoute(pathname: string): boolean {
  return pathname.startsWith("/dashboard/dispatcher/disasters");
}

export function isDispatcherNationalDisasterDetailRoute(pathname: string): boolean {
  return (
    pathname.startsWith("/dashboard/dispatcher/disasters/") &&
    pathname !== "/dashboard/dispatcher/disasters"
  );
}

export function getDispatcherOpsSectionLabel(pathname: string): string {
  if (isGateway999Route(pathname)) {
    return "Start 999 Intake";
  }
  if (isDispatcherNationalDisasterDetailRoute(pathname)) {
    if (pathname.endsWith("/link-reports")) {
      return "Link Reports";
    }
    return "Disaster Command";
  }
  if (isDispatcherNationalDisasterRoute(pathname)) {
    return "National Disaster";
  }
  if (pathname.startsWith("/dashboard/dispatcher/intake-reports")) {
    return "Triage Queue";
  }
  if (pathname.startsWith("/dashboard/dispatcher/incidents")) {
    return "Active Incidents";
  }
  if (pathname.startsWith("/dashboard/dispatcher/service-cases")) {
    return "Service Cases";
  }
  if (pathname.startsWith("/dashboard/dispatcher/archive")) {
    return "Archive";
  }
  if (pathname === "/dashboard/dispatcher") {
    return "Command Center";
  }
  return "Command Center";
}
