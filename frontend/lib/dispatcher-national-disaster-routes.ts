export const DISPATCHER_NATIONAL_DISASTER_BASE = "/dashboard/dispatcher/disasters";

export function dispatcherNationalDisasterLandingPath(): string {
  return DISPATCHER_NATIONAL_DISASTER_BASE;
}

/** Overview mode: /dashboard/dispatcher/disasters/[uuid] */
export function dispatcherNationalDisasterOverviewPath(
  disasterPublicUuid: string,
): string {
  return `${DISPATCHER_NATIONAL_DISASTER_BASE}/${encodeURIComponent(disasterPublicUuid)}`;
}

/** @deprecated Use dispatcherNationalDisasterOverviewPath */
export function dispatcherNationalDisasterDetailPath(
  disasterPublicUuid: string,
): string {
  return dispatcherNationalDisasterOverviewPath(disasterPublicUuid);
}

/** Link Reports mode: /dashboard/dispatcher/disasters/[uuid]/link-reports */
export function dispatcherNationalDisasterLinkReportsPath(
  disasterPublicUuid: string,
): string {
  return `${dispatcherNationalDisasterOverviewPath(disasterPublicUuid)}/link-reports`;
}

export function isDispatcherNationalDisasterRoute(pathname: string): boolean {
  return pathname.startsWith(DISPATCHER_NATIONAL_DISASTER_BASE);
}

export function isDispatcherNationalDisasterDetailRoute(pathname: string): boolean {
  return (
    pathname.startsWith(`${DISPATCHER_NATIONAL_DISASTER_BASE}/`) &&
    pathname !== DISPATCHER_NATIONAL_DISASTER_BASE
  );
}

export function isDispatcherNationalDisasterLinkReportsRoute(
  pathname: string,
): boolean {
  return pathname.endsWith("/link-reports");
}

export type DisasterCommandMode = "overview" | "link-reports";

export function getDisasterCommandModeFromPathname(
  pathname: string,
): DisasterCommandMode {
  return isDispatcherNationalDisasterLinkReportsRoute(pathname)
    ? "link-reports"
    : "overview";
}
