export const NATIONAL_DISASTER_BASE = "/dashboard/admin/national-disaster";

export function nationalDisasterLandingPath(): string {
  return NATIONAL_DISASTER_BASE;
}

export function nationalDisasterFacilitiesPath(): string {
  return `${NATIONAL_DISASTER_BASE}/facilities`;
}

export function nationalDisasterFacilityDetailPath(
  facilityPublicUuid: string,
): string {
  return `${NATIONAL_DISASTER_BASE}/facilities/${encodeURIComponent(facilityPublicUuid)}`;
}

export function nationalDisasterDeclarePath(): string {
  return `${NATIONAL_DISASTER_BASE}/disasters/new`;
}

export function nationalDisasterDetailPath(disasterPublicUuid: string): string {
  return `${NATIONAL_DISASTER_BASE}/disasters/${encodeURIComponent(disasterPublicUuid)}`;
}

export function isNationalDisasterRoute(pathname: string): boolean {
  return pathname.startsWith(NATIONAL_DISASTER_BASE);
}

export function isNationalDisasterLandingRoute(pathname: string): boolean {
  if (!pathname.startsWith(NATIONAL_DISASTER_BASE)) return false;
  if (pathname.startsWith(`${NATIONAL_DISASTER_BASE}/facilities`)) return false;
  return true;
}

export function isNationalDisasterFacilitiesRoute(pathname: string): boolean {
  return pathname.startsWith(`${NATIONAL_DISASTER_BASE}/facilities`);
}
