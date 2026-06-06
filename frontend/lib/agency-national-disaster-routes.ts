export const AGENCY_NATIONAL_DISASTER_BASE = "/dashboard/agency/national-disaster";

export function agencyNationalDisasterLandingPath(): string {
  return AGENCY_NATIONAL_DISASTER_BASE;
}

export function agencyNationalDisasterDetailPath(disasterPublicUuid: string): string {
  return `${AGENCY_NATIONAL_DISASTER_BASE}/${encodeURIComponent(disasterPublicUuid)}`;
}

export function isAgencyNationalDisasterRoute(pathname: string): boolean {
  return pathname.startsWith(AGENCY_NATIONAL_DISASTER_BASE);
}
