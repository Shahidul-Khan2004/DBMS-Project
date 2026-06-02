export const AGENCY_OPS_TABS = [
  { label: "Command Center", href: "/dashboard/agency" },
  { label: "Response Work", href: "/dashboard/agency/response-work" },
  { label: "Units", href: "/dashboard/agency/units" },
  { label: "Field Updates", href: "/dashboard/agency/field-updates" },
] as const;

export function isAgencyOpsTabActive(pathname: string, href: string): boolean {
  if (href === "/dashboard/agency") {
    return pathname === href;
  }
  if (href === "/dashboard/agency/response-work") {
    return (
      pathname === href ||
      pathname.startsWith(`${href}/`) ||
      pathname.startsWith("/dashboard/agency/dispatches") ||
      pathname.startsWith("/dashboard/agency/incidents")
    );
  }
  if (href === "/dashboard/agency/field-updates") {
    return (
      pathname === href ||
      pathname.startsWith(`${href}/`) ||
      pathname.startsWith("/dashboard/agency/response-logs")
    );
  }
  return pathname === href || pathname.startsWith(`${href}/`);
}

export function getAgencyOpsSectionLabel(pathname: string): string {
  if (
    pathname.startsWith("/dashboard/agency/response-work") ||
    pathname.startsWith("/dashboard/agency/dispatches") ||
    pathname.startsWith("/dashboard/agency/incidents")
  ) {
    return "Response Work";
  }
  if (
    pathname.startsWith("/dashboard/agency/field-updates") ||
    pathname.startsWith("/dashboard/agency/response-logs")
  ) {
    return "Field Updates";
  }
  if (pathname.startsWith("/dashboard/agency/units")) {
    return "Units";
  }
  if (pathname === "/dashboard/agency") {
    return "Command Center";
  }
  return "Command Center";
}
