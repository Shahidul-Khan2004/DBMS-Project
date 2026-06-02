import { isNationalDisasterRoute } from "@/lib/admin-national-disaster-routes";

export const ADMIN_OPS_TABS = [
  { label: "Command Center", href: "/dashboard/admin" },
  { label: "Agencies", href: "/dashboard/admin/agencies" },
  { label: "Role Assignment", href: "/dashboard/admin/role-assignment" },
  { label: "Reports", href: "/dashboard/admin/reports" },
  {
    label: "Dispatcher Oversight",
    href: "/dashboard/admin/dispatcher-oversight",
  },
] as const;

export { isNationalDisasterRoute };

export function isAdminOpsTabActive(pathname: string, href: string): boolean {
  if (href === "/dashboard/admin") {
    return pathname === href;
  }
  return pathname === href || pathname.startsWith(`${href}/`);
}

export function getAdminOpsSectionLabel(pathname: string): string {
  if (isNationalDisasterRoute(pathname)) {
    return "National Disaster";
  }
  if (pathname.startsWith("/dashboard/admin/agencies")) {
    return "Agencies";
  }
  if (pathname.startsWith("/dashboard/admin/role-assignment")) {
    return "Role Assignment";
  }
  if (pathname.startsWith("/dashboard/admin/reports")) {
    return "Reports";
  }
  if (pathname.startsWith("/dashboard/admin/dispatcher-oversight")) {
    return "Dispatcher Oversight";
  }
  if (pathname === "/dashboard/admin") {
    return "Command Center";
  }
  return "Command Center";
}
