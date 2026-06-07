import type { LucideIcon } from "lucide-react";
import {
  AlertTriangle,
  ClipboardCheck,
  FileText,
  LayoutGrid,
  MapPin,
} from "lucide-react";

export type CitizenNavItem = {
  href: string;
  label: string;
  icon: LucideIcon;
};

export const CITIZEN_NAV_ITEMS: CitizenNavItem[] = [
  { href: "/dashboard/citizen", label: "Dashboard", icon: LayoutGrid },
  { href: "/dashboard/citizen/reports", label: "My Reports", icon: FileText },
  {
    href: "/dashboard/citizen/service-cases",
    label: "Service Cases",
    icon: ClipboardCheck,
  },
  {
    href: "/dashboard/citizen/incidents",
    label: "My Incidents",
    icon: AlertTriangle,
  },
  { href: "/dashboard/citizen/locations", label: "Locations", icon: MapPin },
];

export function isCitizenNavItemActive(pathname: string, href: string): boolean {
  if (href === "/dashboard/citizen") {
    return pathname === href;
  }
  return pathname === href || pathname.startsWith(`${href}/`);
}

export function getCitizenNavSectionLabel(pathname: string): string {
  if (pathname.startsWith("/dashboard/citizen/reports")) {
    return "My Reports";
  }
  if (pathname.startsWith("/dashboard/citizen/service-cases")) {
    return "Service Cases";
  }
  if (pathname.startsWith("/dashboard/citizen/incidents")) {
    return "My Incidents";
  }
  if (pathname.startsWith("/dashboard/citizen/locations")) {
    return "Locations";
  }
  if (pathname === "/dashboard/citizen/report-new") {
    return "Report New Incident";
  }
  if (pathname === "/dashboard/profile") {
    return "Profile";
  }
  if (pathname === "/dashboard/notifications") {
    return "Notifications";
  }
  if (pathname === "/dashboard/citizen") {
    return "Dashboard";
  }
  return "Citizen Portal";
}
