import type { LucideIcon } from "lucide-react";
import { AlertTriangle, BarChart3, Building2, Shield } from "lucide-react";

export type WorkflowAvailability = "available" | "coming_later";

export type AdminWorkflowArea = {
  id: string;
  title: string;
  description: string;
  icon: LucideIcon;
  availability: WorkflowAvailability;
  href?: string;
  primaryActionLabel: string;
  secondaryActionLabel?: string;
};

export const ADMIN_WORKFLOW_AREAS: readonly AdminWorkflowArea[] = [
  {
    id: "platform-access",
    title: "Platform Access",
    description:
      "Grant supported platform roles and manage access responsibilities.",
    icon: Shield,
    availability: "available",
    href: "/dashboard/admin/role-assignment",
    primaryActionLabel: "Open Role Assignment",
  },
  {
    id: "agency-network",
    title: "Agency Network",
    description:
      "Manage agencies, activation status, onboarding, and representatives.",
    icon: Building2,
    availability: "available",
    href: "/dashboard/admin/agencies",
    primaryActionLabel: "Manage Agencies",
    secondaryActionLabel: "Onboard / Representatives",
  },
  {
    id: "reports-oversight",
    title: "Reports & Oversight",
    description:
      "Review workload, response timing, and administrative insights.",
    icon: BarChart3,
    availability: "available",
    href: "/dashboard/admin/reports",
    primaryActionLabel: "Open Reports",
  },
  {
    id: "disaster-protocol",
    title: "Disaster Protocol",
    description:
      "Future disaster events, affected areas, shelters, relief, and facilities.",
    icon: AlertTriangle,
    availability: "coming_later",
    primaryActionLabel: "Unavailable",
  },
];
