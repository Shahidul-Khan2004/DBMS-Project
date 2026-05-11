import type { ReactNode } from "react";

const STATUS_STYLES: Record<string, string> = {
  received: "bg-blue-100 text-blue-800",
  under_review: "bg-yellow-100 text-yellow-800",
  linked_to_case: "bg-indigo-100 text-indigo-800",
  linked_to_incident: "bg-red-100 text-red-800",
  reported: "bg-red-100 text-red-800",
  classified: "bg-yellow-100 text-yellow-800",
  in_progress: "bg-blue-100 text-blue-800",
  resolved: "bg-green-100 text-green-800",
  closed: "bg-gray-100 text-gray-800",
  cancelled: "bg-gray-100 text-gray-800",
  low: "bg-green-100 text-green-800",
  medium: "bg-yellow-100 text-yellow-800",
  high: "bg-orange-100 text-orange-800",
  critical: "bg-red-100 text-red-800",
  emergency: "bg-red-100 text-red-800",
  non_emergency: "bg-green-100 text-green-800",
  unknown: "bg-yellow-100 text-yellow-800",
};

export function formatBadgeLabel(value: string | null | undefined) {
  return value ? value.replace(/_/g, " ") : "-";
}

export function Badge({
  children,
  tone,
}: {
  children: ReactNode;
  tone?: string | null;
}) {
  const style = tone ? STATUS_STYLES[tone] : undefined;

  return (
    <span
      className={`inline-flex rounded-full px-2.5 py-1 text-xs font-medium capitalize ${
        style ?? "bg-gray-100 text-gray-800"
      }`}
    >
      {children}
    </span>
  );
}
