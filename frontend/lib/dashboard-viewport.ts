/** Flex child class for ops dashboards locked to the viewport on desktop. */
export const OPS_DASHBOARD_CONTENT_CLASS = "flex min-h-0 flex-1 flex-col";

export function isOpsDashboardRoute(pathname: string): boolean {
  return (
    pathname.startsWith("/dashboard/dispatcher") ||
    pathname.startsWith("/dashboard/admin") ||
    pathname.startsWith("/dashboard/agency")
  );
}
