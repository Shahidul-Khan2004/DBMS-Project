"use client";

import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import Image from "next/image";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  AlertTriangle,
  ArrowRight,
  ClipboardCheck,
  FileText,
  MapPin,
  Shield,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import {
  CitizenPageContent,
  ReportIncidentLink,
} from "@/components/citizen/CitizenPortal";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { PageLoading } from "@/components/ui/StatusState";
import { apiGet } from "@/lib/api";
import { clearAuthSession } from "@/lib/auth-store";
import { getMyIncidents } from "@/lib/citizen-incidents-api";
import { formatBangladeshTime } from "@/lib/datetime";
import {
  isActiveIncident,
  isFinalIncident,
  isResolvedIncident,
  mapIncidentsByIntakeUuid,
} from "@/lib/incident-status";
import {
  SERVICE_CASE_OPEN_STATUSES,
  SERVICE_CASE_FINAL_STATUSES,
  isFinalReportOrLinkedResolved,
  isPendingReport,
  mapServiceCasesByIntakeUuid,
} from "@/lib/report-status";
import { LANDING_HERO_OVERLAY_STYLE } from "@/lib/landing-hero-overlay";
import { useAuthGuard } from "@/lib/use-auth-guard";
import type { LoginResponse } from "@/types/auth";
import type { CitizenIncident } from "@/types/citizen-incident";
import type {
  IntakeReport,
  IntakeReportListResponse,
  IntakeReportStats,
  IntakeReportStatsResponse,
} from "@/types/intake";
import type {
  CitizenServiceCase,
  CitizenServiceCaseListResponse,
} from "@/types/service-case";

const EMPTY_STATS: IntakeReportStats = {
  totalReports: 0,
  pendingReports: 0,
  resolvedReports: 0,
};

interface ServiceCaseStats {
  totalServiceCases: number;
  openServiceCases: number;
  resolvedServiceCases: number;
}

const EMPTY_SERVICE_CASE_STATS: ServiceCaseStats = {
  totalServiceCases: 0,
  openServiceCases: 0,
  resolvedServiceCases: 0,
};

interface IncidentStats {
  totalIncidents: number;
  activeIncidents: number;
  resolvedIncidents: number;
  finalIncidents: number;
}

const EMPTY_INCIDENT_STATS: IncidentStats = {
  totalIncidents: 0,
  activeIncidents: 0,
  resolvedIncidents: 0,
  finalIncidents: 0,
};

interface LatestItem {
  primary: string;
  secondary: string;
  occurredAt: string | null;
}

function hasFinalLinkedIncident(
  report: IntakeReport,
  incidentsByIntakeUuid: Map<string, CitizenIncident>,
) {
  if (report.intake_status !== "linked_to_incident") return false;

  const incident = incidentsByIntakeUuid.get(report.public_uuid);
  return incident ? isFinalIncident(incident) : false;
}

function getServiceCaseStats(serviceCases: CitizenServiceCase[]): ServiceCaseStats {
  return serviceCases.reduce<ServiceCaseStats>(
    (nextStats, serviceCase) => {
      const statusCode = serviceCase.status_code;

      nextStats.totalServiceCases += 1;
      if (statusCode === "resolved") {
        nextStats.resolvedServiceCases += 1;
      }
      if (statusCode && SERVICE_CASE_OPEN_STATUSES.has(statusCode)) {
        nextStats.openServiceCases += 1;
      }

      return nextStats;
    },
    { ...EMPTY_SERVICE_CASE_STATS },
  );
}

function getCorrectedReportStats(
  reports: IntakeReport[],
  serviceCases: CitizenServiceCase[],
  incidents: CitizenIncident[],
  backendStats?: IntakeReportStats,
): IntakeReportStats {
  const serviceCasesByIntakeUuid = mapServiceCasesByIntakeUuid(serviceCases);
  const incidentsByIntakeUuid = mapIncidentsByIntakeUuid(incidents);
  const linkedFinalServiceCaseReports = reports.filter((report) => {
    if (report.intake_status !== "linked_to_case") return false;

    const serviceCasesForReport =
      serviceCasesByIntakeUuid.get(report.public_uuid) ?? [];
    return serviceCasesForReport.some((serviceCase) => {
      const statusCode = serviceCase.status_code;
      return statusCode != null && SERVICE_CASE_FINAL_STATUSES.has(statusCode);
    });
  }).length;
  const frontendResolvedReports = reports.filter((report) =>
    isFinalReportOrLinkedResolved(report, serviceCasesByIntakeUuid) ||
    hasFinalLinkedIncident(report, incidentsByIntakeUuid),
  ).length;
  const backendResolvedReports = backendStats?.resolvedReports ?? 0;

  return {
    totalReports: reports.length,
    pendingReports: reports.filter(isPendingReport).length,
    resolvedReports: Math.max(
      frontendResolvedReports,
      backendResolvedReports + linkedFinalServiceCaseReports,
    ),
  };
}

function getReportStatsWithoutLinkedWorkflowData(
  reports: IntakeReport[],
  incidents: CitizenIncident[] = [],
): IntakeReportStats {
  const incidentsByIntakeUuid = mapIncidentsByIntakeUuid(incidents);

  return {
    totalReports: reports.length,
    pendingReports: reports.filter(isPendingReport).length,
    resolvedReports: reports.filter((report) =>
      isFinalReportOrLinkedResolved(report, new Map()) ||
      hasFinalLinkedIncident(report, incidentsByIntakeUuid),
    ).length,
  };
}

function getIncidentStats(incidents: CitizenIncident[]): IncidentStats {
  return {
    totalIncidents: incidents.length,
    activeIncidents: incidents.filter(isActiveIncident).length,
    resolvedIncidents: incidents.filter(isResolvedIncident).length,
    finalIncidents: incidents.filter(isFinalIncident).length,
  };
}

function getTimestamp(value?: string | null) {
  if (!value) return 0;

  const timestamp = new Date(value).getTime();
  return Number.isNaN(timestamp) ? 0 : timestamp;
}

function getLatestReport(reports: IntakeReport[]): LatestItem | null {
  const latest = reports
    .slice()
    .sort((a, b) => getTimestamp(b.created_at) - getTimestamp(a.created_at))[0];

  if (!latest) return null;

  return {
    primary: latest.summary,
    secondary: latest.summary,
    occurredAt: latest.reported_at ?? latest.created_at,
  };
}

function getLatestIncident(incidents: CitizenIncident[]): LatestItem | null {
  const latest = incidents
    .slice()
    .sort(
      (a, b) =>
        getTimestamp(b.last_updated ?? b.created_at) -
        getTimestamp(a.last_updated ?? a.created_at),
    )[0];

  if (!latest) return null;

  return {
    primary: latest.title ?? latest.description ?? "Emergency response",
    secondary: latest.title ?? latest.description ?? "Emergency response",
    occurredAt: latest.last_updated ?? latest.created_at,
  };
}

function getLatestServiceCase(serviceCases: CitizenServiceCase[]): LatestItem | null {
  const latest = serviceCases
    .slice()
    .sort(
      (a, b) =>
        getTimestamp(b.last_updated ?? b.created_at) -
        getTimestamp(a.last_updated ?? a.created_at),
    )[0];

  if (!latest) return null;

  return {
    primary: latest.title,
    secondary: latest.title,
    occurredAt: latest.last_updated ?? latest.created_at,
  };
}

function formatLatestTime(value?: string | null) {
  return formatBangladeshTime(value).replace(/, ([^,]+)$/, " • $1");
}

function getFirstNamePart(value?: string | null) {
  return value?.trim().split(/\s+/).find(Boolean) ?? "";
}

function getEmailPrefix(value?: string | null) {
  const prefix = value?.trim().split("@")[0]?.trim() ?? "";
  return prefix || "";
}

function getCitizenWelcomeName(user: LoginResponse["user"] | null) {
  if (!user) return "";

  return getFirstNamePart(user.full_name) || getEmailPrefix(user.email);
}

function DashboardMetric({
  label,
  value,
  tone = "default",
}: {
  label: string;
  value: number;
  tone?: "default" | "warning" | "success";
}) {
  const toneClass =
    tone === "warning"
      ? "text-amber-700"
      : tone === "success"
      ? "text-[#006747]"
      : "text-[#002D62]";

  return (
    <div className="min-w-0 px-2 py-1 text-center sm:px-4">
      <p className="text-xs font-medium text-[#1F3768] sm:text-sm">{label}</p>
      <p className={`mt-1 text-2xl font-bold leading-none sm:mt-2 sm:text-3xl ${toneClass}`}>
        {value}
      </p>
    </div>
  );
}

function DashboardSummaryCard({
  title,
  description,
  icon: Icon,
  iconClassName,
  items,
  latestItem,
  latestLabel,
  emptyState,
  action,
  error,
}: {
  title: string;
  description: string;
  icon: LucideIcon;
  iconClassName: string;
  items: Array<{ label: string; value: number; tone?: "default" | "warning" | "success" }>;
  latestItem: LatestItem | null;
  latestLabel: string;
  emptyState: string;
  action: ReactNode;
  error?: string;
}) {
  return (
    <div className="flex min-h-[240px] min-w-0 flex-col overflow-hidden rounded-2xl border border-slate-200/80 bg-white p-4 shadow-sm sm:min-h-[260px] sm:p-6">
      <div className="flex items-start gap-4">
        <div
          className={`flex h-12 w-12 shrink-0 items-center justify-center rounded-full ${iconClassName}`}
        >
          <Icon className="h-6 w-6" aria-hidden />
        </div>
        <div className="min-w-0">
          <h2 className="text-lg font-bold text-[#002D62]">{title}</h2>
          <p className="mt-1 text-sm leading-5 text-[#42547A]">{description}</p>
        </div>
      </div>

      {error ? (
        <div className="mt-4">
          <ErrorAlert message={error} />
        </div>
      ) : null}

      <div className="mt-5 border-y border-slate-200 py-4">
        <div className="grid grid-cols-3">
          {items.map((item, index) => (
            <div
              key={item.label}
              className={index > 0 ? "border-l border-slate-200" : ""}
            >
              <DashboardMetric
                label={item.label}
                value={item.value}
                tone={item.tone}
              />
            </div>
          ))}
        </div>
      </div>

      <div className="mt-4 flex flex-1 flex-col">
        <p className="text-sm font-semibold text-[#42547A]">{latestLabel}</p>
        {latestItem ? (
          <div className="mt-2 min-w-0">
            <p className="line-clamp-2 text-base font-bold text-slate-950">
              {latestItem.secondary || latestItem.primary}
            </p>
            {latestItem.occurredAt ? (
              <p className="mt-2 text-sm text-[#42547A]">
                {formatLatestTime(latestItem.occurredAt)}
              </p>
            ) : null}
          </div>
        ) : (
          <p className="mt-2 text-sm leading-6 text-[#42547A]">{emptyState}</p>
        )}
      </div>

      <div className="mt-5">{action}</div>
    </div>
  );
}

function WelcomeCard({ userName }: { userName?: string | null }) {
  const welcomeTitle = userName ? `Welcome, ${userName}` : "Welcome back";

  return (
    <div className="overflow-hidden rounded-2xl border border-slate-200/80 bg-white shadow-sm">
      <div className="relative min-h-[200px] overflow-hidden sm:min-h-[220px] lg:min-h-[240px]">
        <Image
          src="/images/citizen-dashboard-hero-clean.webp"
          alt="Bangladesh disaster response team assisting flood-affected citizens"
          fill
          sizes="(max-width: 1600px) 100vw, 1600px"
          className="object-cover"
          priority
        />
        <div
          className="absolute inset-0 pointer-events-none"
          aria-hidden
          style={LANDING_HERO_OVERLAY_STYLE}
        />
        <div className="relative flex min-h-[200px] items-center px-4 py-6 sm:min-h-[220px] sm:px-8 sm:py-8 lg:min-h-[240px] lg:px-10">
          <div className="w-full max-w-[620px] rounded-2xl border border-white/20 bg-[#002D62]/95 p-6 shadow-xl sm:p-8 lg:p-10">
            <h1
              className="truncate text-2xl font-bold text-white sm:text-3xl"
              title={welcomeTitle}
            >
              {welcomeTitle}
            </h1>
            <p className="mt-3 text-base leading-6 text-white/90">
              Track your reports, emergency incidents, and service cases from one
              place.
            </p>
            <div className="mt-5">
              <ReportIncidentLink className="w-fit" />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

interface RecentActivityItem {
  id: string;
  label: string;
  title: string;
  time: string | null;
  href: string;
}

function buildRecentActivity(
  reports: IntakeReport[],
  incidents: CitizenIncident[],
  serviceCases: CitizenServiceCase[],
): RecentActivityItem[] {
  const items: RecentActivityItem[] = [];

  for (const report of reports.slice(0, 3)) {
    items.push({
      id: `report-${report.public_uuid}`,
      label: "Report",
      title: report.summary,
      time: report.reported_at ?? report.created_at,
      href: `/dashboard/citizen/reports/${report.public_uuid}`,
    });
  }

  for (const incident of incidents.slice(0, 3)) {
    items.push({
      id: `incident-${incident.public_uuid}`,
      label: "Emergency response",
      title: incident.title ?? incident.description ?? "Emergency response update",
      time: incident.last_updated ?? incident.reported_at ?? incident.created_at,
      href: `/dashboard/citizen/incidents/${incident.public_uuid}`,
    });
  }

  for (const serviceCase of serviceCases.slice(0, 3)) {
    items.push({
      id: `case-${serviceCase.public_uuid}`,
      label: "Service case",
      title: serviceCase.title,
      time: serviceCase.last_updated ?? serviceCase.created_at,
      href: `/dashboard/citizen/service-cases/${serviceCase.public_uuid}`,
    });
  }

  return items
    .sort((a, b) => getTimestamp(b.time) - getTimestamp(a.time))
    .slice(0, 6);
}

function RecentActivityPanel({
  items,
  onNavigate,
}: {
  items: RecentActivityItem[];
  onNavigate: (href: string) => void;
}) {
  return (
    <div className="min-w-0 overflow-hidden rounded-2xl border border-slate-200/80 bg-white shadow-sm">
      <div className="border-b border-slate-200/80 px-4 py-4 sm:px-6">
        <h2 className="text-lg font-bold text-[#002D62]">Recent Activity</h2>
        <p className="mt-1 text-sm text-[#42547A]">
          Latest updates across your reports and responses.
        </p>
      </div>
      <div className="max-h-[22rem] overflow-y-auto overscroll-y-contain px-4 py-4 sm:px-6">
        {items.length === 0 ? (
          <p className="text-sm text-[#42547A]">
            Activity from your reports, emergency responses, and service cases
            will appear here.
          </p>
        ) : (
          <ul className="space-y-3">
            {items.map((item) => (
              <li key={item.id}>
                <button
                  type="button"
                  onClick={() => onNavigate(item.href)}
                  className="flex w-full min-w-0 items-start gap-3 rounded-xl border border-slate-200/80 bg-[#F6F9FE] px-4 py-3 text-left transition-colors hover:border-[#002D62]/20 hover:bg-[#EFF6FF]"
                >
                  <div className="min-w-0 flex-1">
                    <p className="text-xs font-semibold uppercase tracking-wide text-[#42547A]">
                      {item.label}
                    </p>
                    <p className="mt-1 line-clamp-2 text-sm font-semibold text-slate-900">
                      {item.title}
                    </p>
                    {item.time ? (
                      <p className="mt-1 text-xs text-[#60739A]">
                        {formatLatestTime(item.time)}
                      </p>
                    ) : null}
                  </div>
                  <ArrowRight
                    className="mt-1 h-4 w-4 shrink-0 text-[#0B3FE8]"
                    aria-hidden
                  />
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function QuickActionsPanel({ onNavigate }: { onNavigate: (href: string) => void }) {
  const actions = [
    {
      label: "Report New Incident",
      href: "/dashboard/citizen/report-new",
      variant: "emergency" as const,
    },
    {
      label: "View My Reports",
      href: "/dashboard/citizen/reports",
      variant: "outline" as const,
    },
    {
      label: "Manage Locations",
      href: "/dashboard/citizen/locations",
      variant: "outline" as const,
    },
    {
      label: "View Safety & National Disaster Guidelines",
      href: "/#national-disaster",
      variant: "outline" as const,
    },
  ];

  return (
    <div className="min-w-0 overflow-hidden rounded-2xl border border-slate-200/80 bg-white shadow-sm">
      <div className="border-b border-slate-200/80 px-4 py-4 sm:px-6">
        <h2 className="text-lg font-bold text-[#002D62]">Quick Actions</h2>
        <p className="mt-1 text-sm text-[#42547A]">
          Common tasks to report, review, and stay prepared.
        </p>
      </div>
      <div className="space-y-3 px-4 py-5 sm:px-6">
        {actions.map((action) => (
          <Button
            key={action.href}
            type="button"
            variant={action.variant}
            className="h-auto min-h-11 w-full items-center justify-between gap-3 px-4 py-2.5 text-left"
            onClick={() => {
              if (action.href.includes("#")) {
                window.location.href = action.href;
                return;
              }
              onNavigate(action.href);
            }}
          >
            <span className="inline-flex min-w-0 flex-1 items-center gap-2">
              {action.href === "/dashboard/citizen/locations" ? (
                <MapPin className="h-4 w-4 shrink-0" aria-hidden />
              ) : action.href === "/#national-disaster" ? (
                <Shield className="h-4 w-4 shrink-0" aria-hidden />
              ) : null}
              <span className="whitespace-normal text-base leading-snug lg:text-sm lg:leading-relaxed">
                {action.label}
              </span>
            </span>
            <ArrowRight className="h-4 w-4 shrink-0 self-center" aria-hidden />
          </Button>
        ))}
      </div>
    </div>
  );
}

export default function CitizenDashboard() {
  const router = useRouter();
  const isChecking = useAuthGuard(["citizen"]);
  const [user, setUser] = useState<LoginResponse["user"] | null>(null);
  const [stats, setStats] = useState<IntakeReportStats>(EMPTY_STATS);
  const [serviceCaseStats, setServiceCaseStats] = useState<ServiceCaseStats>(
    EMPTY_SERVICE_CASE_STATS,
  );
  const [incidentStats, setIncidentStats] =
    useState<IncidentStats>(EMPTY_INCIDENT_STATS);
  const [reports, setReports] = useState<IntakeReport[]>([]);
  const [serviceCases, setServiceCases] = useState<CitizenServiceCase[]>([]);
  const [incidents, setIncidents] = useState<CitizenIncident[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState("");
  const [serviceCaseStatsError, setServiceCaseStatsError] = useState("");
  const [incidentStatsError, setIncidentStatsError] = useState("");

  useEffect(() => {
    if (isChecking) return;

    const loadDashboard = async () => {
      const sessionUser = sessionStorage.getItem("loggedInUser");

      setIsLoading(true);
      setError("");
      setServiceCaseStatsError("");
      setIncidentStatsError("");
      try {
        const parsedUser = sessionUser
          ? (JSON.parse(sessionUser) as LoginResponse["user"])
          : null;
        setUser(parsedUser);

        const [
          reportStatsResult,
          reportsResult,
          serviceCasesResult,
          incidentsResult,
        ] =
          await Promise.allSettled([
            apiGet<IntakeReportStatsResponse>("/intake/reports/my/stats"),
            apiGet<IntakeReportListResponse>("/intake/reports/my"),
            apiGet<CitizenServiceCaseListResponse>(
              "/intake/reports/my/service-cases",
            ),
            getMyIncidents(),
          ]);

        const incidents =
          incidentsResult.status === "fulfilled"
            ? incidentsResult.value.incidents ?? []
            : [];
        const reports =
          reportsResult.status === "fulfilled"
            ? reportsResult.value.reports ?? []
            : [];
        const serviceCases =
          serviceCasesResult.status === "fulfilled"
            ? serviceCasesResult.value.service_cases ?? []
            : [];

        setReports(reports);
        setIncidents(incidents);
        setServiceCases(serviceCases);
        setIncidentStats(getIncidentStats(incidents));
        if (incidentsResult.status === "rejected") {
          setIncidentStatsError(
            incidentsResult.reason instanceof Error
              ? incidentsResult.reason.message
              : "Could not load your emergency incident stats.",
          );
        }

        if (serviceCasesResult.status === "fulfilled") {
          setServiceCaseStats(getServiceCaseStats(serviceCases));

          if (reportsResult.status === "fulfilled") {
            setStats(
              getCorrectedReportStats(
                reports,
                serviceCases,
                incidents,
                reportStatsResult.status === "fulfilled"
                  ? reportStatsResult.value.stats
                  : undefined,
              ),
            );
          } else if (reportStatsResult.status === "fulfilled") {
            setStats({
              ...(reportStatsResult.value.stats ?? EMPTY_STATS),
              pendingReports: EMPTY_STATS.pendingReports,
            });
            setError(
              reportsResult.reason instanceof Error
                ? reportsResult.reason.message
                : "Could not load corrected report stats. Pending Reports is hidden because backend stats may include linked reports.",
            );
          } else {
            setStats(EMPTY_STATS);
            setError("Could not load your dashboard stats.");
          }
        } else {
          setServiceCaseStats(EMPTY_SERVICE_CASE_STATS);
          setServiceCaseStatsError(
            serviceCasesResult.reason instanceof Error
              ? serviceCasesResult.reason.message
              : "Could not load your service case stats.",
          );

          if (reportsResult.status === "fulfilled") {
            setStats(
              getReportStatsWithoutLinkedWorkflowData(
                reports,
                incidents,
              ),
            );
            setError(
              "Could not load service case data, so linked service cases are not included in resolved report totals.",
            );
          } else if (reportStatsResult.status === "fulfilled") {
            setStats({
              ...(reportStatsResult.value.stats ?? EMPTY_STATS),
              pendingReports: EMPTY_STATS.pendingReports,
            });
            setError(
              "Could not load corrected report data. Pending Reports is hidden because backend stats may include linked reports.",
            );
          } else {
            setStats(EMPTY_STATS);
            setError("Could not load your dashboard stats.");
          }
        }
      } catch (err) {
        setError(
          err instanceof Error
            ? err.message
            : "Could not load your dashboard stats.",
        );
        setIncidentStats(EMPTY_INCIDENT_STATS);
        setReports([]);
        setIncidents([]);
        setServiceCases([]);
      } finally {
        setIsLoading(false);
      }
    };

    void loadDashboard();
  }, [isChecking]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  if (isChecking || isLoading) {
    return <PageLoading label="Loading citizen dashboard" />;
  }

  const latestReport = getLatestReport(reports);
  const latestIncident = getLatestIncident(incidents);
  const latestServiceCase = getLatestServiceCase(serviceCases);
  const welcomeName = getCitizenWelcomeName(user);
  const recentActivity = buildRecentActivity(reports, incidents, serviceCases);

  return (
    <DashboardLayout
      title="NIERS Citizen Portal"
      subtitle="Report incidents and emergencies"
      onLogout={handleLogout}
    >
      <CitizenPageContent>
        {error && <ErrorAlert message={error} />}

        <WelcomeCard userName={welcomeName} />

        <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-3">
          <DashboardSummaryCard
            title="Reports"
            description="View the status of your submitted reports."
            icon={FileText}
            iconClassName="bg-[#002D62] text-white"
            latestItem={latestReport}
            latestLabel="Latest Report"
            emptyState="No reports submitted yet."
            error={reports.length > 0 ? "" : error}
            action={
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="h-11 w-full max-w-xs justify-between px-5 text-sm text-[#002D62]"
                onClick={() => router.push("/dashboard/citizen/reports")}
              >
                View My Reports
                <ArrowRight className="h-4 w-4" aria-hidden />
              </Button>
            }
            items={[
              { label: "Total", value: stats.totalReports },
              { label: "Pending", value: stats.pendingReports, tone: "warning" },
              { label: "Resolved", value: stats.resolvedReports, tone: "success" },
            ]}
          />

          <DashboardSummaryCard
            title="Incidents"
            description="Track emergency responses linked to your reports."
            icon={AlertTriangle}
            iconClassName="bg-[#B91C1C] text-white"
            latestItem={latestIncident}
            latestLabel="Latest Response"
            emptyState="No linked emergency responses yet."
            error={incidentStatsError}
            action={
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="h-11 w-full max-w-xs justify-between px-5 text-sm text-[#002D62]"
                onClick={() => router.push("/dashboard/citizen/incidents")}
              >
                View Emergency Responses
                <ArrowRight className="h-4 w-4" aria-hidden />
              </Button>
            }
            items={[
              { label: "Total", value: incidentStats.totalIncidents },
              { label: "Active", value: incidentStats.activeIncidents, tone: "warning" },
              { label: "Resolved", value: incidentStats.resolvedIncidents, tone: "success" },
            ]}
          />

          <DashboardSummaryCard
            title="Service Cases"
            description="Track service cases that need follow-up."
            icon={ClipboardCheck}
            iconClassName="bg-[#002D62] text-white"
            latestItem={latestServiceCase}
            latestLabel="Latest Case"
            emptyState="No service cases have been opened yet."
            error={serviceCaseStatsError}
            action={
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="h-11 w-full max-w-xs justify-between px-5 text-sm text-[#002D62]"
                onClick={() => router.push("/dashboard/citizen/service-cases")}
              >
                View Service Cases
                <ArrowRight className="h-4 w-4" aria-hidden />
              </Button>
            }
            items={[
              { label: "Total", value: serviceCaseStats.totalServiceCases },
              { label: "Open", value: serviceCaseStats.openServiceCases, tone: "warning" },
              { label: "Resolved", value: serviceCaseStats.resolvedServiceCases, tone: "success" },
            ]}
          />
        </div>

        <div className="grid gap-6 lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)] xl:grid-cols-[minmax(0,2fr)_minmax(360px,1fr)]">
          <RecentActivityPanel
            items={recentActivity}
            onNavigate={(href) => router.push(href)}
          />
          <QuickActionsPanel onNavigate={(href) => router.push(href)} />
        </div>

        <footer className="mt-8 flex flex-wrap items-center justify-center gap-3 text-xs text-[#42547A]">
          <span>© 2025 NIERS. All rights reserved.</span>
          <Link className="font-medium text-[#0B3FE8]" href="/">
            Privacy Policy
          </Link>
          <span>•</span>
          <Link className="font-medium text-[#0B3FE8]" href="/">
            Terms of Use
          </Link>
        </footer>
      </CitizenPageContent>
    </DashboardLayout>
  );
}
