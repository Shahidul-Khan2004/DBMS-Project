"use client";

import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import Image from "next/image";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { AlertTriangle, ArrowRight, ClipboardCheck, FileText } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardHeader, CardContent } from "@/components/ui/Card";
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
    primary: latest.report_code,
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
    primary: latest.incident_code,
    secondary: latest.title ?? latest.description ?? "Linked emergency incident",
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
    primary: latest.case_code,
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
    <div className="min-w-0 px-4 py-1 text-center">
      <p className="text-sm font-medium text-[#1F3768]">
        {label}
      </p>
      <p className={`mt-2 text-3xl font-bold leading-none ${toneClass}`}>{value}</p>
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
    <Card className="flex min-h-[320px] flex-col overflow-hidden !rounded-2xl !border-slate-200 !bg-white shadow-sm shadow-[#002D62]/8">
      <CardHeader className="!border-b-0 !px-5 !pb-4 !pt-5">
        <div className="flex items-center gap-4">
          <div className={`flex h-12 w-12 shrink-0 items-center justify-center rounded-full ${iconClassName}`}>
            <Icon className="h-6 w-6" aria-hidden />
          </div>
          <div className="min-w-0">
            <h2 className="text-lg font-bold text-[#002D62]">{title}</h2>
            <p className="mt-1 text-sm leading-5 text-[#42547A]">{description}</p>
          </div>
        </div>
      </CardHeader>
      <CardContent className="flex flex-1 flex-col !px-5 !pb-5 !pt-0">
        {error ? (
          <div className="mb-4">
            <ErrorAlert message={error} />
          </div>
        ) : null}
        <div className="border-y border-slate-200 py-3">
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
          <p className="text-sm font-semibold text-[#42547A]">
            {latestLabel}
          </p>
          {latestItem ? (
            <div className="mt-2 min-w-0">
              <p className="truncate text-base font-bold text-slate-950">
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

        <div className="mt-4">{action}</div>
      </CardContent>
    </Card>
  );
}

function WelcomeCard({ userName }: { userName?: string | null }) {
  const welcomeTitle = userName ? `Welcome, ${userName}` : "Welcome back";

  return (
    <Card className="overflow-hidden !rounded-2xl !border-slate-200 !bg-white shadow-lg shadow-[#002D62]/8">
      <CardContent className="!p-0">
        <div className="relative min-h-[170px] overflow-hidden">
          <Image
            src="/images/citizen-dashboard-hero-clean.webp"
            alt="Bangladesh disaster response team assisting flood-affected citizens"
            fill
            sizes="100vw"
            className="object-cover"
            priority
          />
          <div className="absolute inset-0 bg-[#002D62]/30 mix-blend-multiply" />
          <div className="absolute inset-0 bg-[linear-gradient(90deg,#fff_0%,rgba(255,255,255,0.94)_24%,rgba(255,255,255,0.42)_42%,rgba(255,255,255,0)_58%)]" />
          <div className="relative flex min-h-[170px] max-w-md flex-col justify-center px-6 py-6 sm:px-9">
            <h1
              className="max-w-[22rem] truncate text-2xl font-bold text-[#002D62] sm:text-3xl"
              title={welcomeTitle}
            >
              {welcomeTitle}
            </h1>
            <p className="mt-3 max-w-xs text-base leading-6 text-[#42547A]">
              Track your reports, incidents, and service cases from one place.
            </p>
          </div>
        </div>
      </CardContent>
    </Card>
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

  return (
    <DashboardLayout
      title="NIERS Citizen Portal"
      subtitle="Report incidents and emergencies"
      onLogout={handleLogout}
    >
      <div className="space-y-4">
        {error && <ErrorAlert message={error} />}

        <WelcomeCard userName={welcomeName} />

        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
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
                className="h-12 w-56 max-w-full justify-between !rounded-lg border-[#0B3FE8] px-6 text-sm text-[#0B3FE8]"
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
            description="See incidents that are linked to you."
            icon={AlertTriangle}
            iconClassName="bg-orange-600 text-white"
            latestItem={latestIncident}
            latestLabel="Latest Incident"
            emptyState="No linked emergency incidents yet."
            error={incidentStatsError}
            action={
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="h-12 w-56 max-w-full justify-between !rounded-lg border-[#0B3FE8] px-6 text-sm text-[#0B3FE8]"
                onClick={() => router.push("/dashboard/citizen/incidents")}
              >
                View My Incidents
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
            iconClassName="bg-[#0AA64B] text-white"
            latestItem={latestServiceCase}
            latestLabel="Latest Case"
            emptyState="No service cases have been opened yet."
            error={serviceCaseStatsError}
            action={
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="h-12 w-56 max-w-full justify-between !rounded-lg border-[#0B3FE8] px-6 text-sm text-[#0B3FE8]"
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
        <footer className="flex flex-wrap items-center justify-center gap-4 pb-1 text-sm text-[#42547A]">
          <span>© 2025 NIERS. All rights reserved.</span>
          <Link className="font-medium text-[#0B3FE8]" href="/">
            Privacy Policy
          </Link>
          <span>•</span>
          <Link className="font-medium text-[#0B3FE8]" href="/">
            Terms of Use
          </Link>
        </footer>
      </div>
    </DashboardLayout>
  );
}
