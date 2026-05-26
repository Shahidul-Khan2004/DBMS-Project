"use client";

import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { useRouter } from "next/navigation";
import { AlertTriangle, Clock3, FileText, MapPin, PlusCircle } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardHeader, CardContent } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { PageHeader, PageLoading } from "@/components/ui/StatusState";
import { apiGet } from "@/lib/api";
import { clearAuthSession } from "@/lib/auth-store";
import { getMyIncidents } from "@/lib/citizen-incidents-api";
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

function OverviewMetric({
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
    <div className="min-w-0 rounded-2xl border border-[#002D62]/10 bg-white px-4 py-3 shadow-sm">
      <p className="text-xs font-semibold uppercase tracking-wide text-gray-500">
        {label}
      </p>
      <p className={`mt-1 text-2xl font-bold ${toneClass}`}>{value}</p>
    </div>
  );
}

function SummaryCard({
  title,
  icon: Icon,
  iconClassName,
  items,
  action,
  error,
}: {
  title: string;
  icon: LucideIcon;
  iconClassName: string;
  items: Array<{ label: string; value: number; tone?: "default" | "warning" | "success" }>;
  action: ReactNode;
  error?: string;
}) {
  return (
    <Card className="shadow-md">
      <CardHeader className="px-4 py-4">
        <div className="flex items-center justify-between gap-3">
          <div className="flex min-w-0 items-center gap-3">
            <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl ${iconClassName}`}>
              <Icon className="h-5 w-5" aria-hidden />
            </div>
            <h2 className="truncate text-base font-semibold text-[#002D62]">
              {title}
            </h2>
          </div>
          <div className="shrink-0 [&_button]:whitespace-nowrap">{action}</div>
        </div>
      </CardHeader>
      <CardContent className="px-4 py-4">
        {error ? (
          <div className="mb-3">
            <ErrorAlert message={error} />
          </div>
        ) : null}
        <div className="grid grid-cols-3 gap-2">
          {items.map((item) => (
            <OverviewMetric
              key={item.label}
              label={item.label}
              value={item.value}
              tone={item.tone}
            />
          ))}
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

        setIncidentStats(getIncidentStats(incidents));
        if (incidentsResult.status === "rejected") {
          setIncidentStatsError(
            incidentsResult.reason instanceof Error
              ? incidentsResult.reason.message
              : "Could not load your emergency incident stats.",
          );
        }

        if (serviceCasesResult.status === "fulfilled") {
          const serviceCases = serviceCasesResult.value.service_cases ?? [];
          setServiceCaseStats(getServiceCaseStats(serviceCases));

          if (reportsResult.status === "fulfilled") {
            setStats(
              getCorrectedReportStats(
                reportsResult.value.reports ?? [],
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
                reportsResult.value.reports ?? [],
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

  return (
    <DashboardLayout
      title="NIERS Citizen Portal"
      subtitle="Report incidents and emergencies"
      onLogout={handleLogout}
    >
      <div className="space-y-6">
        {error && <ErrorAlert message={error} />}

        <PageHeader
          eyebrow="Citizen dashboard"
          title={`Welcome${user?.full_name ? `, ${user.full_name}` : ""}`}
          description="Track submitted reports, update reported locations, and keep trusted places ready for future submissions."
          meta={
            user?.id ? (
              <p className="break-all text-sm text-gray-600">
                User ID: {user.id}
              </p>
            ) : null
          }
          actions={
            <>
              <Button
                type="button"
                onClick={() => router.push("/dashboard/citizen/report-new")}
              >
                <PlusCircle className="h-4 w-4" aria-hidden />
                Report New Incident
              </Button>
              <Button
                type="button"
                variant="secondary"
                onClick={() => router.push("/dashboard/citizen/incidents")}
              >
                <AlertTriangle className="h-4 w-4" aria-hidden />
                My Incidents
              </Button>
              <Button
                type="button"
                variant="secondary"
                onClick={() => router.push("/dashboard/citizen/service-cases")}
              >
                <FileText className="h-4 w-4" aria-hidden />
                My Service Cases
              </Button>
              <Button
                type="button"
                variant="secondary"
                onClick={() => router.push("/dashboard/citizen/locations")}
              >
                <MapPin className="h-4 w-4" aria-hidden />
                Saved Locations
              </Button>
            </>
          }
        />

        <Card className="shadow-md">
          <CardContent className="p-4">
            <div className="grid gap-3 sm:grid-cols-3">
              <OverviewMetric label="Reports" value={stats.totalReports} />
              <OverviewMetric
                label="Incidents"
                value={incidentStats.totalIncidents}
                tone={incidentStats.activeIncidents > 0 ? "warning" : "default"}
              />
              <OverviewMetric
                label="Service Cases"
                value={serviceCaseStats.totalServiceCases}
                tone={serviceCaseStats.openServiceCases > 0 ? "warning" : "default"}
              />
            </div>
          </CardContent>
        </Card>

        <div className="grid gap-4 xl:grid-cols-3">
          <SummaryCard
            title="Reports"
            icon={FileText}
            iconClassName="bg-[#002D62] text-white"
            error=""
            action={
              <Button
                type="button"
                variant="secondary"
                size="sm"
                onClick={() => router.push("/dashboard/citizen/reports")}
              >
                View My Reports
              </Button>
            }
            items={[
              { label: "Total", value: stats.totalReports },
              { label: "Pending", value: stats.pendingReports, tone: "warning" },
              { label: "Resolved", value: stats.resolvedReports, tone: "success" },
            ]}
          />

          <SummaryCard
            title="Incidents"
            icon={AlertTriangle}
            iconClassName="bg-red-50 text-[#B71C1C]"
            error={incidentStatsError}
            action={
              <Button
                type="button"
                variant="secondary"
                size="sm"
                onClick={() => router.push("/dashboard/citizen/incidents")}
              >
                View My Incidents
              </Button>
            }
            items={[
              { label: "Total", value: incidentStats.totalIncidents },
              { label: "Active", value: incidentStats.activeIncidents, tone: "warning" },
              { label: "Resolved", value: incidentStats.resolvedIncidents, tone: "success" },
            ]}
          />

          <SummaryCard
            title="Service Cases"
            icon={Clock3}
            iconClassName="bg-amber-100 text-amber-800"
            error={serviceCaseStatsError}
            action={
              <Button
                type="button"
                variant="secondary"
                size="sm"
                onClick={() => router.push("/dashboard/citizen/service-cases")}
              >
                View Service Cases
              </Button>
            }
            items={[
              { label: "Total", value: serviceCaseStats.totalServiceCases },
              { label: "Open", value: serviceCaseStats.openServiceCases, tone: "warning" },
              { label: "Resolved", value: serviceCaseStats.resolvedServiceCases, tone: "success" },
            ]}
          />
        </div>
      </div>
    </DashboardLayout>
  );
}
