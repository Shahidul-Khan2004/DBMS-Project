"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { CheckCircle2, Clock3, FileText, MapPin, PlusCircle } from "lucide-react";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardHeader, CardContent } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { PageHeader, PageLoading } from "@/components/ui/StatusState";
import { apiGet } from "@/lib/api";
import { clearAuthSession } from "@/lib/auth-store";
import { useAuthGuard } from "@/lib/use-auth-guard";
import type { LoginResponse } from "@/types/auth";
import type {
  IntakeReportStats,
  IntakeReportStatsResponse,
} from "@/types/intake";

const EMPTY_STATS: IntakeReportStats = {
  totalReports: 0,
  pendingReports: 0,
  resolvedReports: 0,
};

const STAT_CARDS = [
  {
    key: "totalReports",
    label: "Total Reports",
    description: "All reports submitted from your account",
    icon: FileText,
    accent: "bg-[#002D62] text-white",
  },
  {
    key: "pendingReports",
    label: "Pending Reports",
    description: "Reports still being reviewed or coordinated",
    icon: Clock3,
    accent: "bg-amber-100 text-amber-800",
  },
  {
    key: "resolvedReports",
    label: "Resolved Reports",
    description: "Reports closed after action or review",
    icon: CheckCircle2,
    accent: "bg-emerald-100 text-emerald-800",
  },
] as const;

export default function CitizenDashboard() {
  const router = useRouter();
  const isChecking = useAuthGuard(["citizen"]);
  const [user, setUser] = useState<LoginResponse["user"] | null>(null);
  const [stats, setStats] = useState<IntakeReportStats>(EMPTY_STATS);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    if (isChecking) return;

    const loadDashboard = async () => {
      const sessionUser = sessionStorage.getItem("loggedInUser");

      setIsLoading(true);
      setError("");
      try {
        const parsedUser = sessionUser
          ? (JSON.parse(sessionUser) as LoginResponse["user"])
          : null;
        setUser(parsedUser);

        const data = await apiGet<IntakeReportStatsResponse>(
          "/intake/reports/my/stats",
        );
        setStats(data.stats ?? EMPTY_STATS);
      } catch (err) {
        setError(
          err instanceof Error
            ? err.message
            : "Could not load your dashboard stats.",
        );
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
          <CardHeader>
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <h2 className="text-lg font-semibold text-[#002D62]">
                Your Reports
              </h2>
              <Button
                type="button"
                variant="secondary"
                size="sm"
                onClick={() => router.push("/dashboard/citizen/reports")}
              >
                View My Reports
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 sm:grid-cols-3">
              {STAT_CARDS.map((item) => {
                const Icon = item.icon;
                return (
                  <div
                    key={item.key}
                    className="rounded-2xl border border-[#002D62]/10 bg-white p-5 shadow-sm"
                  >
                    <div
                      className={`flex h-11 w-11 items-center justify-center rounded-2xl ${item.accent}`}
                    >
                      <Icon className="h-5 w-5" aria-hidden />
                    </div>
                    <div className="mt-5 text-3xl font-bold text-[#002D62]">
                      {stats[item.key]}
                    </div>
                    <p className="mt-1 text-sm font-semibold text-gray-900">
                      {item.label}
                    </p>
                    <p className="mt-2 text-xs leading-5 text-gray-600">
                      {item.description}
                    </p>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
}
