"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { ArrowRight, FileText, MapPin } from "lucide-react";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardContent, CardHeader } from "@/components/ui/Card";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { EmptyState, PageLoading } from "@/components/ui/StatusState";
import { apiGet } from "@/lib/api";
import { clearAuthSession } from "@/lib/auth-store";
import { formatBangladeshTime } from "@/lib/datetime";
import { useAuthGuard } from "@/lib/use-auth-guard";
import type {
  CitizenServiceCase,
  CitizenServiceCaseListResponse,
} from "@/types/service-case";

function formatLocation(location: CitizenServiceCase["location"] | null | undefined) {
  if (!location) return null;
  return location.address_text || location.place_name || "Map location selected";
}

export default function CitizenServiceCasesPage() {
  const router = useRouter();
  const isChecking = useAuthGuard(["citizen"]);
  const [serviceCases, setServiceCases] = useState<CitizenServiceCase[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (isChecking) return;

    const loadServiceCases = async () => {
      setIsLoading(true);
      setError(null);

      try {
        const data = await apiGet<CitizenServiceCaseListResponse>(
          "/intake/reports/my/service-cases",
        );
        setServiceCases(data.service_cases ?? []);
      } catch (err) {
        setError(
          err instanceof Error
            ? err.message
            : "Unexpected error while loading service cases.",
        );
      } finally {
        setIsLoading(false);
      }
    };

    void loadServiceCases();
  }, [isChecking]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  if (isChecking) {
    return <PageLoading label="Loading service cases" />;
  }

  return (
    <DashboardLayout
      title="My Service Cases"
      subtitle="View service cases linked to your reports"
      onLogout={handleLogout}
    >
      <div className="space-y-6">
        <div className="flex flex-col gap-3 sm:flex-row sm:justify-end">
          <Button
            type="button"
            variant="secondary"
            onClick={() => router.push("/dashboard/citizen")}
          >
            Back to Dashboard
          </Button>
          <Button onClick={() => router.push("/dashboard/citizen/reports")}> 
            View My Reports
          </Button>
        </div>

        <Card className="shadow-md">
          <CardHeader>
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-[#002D62] text-white">
                <FileText className="h-5 w-5" aria-hidden />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-[#002D62]">
                  Citizen Service Cases
                </h2>
                <p className="mt-1 text-sm text-gray-600">
                  Service cases opened from your reports will appear here.
                </p>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            {isLoading && (
              <p className="text-sm text-gray-600">Loading your service cases...</p>
            )}

            {error && <ErrorAlert message={error} />}

            {!isLoading && !error && serviceCases.length === 0 && (
              <EmptyState
                title="No service cases yet"
                description="Service cases created from your reports will appear here after a dispatcher classifies them."
                icon={<FileText className="h-6 w-6" aria-hidden />}
                action={
                  <Button
                    type="button"
                    onClick={() => router.push("/dashboard/citizen/reports")}
                  >
                    View My Reports
                  </Button>
                }
              />
            )}

            {!isLoading && !error && serviceCases.length > 0 && (
              <div className="grid gap-4">
                {serviceCases.map((serviceCase) => (
                  <div
                    key={serviceCase.public_uuid}
                    className="rounded-2xl border border-[#002D62]/10 bg-white p-5 shadow-sm"
                  >
                    <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                      <div>
                        <p className="text-xs font-bold uppercase tracking-wide text-[#006747]">
                          {serviceCase.case_code}
                        </p>
                        <h3 className="mt-1 text-lg font-semibold text-gray-900">
                          {serviceCase.title}
                        </h3>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        <Badge tone={serviceCase.status_code}>
                          {formatBadgeLabel(serviceCase.status_code)}
                        </Badge>
                        <Badge tone={serviceCase.priority_level}>
                          {formatBadgeLabel(serviceCase.priority_level)}
                        </Badge>
                      </div>
                    </div>

                    <div className="mt-4 grid gap-3 text-sm text-gray-600 sm:grid-cols-2">
                      <p>
                        <span className="font-medium text-gray-800">Category:</span>{" "}
                        {formatBadgeLabel(serviceCase.category_code)}
                      </p>
                      <p>
                        <span className="font-medium text-gray-800">Intake report:</span>{" "}
                        {serviceCase.intake_report_code ?? "-"}
                      </p>
                      <p>
                        <span className="font-medium text-gray-800">Last updated:</span>{" "}
                        {formatBangladeshTime(serviceCase.last_updated)}
                      </p>
                      <p>
                        <span className="font-medium text-gray-800">Created:</span>{" "}
                        {formatBangladeshTime(serviceCase.created_at)}
                      </p>
                      <div className="sm:col-span-2">
                        <div className="flex gap-2 rounded-2xl bg-[#EFF6FF] px-3 py-2">
                          <MapPin
                            className="mt-0.5 h-4 w-4 shrink-0 text-[#006747]"
                            aria-hidden
                          />
                          <p className="text-sm text-gray-700">
                            <span className="font-medium text-gray-800">Location:</span>{" "}
                            {formatLocation(serviceCase.location) || serviceCase.location_text || "-"}
                          </p>
                        </div>
                      </div>
                    </div>

                    <div className="mt-5">
                      <Button
                        type="button"
                        size="sm"
                        onClick={() =>
                          router.push(
                            `/dashboard/citizen/service-cases/${serviceCase.public_uuid}`,
                          )
                        }
                      >
                        View Details
                        <ArrowRight className="h-4 w-4" aria-hidden />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
}
