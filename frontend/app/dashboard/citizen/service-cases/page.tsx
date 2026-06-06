"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { ArrowRight, ClipboardCheck } from "lucide-react";
import {
  CitizenLocationPill,
  CitizenMetaItem,
  CitizenRecordCard,
  CitizenSectionCard,
  getCitizenFriendlyError,
} from "@/components/citizen/CitizenPortal";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { EmptyState, PageLoading } from "@/components/ui/StatusState";
import { apiGet } from "@/lib/api";
import { clearAuthSession } from "@/lib/auth-store";
import { formatBangladeshTime } from "@/lib/datetime";
import { sortNewestFirst } from "@/lib/sort";
import {
  getServiceCaseStatusLabel,
  isServiceCaseFinal,
} from "@/lib/service-case-status";
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
        setServiceCases(
          sortNewestFirst(data.service_cases ?? [], (serviceCase) => [
            serviceCase.last_updated,
            serviceCase.created_at,
          ]),
        );
      } catch (err) {
        console.error("Failed to load citizen service cases", err);
        setError(
          getCitizenFriendlyError(
            err,
            "We could not load your service cases right now. Please try again.",
          ),
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
      title="Service Cases"
      subtitle="Follow up on non-emergency cases created from your reports."
      onLogout={handleLogout}
    >
      <div className="space-y-3">
        <CitizenSectionCard
          title="Your Service Cases"
          subtitle="Service cases opened from your reports will appear here."
          icon={<ClipboardCheck className="h-5 w-5" aria-hidden />}
          className="flex max-h-[calc(100dvh-11rem)] min-h-[22rem] flex-col"
          contentClassName="min-h-0 flex-1 overflow-y-auto overscroll-y-contain"
        >
            {isLoading && (
              <p className="text-sm text-[#42547A]">Loading your service cases...</p>
            )}

            {error && <ErrorAlert message={error} />}

            {!isLoading && !error && serviceCases.length === 0 && (
              <EmptyState
                title="No service cases yet."
                description="Service cases created from your reports will appear here after a dispatcher classifies them."
                icon={<ClipboardCheck className="h-6 w-6" aria-hidden />}
              />
            )}

            {!isLoading && !error && serviceCases.length > 0 && (
              <div className="grid gap-4">
                {serviceCases.map((serviceCase) => (
                  <CitizenRecordCard
                    key={serviceCase.public_uuid}
                  >
                    <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                      <div className="min-w-0">
                        <p className="text-xs font-bold uppercase tracking-wide text-[#006747]">
                          {serviceCase.case_code}
                        </p>
                        <h3 className="mt-1 break-words text-lg font-semibold text-slate-950">
                          {serviceCase.title}
                        </h3>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        <Badge tone={serviceCase.status_code}>
                          {getServiceCaseStatusLabel(serviceCase.status_code)}
                        </Badge>
                        {isServiceCaseFinal(serviceCase.status_code) ? (
                          <Badge tone="closed">Final</Badge>
                        ) : null}
                        {serviceCase.priority_level ? (
                          <Badge tone={serviceCase.priority_level}>
                            {formatBadgeLabel(serviceCase.priority_level)}
                          </Badge>
                        ) : null}
                      </div>
                    </div>

                    <div className="mt-4 grid gap-3 sm:grid-cols-2">
                      <CitizenMetaItem
                        label="Category"
                        value={formatBadgeLabel(serviceCase.category_code)}
                      />
                      <CitizenMetaItem
                        label="Intake report"
                        value={serviceCase.intake_report_code ?? "-"}
                      />
                      <CitizenMetaItem
                        label="Last updated"
                        value={formatBangladeshTime(serviceCase.last_updated)}
                      />
                      <CitizenMetaItem
                        label="Created"
                        value={formatBangladeshTime(serviceCase.created_at)}
                      />
                      <div className="sm:col-span-2">
                        <CitizenLocationPill>
                          {formatLocation(serviceCase.location) ||
                            serviceCase.location_text ||
                            "-"}
                        </CitizenLocationPill>
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
                  </CitizenRecordCard>
                ))}
              </div>
            )}
        </CitizenSectionCard>
      </div>
    </DashboardLayout>
  );
}
