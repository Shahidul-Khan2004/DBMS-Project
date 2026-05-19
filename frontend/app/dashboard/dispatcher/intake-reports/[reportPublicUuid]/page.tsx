"use client";

import dynamic from "next/dynamic";
import {
  type FormEvent,
  type ReactNode,
  useCallback,
  useEffect,
  useState,
} from "react";
import { useParams, useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardContent, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import { EmptyState, PageLoading } from "@/components/ui/StatusState";
import { ApiError, apiJson, apiPost, ensureAuthSession } from "@/lib/api";
import { clearAuthSession } from "@/lib/auth-store";
import { formatBangladeshTime } from "@/lib/datetime";
import {
  canClassifyServiceCase,
  canEscalateServiceCase,
  canPromoteEmergency,
  getEmergencyAction,
  getEscalateServiceCaseHref,
} from "@/lib/dispatcher-intake-actions";
import type {
  LocationPickerSelectionDetails,
  LocationPickerValue,
} from "@/components/location/LocationPicker";
import type {
  IntakeLocationHistoryItem,
  IntakeLocationHistoryResponse,
  UpdateIntakeLocationResponse,
} from "@/types/intake";
import type {
  OperationsIntakeReport,
  OperationsIntakeReportResponse,
} from "@/types/operations-intake";

const LocationPicker = dynamic(
  () =>
    import("@/components/location/LocationPicker").then((mod) => ({
      default: mod.LocationPicker,
    })),
  {
    ssr: false,
    loading: () => (
      <div className="h-[420px] animate-pulse rounded-2xl bg-slate-100" />
    ),
  },
);

type IntakeLinkType = "supporting_report" | "follow_up_report";

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function formatLabel(value: string | null | undefined) {
  if (!value) return "-";
  return value.replace(/_/g, " ");
}

function DetailRow({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <dl>
      <dt className="text-sm font-medium text-gray-600">{label}</dt>
      <dd className="mt-1 wrap-break-word text-sm text-gray-900">{children}</dd>
    </dl>
  );
}

function formatLocation(
  location: OperationsIntakeReport["location"] | IntakeLocationHistoryItem["location"],
) {
  if (!location) return "-";
  return (
    location.address_text ||
    location.place_name ||
    "Map location selected"
  );
}

function formatApiError(error: unknown, fallback: string) {
  if (error instanceof ApiError) {
    const hints: Record<string, string> = {
      EMERGENCY_INCIDENT_REQUIRES_LOCATION:
        "Add a reported location to this intake before linking it.",
      INTAKE_ALREADY_LINKED:
        "This intake report is already linked to an emergency incident.",
      INTAKE_NOT_PROMOTABLE:
        "This intake report cannot be linked in its current status.",
      INCIDENT_NOT_LINKABLE:
        "The selected incident cannot accept new intake links.",
      INCIDENT_NOT_FOUND:
        "Check the target incident public UUID and try again.",
    };
    const hint = error.code ? hints[error.code] : undefined;
    const codePrefix = error.code ? `${error.code}: ` : "";
    return `${codePrefix}${error.message}${hint ? ` ${hint}` : ""}`;
  }

  return error instanceof Error ? error.message : fallback;
}

function LocationHistory({ history }: { history: IntakeLocationHistoryItem[] }) {
  if (history.length === 0) {
    return <p className="text-sm text-gray-600">No location changes recorded.</p>;
  }

  return (
    <ul className="divide-y divide-[#002D62]/10">
      {history.map((item, index) => (
        <li key={`${item.changed_at}-${index}`} className="py-4">
          <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
            <div>
              <p className="text-sm font-semibold capitalize text-[#002D62]">
                {formatBadgeLabel(item.change_kind)}
              </p>
              <p className="mt-1 text-sm text-gray-700">
                {formatLocation(item.location)}
              </p>
              {item.previous_location && (
                <p className="mt-1 text-xs text-gray-500">
                  Previous: {formatLocation(item.previous_location)}
                </p>
              )}
            </div>
            <div className="text-xs text-gray-500 sm:text-right">
              <p>{formatBangladeshTime(item.changed_at)}</p>
              <p className="mt-1">
                {item.changed_by?.full_name ?? "System"} |{" "}
                {item.changed_by?.actor_kind ?? "system"}
              </p>
            </div>
          </div>
        </li>
      ))}
    </ul>
  );
}

export default function IntakeReportDetailPage() {
  const params = useParams();
  const router = useRouter();
  const reportPublicUuid = params.reportPublicUuid as string;

  const [report, setReport] = useState<OperationsIntakeReport | null>(null);
  const [history, setHistory] = useState<IntakeLocationHistoryItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isLoadingSession, setIsLoadingSession] = useState(true);
  const [locationMessage, setLocationMessage] = useState("");
  const [locationError, setLocationError] = useState("");
  const [savingLocation, setSavingLocation] = useState(false);
  const [isLocationUpdateOpen, setIsLocationUpdateOpen] = useState(false);
  const [locationForm, setLocationForm] = useState({
    latitude: "",
    longitude: "",
    addressText: "",
    placeName: "",
  });

  const redirectToLogin = useCallback(() => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/auth/login");
  }, [router]);

  const loadReport = useCallback(async () => {
    const accessToken = await ensureAuthSession();

    if (!accessToken) {
      redirectToLogin();
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const [detailData, historyData] = await Promise.all([
        apiJson<OperationsIntakeReportResponse>(
          `/operations/intake-reports/${reportPublicUuid}`,
        ),
        apiJson<IntakeLocationHistoryResponse>(
          `/operations/intake-reports/${reportPublicUuid}/reported-location-history`,
        ),
      ]);

      const nextReport = detailData.intake_report;
      setReport(nextReport);
      setHistory(historyData.history ?? []);
      setLocationForm({
        latitude: nextReport.location?.latitude?.toString() ?? "",
        longitude: nextReport.location?.longitude?.toString() ?? "",
        addressText: nextReport.location?.address_text ?? nextReport.location_text ?? "",
        placeName: nextReport.location?.place_name ?? "",
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load intake report.");
      setReport(null);
      setHistory([]);
    } finally {
      setLoading(false);
    }
  }, [reportPublicUuid, redirectToLogin]);

  useEffect(() => {
    let cancelled = false;

    async function checkSession() {
      const accessToken = await ensureAuthSession();
      const sessionUser = sessionStorage.getItem("loggedInUser");

      if (cancelled) return;

      if (!sessionUser || !accessToken) {
        redirectToLogin();
        return;
      }

      setIsLoadingSession(false);
    }

    void checkSession();

    return () => {
      cancelled = true;
    };
  }, [redirectToLogin]);

  useEffect(() => {
    if (isLoadingSession || !reportPublicUuid) return;
    void loadReport();
  }, [isLoadingSession, reportPublicUuid, loadReport]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  const handleLocationChange = useCallback(
    (
      location: LocationPickerValue,
      details?: LocationPickerSelectionDetails,
    ) => {
      setLocationForm((current) => ({
        ...current,
        latitude: location.latitude.toString(),
        longitude: location.longitude.toString(),
        addressText: details?.addressText ?? current.addressText,
        placeName: details?.placeName ?? current.placeName,
      }));
      setLocationError("");
      setLocationMessage("");
    },
    [],
  );

  async function handleLocationSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLocationError("");
    setLocationMessage("");

    const latitude = Number(locationForm.latitude);
    const longitude = Number(locationForm.longitude);

    if (!Number.isFinite(latitude) || !Number.isFinite(longitude)) {
      setLocationError("Choose a valid point on the map.");
      return;
    }

    setSavingLocation(true);
    try {
      const data = await apiJson<UpdateIntakeLocationResponse>(
        `/intake/reports/${reportPublicUuid}/location`,
        {
          method: "PATCH",
          body: JSON.stringify({
            location: {
              latitude,
              longitude,
              address_text: locationForm.addressText.trim() || undefined,
              place_name: locationForm.placeName.trim() || undefined,
              source: "dispatcher_selected",
            },
          }),
        },
      );

      setLocationMessage(data.message || "Reported location updated.");
      await loadReport();
      setIsLocationUpdateOpen(false);
    } catch (err) {
      setLocationError(
        err instanceof Error ? err.message : "Could not update location.",
      );
    } finally {
      setSavingLocation(false);
    }
  }

  if (isLoadingSession) {
    return <PageLoading label="Loading intake details" />;
  }

  const selectedLocation =
    locationForm.latitude.trim() &&
    locationForm.longitude.trim() &&
    Number.isFinite(Number(locationForm.latitude)) &&
    Number.isFinite(Number(locationForm.longitude))
      ? {
          latitude: Number(locationForm.latitude),
          longitude: Number(locationForm.longitude),
        }
      : null;

  return (
    <DashboardLayout
      title="Intake Report Details"
      subtitle={`Report ${report?.report_code || reportPublicUuid}`}
      onLogout={handleLogout}
    >
      <div className="space-y-6">

        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <Button
            type="button"
            variant="secondary"
            size="sm"
            onClick={() => router.push("/dashboard/dispatcher/intake-reports")}
          >
            Back to Reports
          </Button>

          {report ? (
            <div className="flex flex-wrap gap-3">
              {canClassifyServiceCase(report) ? (
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() =>
                    router.push(
                      `/dashboard/dispatcher/intake-reports/${report.public_uuid}/classify/service-case`,
                    )
                  }
                >
                  Classify as Service Case
                </Button>
              ) : null}

              {canPromoteEmergency(report) ? (
                <Button
                  type="button"
                  size="sm"
                  onClick={() => router.push(getEmergencyAction(report).href)}
                >
                  {getEmergencyAction(report).label}
                </Button>
              ) : null}

              {canEscalateServiceCase(report) ? (
                <Button
                  type="button"
                  size="sm"
                  onClick={() =>
                    router.push(getEscalateServiceCaseHref(report.public_uuid))
                  }
                >
                  Escalate to Emergency
                </Button>
              ) : null}
            </div>
          ) : null}
        </div>

        {error && <ErrorAlert message={error} />}

        {loading && !report ? <LoadingSkeleton lines={8} /> : null}

        {!loading && !report && !error ? (
          <EmptyState
            title="Intake report not found"
            description="The backend did not return an intake report for this identifier. Check the queue and try opening it again."
          />
        ) : null}

        {report ? (
          <div className="grid gap-6 lg:grid-cols-3">
            <Card className="shadow-md lg:col-span-2">
              <CardHeader>
                <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                  <div>
                    <p className="text-sm font-bold uppercase tracking-wide text-gray-600">
                      Report ID
                    </p>
                    <p className="mt-0.5 text-sm font-medium text-gray-600">
                      {report.report_code}
                    </p>
                    <h2 className="mt-1 text-xl font-semibold text-gray-900">
                      {report.summary || "(No summary)"}
                    </h2>
                  </div>

                  <div className="flex flex-wrap gap-2">
                    <Badge tone={report.intake_status}>
                      {formatLabel(report.intake_status)}
                    </Badge>
                    <Badge tone={report.urgency_type}>
                      {formatLabel(report.urgency_type)}
                    </Badge>
                  </div>
                </div>
              </CardHeader>

              <CardContent className="space-y-4">
                <div>
                  <h3 className="text-sm font-semibold text-gray-900">
                    Description
                  </h3>
                  <p className="mt-2 whitespace-pre-wrap text-sm leading-6 text-gray-700">
                    {report.description?.trim() || "No description provided."}
                  </p>
                </div>

                {report.final_disposition ? (
                  <div className="rounded-2xl border border-[#002D62]/10 bg-[#EFF6FF] p-4">
                    <h3 className="text-sm font-semibold text-gray-900">
                      Final Disposition
                    </h3>
                    <p className="mt-1 text-sm text-gray-700">
                      {formatLabel(report.final_disposition)}
                    </p>
                  </div>
                ) : null}
              </CardContent>
            </Card>

            <Card className="shadow-md">
              <CardHeader>
                <h2 className="text-lg font-semibold text-[#002D62]">
                  Operations Snapshot
                </h2>
              </CardHeader>

              <CardContent>
                <dl className="space-y-4">
                  <DetailRow label="Reporter User ID">
                    {report.reporter_user_id}
                  </DetailRow>
                  <DetailRow label="Category">
                    {formatLabel(report.category_code)}
                  </DetailRow>
                  <DetailRow label="Channel">
                    {formatLabel(report.channel_code)}
                  </DetailRow>
                  <DetailRow label="Service Case">
                    {report.has_service_case ? "Linked" : "Not linked"}
                  </DetailRow>
                  <DetailRow label="Incident">
                    {report.has_incident ? "Linked" : "Not linked"}
                  </DetailRow>
                  <DetailRow label="Public UUID">{report.public_uuid}</DetailRow>
                </dl>
              </CardContent>
            </Card>

            <Card className="shadow-md lg:col-span-3">
              <CardHeader>
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                  <h2 className="text-lg font-semibold text-[#002D62]">
                    Reported Location
                  </h2>
                  <Button
                    type="button"
                    variant="secondary"
                    size="sm"
                    onClick={() => {
                      setIsLocationUpdateOpen(true);
                      setLocationError("");
                      setLocationMessage("");
                    }}
                  >
                    Update Location
                  </Button>
                </div>
              </CardHeader>
              <CardContent className="space-y-5">
                <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                  <DetailRow label="Location">
                    {formatLocation(report.location)}
                  </DetailRow>
                  <DetailRow label="Source">
                    {formatLabel(report.location?.source)}
                  </DetailRow>
                </dl>

                {report.location && (
                  <a
                    href={`https://www.openstreetmap.org/?mlat=${report.location.latitude}&mlon=${report.location.longitude}#map=16/${report.location.latitude}/${report.location.longitude}`}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex text-sm font-semibold text-[#006747] hover:text-[#002D62]"
                  >
                    Open location in map
                  </a>
                )}

                {locationMessage && (
                  <div className="rounded-2xl bg-green-50 p-3 text-sm text-green-700">
                    {locationMessage}
                  </div>
                )}
              </CardContent>
            </Card>

            {isLocationUpdateOpen ? (
              <Card className="shadow-md lg:col-span-3">
                <CardHeader>
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                    <div>
                      <h2 className="text-lg font-semibold text-[#002D62]">
                        Update Location
                      </h2>
                      <p className="mt-1 text-sm text-gray-600">
                        Search or click the map to correct the reported
                        location.
                      </p>
                    </div>
                    <Button
                      type="button"
                      variant="secondary"
                      size="sm"
                      onClick={() => {
                        if (savingLocation) return;
                        setIsLocationUpdateOpen(false);
                        setLocationError("");
                      }}
                      disabled={savingLocation}
                    >
                      Cancel
                    </Button>
                  </div>
                </CardHeader>
                <CardContent>
                  {locationError && (
                    <div className="mb-4 rounded-2xl bg-red-50 p-3 text-sm text-red-700">
                      {locationError}
                    </div>
                  )}

                  <form onSubmit={handleLocationSubmit} className="space-y-4">
                    <LocationPicker
                      value={selectedLocation}
                      onChange={handleLocationChange}
                      selectedAddress={locationForm.addressText}
                      selectedPlaceName={locationForm.placeName}
                      syncSearchQueryToSelectedLabel={false}
                      showCurrentLocation={false}
                    />
                    <div className="grid gap-4 sm:grid-cols-2">
                      <div>
                        <label className="block text-sm font-medium text-gray-700">
                          Address Text
                        </label>
                        <input
                          value={locationForm.addressText}
                          onChange={(event) =>
                            setLocationForm((current) => ({
                              ...current,
                              addressText: event.target.value,
                            }))
                          }
                          className="mt-1 w-full rounded-2xl border border-[#002D62]/20 bg-white px-3 py-2 text-gray-900"
                          placeholder="Optional address or landmark"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-700">
                          Place Name
                        </label>
                        <input
                          value={locationForm.placeName}
                          onChange={(event) =>
                            setLocationForm((current) => ({
                              ...current,
                              placeName: event.target.value,
                            }))
                          }
                          className="mt-1 w-full rounded-2xl border border-[#002D62]/20 bg-white px-3 py-2 text-gray-900"
                          placeholder="Optional place name"
                        />
                      </div>
                    </div>
                    <Button type="submit" isLoading={savingLocation}>
                      Save Location Correction
                    </Button>
                  </form>
                </CardContent>
              </Card>
            ) : null}

            <Card className="shadow-md lg:col-span-3">
              <CardHeader>
                <h2 className="text-lg font-semibold text-[#002D62]">
                  Location History
                </h2>
              </CardHeader>
              <CardContent>
                <LocationHistory history={history} />
              </CardContent>
            </Card>

            <Card className="shadow-md lg:col-span-3">
              <CardHeader>
                <h2 className="text-lg font-semibold text-[#002D62]">
                  Timeline
                </h2>
              </CardHeader>

              <CardContent>
                <dl className="grid gap-4 sm:grid-cols-3">
                  <DetailRow label="Reported At">
                    {formatBangladeshTime(report.reported_at)}
                  </DetailRow>
                  <DetailRow label="Created At">
                    {formatBangladeshTime(report.created_at)}
                  </DetailRow>
                  <DetailRow label="Updated At">
                    {formatBangladeshTime(report.updated_at)}
                  </DetailRow>
                </dl>
              </CardContent>
            </Card>
          </div>
        ) : null}
      </div>
    </DashboardLayout>
  );
}
