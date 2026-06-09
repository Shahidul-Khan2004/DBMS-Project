"use client";

import dynamic from "next/dynamic";
import { type FormEvent, type ReactNode, useCallback, useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import {
  AlertTriangle,
  CalendarClock,
  Clock3,
  FileText,
  Flag,
  Folder,
  Globe2,
  History,
  MapPin,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { CitizenBackButton } from "@/components/citizen/CitizenPortal";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardContent, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import { EmptyState, PageLoading } from "@/components/ui/StatusState";
import { OpenLocationMapButton } from "@/components/location/LocationMapModal";
import type {
  LocationPickerSelectionDetails,
  LocationPickerValue,
} from "@/components/location/LocationPicker";
import { apiGet, apiJson } from "@/lib/api";
import { clearAuthSession } from "@/lib/auth-store";
import { getMyIncidents } from "@/lib/citizen-incidents-api";
import { formatBangladeshTime } from "@/lib/datetime";
import { formatIncidentStatus, isTerminalIncident } from "@/lib/incident-status";
import {
  INTAKE_FINAL_STATUSES,
  formatReportStatus,
  getReportStatusTone,
} from "@/lib/report-status";
import { isServiceCaseFinal } from "@/lib/service-case-status";
import { useAuthGuard } from "@/lib/use-auth-guard";
import type { CitizenIncident } from "@/types/citizen-incident";
import type {
  IntakeLocation,
  IntakeLocationHistoryItem,
  IntakeLocationHistoryResponse,
  IntakeReport,
  IntakeReportDetailResponse,
  UpdateIntakeLocationResponse,
} from "@/types/intake";
import type {
  CitizenServiceCase,
  CitizenServiceCaseListResponse,
} from "@/types/service-case";

const LocationPicker = dynamic(
  () =>
    import("@/components/location/LocationPicker").then((mod) => ({
      default: mod.LocationPicker,
    })),
  {
    ssr: false,
    loading: () => (
      <div className="h-[300px] animate-pulse rounded-2xl bg-slate-100" />
    ),
  },
);

function DetailRow({
  label,
  value,
  icon: Icon,
  children,
  className = "",
}: {
  label: string;
  value: string | null;
  icon?: LucideIcon;
  children?: ReactNode;
  className?: string;
}) {
  return (
    <div className={`min-w-0 ${className}`}>
      <dt className="flex items-center gap-2 text-[11px] font-bold uppercase text-[#42547A]">
        {Icon ? <Icon className="h-4 w-4 text-[#002D62]" aria-hidden /> : null}
        {label}
      </dt>
      <dd className="mt-2 break-words text-sm font-semibold text-[#071633]">
        {children ?? value ?? "-"}
      </dd>
    </div>
  );
}

function CompactCard({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <Card className={`!rounded-2xl !bg-white shadow-sm shadow-[#002D62]/5 ${className}`}>
      {children}
    </Card>
  );
}

function ReportDetailMetric({
  label,
  value,
  icon,
  children,
}: {
  label: string;
  value: string | null;
  icon: LucideIcon;
  children?: ReactNode;
}) {
  return (
    <DetailRow
      label={label}
      value={value}
      icon={icon}
      className="border-t border-[#002D62]/10 px-5 py-4 md:border-l md:border-t-0"
    >
      {children}
    </DetailRow>
  );
}

function formatLocation(location: IntakeLocation | null | undefined) {
  if (!location) return "-";
  return (
    location.address_text ||
    location.place_name ||
    "Map location selected"
  );
}

function getActorDisplayName(item: IntakeLocationHistoryItem) {
  const actorKind = item.changed_by?.actor_kind ?? "system";
  const fullName = item.changed_by?.full_name?.trim();
  if (!fullName) return actorKind;

  const firstName = fullName.split(/\s+/).find(Boolean);
  return firstName ? `${firstName} | ${actorKind}` : actorKind;
}

function LocationHistory({ history }: { history: IntakeLocationHistoryItem[] }) {
  if (history.length === 0) {
    return <p className="text-sm text-gray-600">No location changes recorded.</p>;
  }

  return (
    <ul className="max-h-[min(24rem,45vh)] space-y-3 overflow-y-auto overscroll-y-contain pr-1">
      {history.map((item, index) => (
        <li key={`${item.changed_at}-${index}`} className="relative pl-6">
          <span
            className="absolute left-0 top-1.5 h-3 w-3 rounded-full bg-[#0B3FE8]"
            aria-hidden
          />
          <span
            className="absolute bottom-0 left-[5px] top-5 w-px bg-[#D7E4F6]"
            aria-hidden
          />
          <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
            <div className="min-w-0 pr-3">
              <p className="text-sm font-semibold capitalize text-[#002D62]">
                {formatBadgeLabel(item.change_kind)}
              </p>
              <div className="mt-1 grid gap-1 text-sm text-gray-700">
                <p className="truncate" title={formatLocation(item.location)}>
                  <span className="font-medium text-gray-900">Now:</span>{" "}
                  {formatLocation(item.location)}
                </p>
                <p className="truncate" title={formatLocation(item.previous_location)}>
                  <span className="font-medium text-gray-900">
                    Previous:
                  </span>{" "}
                  {formatLocation(item.previous_location)}
                </p>
              </div>
            </div>
            <div className="shrink-0 text-xs text-[#42547A] sm:text-right">
              <p>{formatBangladeshTime(item.changed_at)}</p>
              <p
                className="mt-1 max-w-[12rem] truncate"
                title={`${item.changed_by?.full_name ?? "System"} | ${
                  item.changed_by?.actor_kind ?? "system"
                }`}
              >
                {getActorDisplayName(item)}
              </p>
            </div>
          </div>
        </li>
      ))}
    </ul>
  );
}

function isLinkedIncidentTerminal(linkedIncident: CitizenIncident | null) {
  return linkedIncident ? isTerminalIncident(linkedIncident.status_code) : false;
}

function isReportLocationReadOnly(
  report: IntakeReport | null,
  linkedIncident: CitizenIncident | null,
  linkedServiceCase: CitizenServiceCase | null,
) {
  if (!report) return false;
  if (INTAKE_FINAL_STATUSES.has(report.intake_status)) return true;
  if (Boolean(report.final_disposition?.trim())) return true;
  if (isLinkedIncidentTerminal(linkedIncident)) return true;
  return isServiceCaseFinal(linkedServiceCase?.status_code);
}

export default function CitizenReportDetailPage() {
  const router = useRouter();
  const params = useParams();
  const reportPublicUuid = params.reportPublicUuid as string;
  const isChecking = useAuthGuard(["citizen"]);
  const [report, setReport] = useState<IntakeReport | null>(null);
  const [linkedIncident, setLinkedIncident] = useState<CitizenIncident | null>(
    null,
  );
  const [linkedServiceCase, setLinkedServiceCase] =
    useState<CitizenServiceCase | null>(null);
  const [history, setHistory] = useState<IntakeLocationHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [incidentError, setIncidentError] = useState("");
  const [locationMessage, setLocationMessage] = useState("");
  const [locationError, setLocationError] = useState("");
  const [savingLocation, setSavingLocation] = useState(false);
  const [selectedLocationDetails, setSelectedLocationDetails] =
    useState<LocationPickerSelectionDetails>({});
  const [locationForm, setLocationForm] = useState({
    latitude: "",
    longitude: "",
    addressText: "",
    placeName: "",
  });

  const loadReport = useCallback(async () => {
    setLoading(true);
    setError("");
    setIncidentError("");
    try {
      const [detailResult, historyResult, incidentsResult, serviceCasesResult] =
        await Promise.allSettled([
          apiJson<IntakeReportDetailResponse>(
            `/intake/reports/${reportPublicUuid}`,
          ),
          apiJson<IntakeLocationHistoryResponse>(
            `/intake/reports/${reportPublicUuid}/reported-location-history`,
          ),
          getMyIncidents(),
          apiGet<CitizenServiceCaseListResponse>(
            "/intake/reports/my/service-cases",
          ),
        ]);

      if (detailResult.status === "rejected") {
        throw detailResult.reason;
      }

      const nextReport = detailResult.value.report;
      setReport(nextReport);
      setHistory(
        historyResult.status === "fulfilled"
          ? historyResult.value.history ?? []
          : [],
      );

      if (incidentsResult.status === "fulfilled") {
        setLinkedIncident(
          incidentsResult.value.incidents?.find(
            (incident) => incident.intake_public_uuid === nextReport.public_uuid,
          ) ?? null,
        );
      } else {
        setLinkedIncident(null);
        if (nextReport.intake_status === "linked_to_incident") {
          setIncidentError(
            incidentsResult.reason instanceof Error
              ? incidentsResult.reason.message
              : "Could not load linked emergency incident details.",
          );
        }
      }

      if (serviceCasesResult.status === "fulfilled") {
        setLinkedServiceCase(
          serviceCasesResult.value.service_cases?.find(
            (serviceCase) =>
              serviceCase.intake_public_uuid === nextReport.public_uuid,
          ) ?? null,
        );
      } else {
        setLinkedServiceCase(null);
      }

      setLocationForm({
        latitude: nextReport.location?.latitude?.toString() ?? "",
        longitude: nextReport.location?.longitude?.toString() ?? "",
        addressText: "",
        placeName: "",
      });
      setSelectedLocationDetails({
        addressText:
          nextReport.location?.address_text ??
          nextReport.location_text ??
          undefined,
        placeName: nextReport.location?.place_name ?? undefined,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load report.");
    } finally {
      setLoading(false);
    }
  }, [reportPublicUuid]);

  const handleLocationChange = useCallback(
    (
      location: LocationPickerValue,
      details?: LocationPickerSelectionDetails,
    ) => {
      setSelectedLocationDetails(details ?? {});
      setLocationForm((current) => {
        const latitude = location.latitude.toString();
        const longitude = location.longitude.toString();
        const locationChanged =
          current.latitude !== latitude || current.longitude !== longitude;

        return {
          ...current,
          latitude,
          longitude,
          addressText: locationChanged ? "" : current.addressText,
          placeName: locationChanged ? "" : current.placeName,
        };
      });
      setLocationError("");
      setLocationMessage("");
    },
    [],
  );

  useEffect(() => {
    if (isChecking) return;
    void loadReport();
  }, [isChecking, loadReport]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  async function handleLocationSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLocationError("");
    setLocationMessage("");

    if (isReportLocationReadOnly(report, linkedIncident, linkedServiceCase)) {
      setLocationError(
        "Location updates are no longer available because this report has already been resolved.",
      );
      return;
    }

    const latitude = Number(locationForm.latitude);
    const longitude = Number(locationForm.longitude);
    const manualAddressText = locationForm.addressText;
    const manualPlaceName = locationForm.placeName;

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
              source: "user_shared",
            },
          }),
        },
      );

      setReport(data.report);
      setLocationForm({
        latitude: data.report.location?.latitude?.toString() ?? "",
        longitude: data.report.location?.longitude?.toString() ?? "",
        addressText: manualAddressText,
        placeName: manualPlaceName,
      });
      setSelectedLocationDetails({
        addressText:
          data.report.location?.address_text ??
          data.report.location_text ??
          undefined,
        placeName: data.report.location?.place_name ?? undefined,
      });
      setLocationMessage(data.message || "Reported location updated.");
      const historyData = await apiJson<IntakeLocationHistoryResponse>(
        `/intake/reports/${reportPublicUuid}/reported-location-history`,
      );
      setHistory(historyData.history ?? []);
    } catch (err) {
      setLocationError(
        err instanceof Error ? err.message : "Could not update location.",
      );
    } finally {
      setSavingLocation(false);
    }
  }

  if (isChecking) {
    return <PageLoading label="Loading report details" />;
  }

  const selectedLocation =
    Number.isFinite(Number(locationForm.latitude)) &&
    Number.isFinite(Number(locationForm.longitude)) &&
    locationForm.latitude.trim() &&
    locationForm.longitude.trim()
      ? {
          latitude: Number(locationForm.latitude),
          longitude: Number(locationForm.longitude),
        }
      : null;
  const locationReadOnly = isReportLocationReadOnly(
    report,
    linkedIncident,
    linkedServiceCase,
  );
  const selectedLocationLabel =
    locationForm.addressText.trim() ||
    selectedLocationDetails.addressText?.trim() ||
    locationForm.placeName.trim() ||
    selectedLocationDetails.placeName?.trim() ||
    "Selected map point";
  const selectedPlaceName =
    locationForm.placeName.trim() ||
    selectedLocationDetails.placeName?.trim() ||
    "";
  const showDistinctPlaceName =
    Boolean(selectedPlaceName) && selectedPlaceName !== selectedLocationLabel;

  return (
    <DashboardLayout
      title="Report Details"
      subtitle={`Report ${report?.report_code ?? reportPublicUuid}`}
      onLogout={handleLogout}
      contentClassName="min-h-0 lg:h-[calc(100dvh-14rem)] lg:overflow-hidden"
    >
      <div className="flex min-h-0 flex-col gap-3 lg:h-full">
        {error && <ErrorAlert message={error} />}
        {loading ? (
          <CompactCard>
            <CardContent>
              <LoadingSkeleton lines={6} />
            </CardContent>
          </CompactCard>
        ) : !report ? (
          <CompactCard>
            <CardContent>
              <EmptyState
                title="Report not found"
                description="The backend did not return a report for this identifier, or it is not available to this account."
              />
            </CardContent>
          </CompactCard>
        ) : (
          <div className="grid min-h-0 flex-1 gap-3 lg:grid-cols-[minmax(0,1.04fr)_minmax(0,1fr)] lg:overflow-hidden xl:grid-cols-[minmax(0,1.04fr)_minmax(360px,0.96fr)]">
              <div className="min-w-0 space-y-3 lg:min-h-0 lg:overflow-y-auto lg:overscroll-y-contain lg:pr-1">
                <CompactCard>
                  <CardContent className="!p-0">
                    <div className="border-b border-[#002D62]/10 px-4 py-3 sm:px-5">
                      <CitizenBackButton
                        href="/dashboard/citizen/reports"
                        label="Back to My Reports"
                      />
                    </div>

                    <div className="flex items-start justify-between gap-3 p-4 sm:p-5">
                      <div className="flex min-w-0 gap-3 sm:gap-4">
                        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-[#DFF2CE] text-[#2D6B1F]">
                          <FileText className="h-6 w-6" aria-hidden />
                        </div>
                        <div className="min-w-0">
                          <h2 className="text-base font-bold text-[#002D62]">
                            Report Details
                          </h2>
                          <p className="mt-2 text-xs font-bold uppercase tracking-wide text-[#006747]">
                            Report Code
                          </p>
                          <p className="mt-1 break-words text-sm font-bold text-[#002D62]">
                            {report.report_code}
                          </p>
                          <h3 className="mt-3 break-words text-xl font-bold text-[#071633]">
                            {report.summary}
                          </h3>
                          <p className="mt-2 line-clamp-3 text-sm leading-6 text-[#42547A]">
                            {report.description || "No description provided."}
                          </p>
                        </div>
                      </div>
                      <Badge tone={getReportStatusTone(report.intake_status)}>
                        {formatReportStatus(report.intake_status)}
                      </Badge>
                    </div>

                    <dl className="grid border-t border-[#002D62]/10 sm:grid-cols-2 xl:grid-cols-3">
                      <ReportDetailMetric
                        label="Category"
                        value={formatBadgeLabel(report.category_code)}
                        icon={Folder}
                      />
                      <ReportDetailMetric
                        label="Channel"
                        value={formatBadgeLabel(report.channel_code)}
                        icon={Globe2}
                      />
                      {report.urgency_type ? (
                        <ReportDetailMetric
                          label="Urgency"
                          value={formatBadgeLabel(report.urgency_type)}
                          icon={AlertTriangle}
                        />
                      ) : null}
                      <ReportDetailMetric
                        label="Reported At"
                        value={formatBangladeshTime(report.reported_at)}
                        icon={Clock3}
                      />
                      <ReportDetailMetric
                        label="Created At"
                        value={formatBangladeshTime(report.created_at)}
                        icon={CalendarClock}
                      />
                      {report.final_disposition ? (
                        <ReportDetailMetric
                          label="Final Disposition"
                          value={report.final_disposition}
                          icon={Flag}
                        />
                      ) : null}
                    </dl>

                    {report.intake_status === "linked_to_incident" ? (
                      <div className="border-t border-[#002D62]/10 p-4">
                        <div className="rounded-xl border border-[#DA291C]/15 bg-red-50 p-3 text-sm text-red-900">
                          <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                            <div>
                              <p className="font-semibold">
                                Linked to emergency incident
                              </p>
                              <p className="mt-1">
                                {linkedIncident
                                  ? `${linkedIncident.incident_code} is ${formatIncidentStatus(linkedIncident.status_code)}.`
                                  : "Incident details will appear when available to your account."}
                              </p>
                            </div>
                            {linkedIncident ? (
                              <Button
                                type="button"
                                size="sm"
                                variant="secondary"
                                onClick={() =>
                                  router.push(
                                    `/dashboard/citizen/incidents/${linkedIncident.public_uuid}`,
                                  )
                                }
                              >
                                View Incident
                              </Button>
                            ) : null}
                          </div>
                          {incidentError ? (
                            <p className="mt-2 text-xs text-red-800">
                              {incidentError}
                            </p>
                          ) : null}
                        </div>
                      </div>
                    ) : linkedIncident ? (
                      <div className="border-t border-[#002D62]/10 p-4">
                        <div className="rounded-xl border border-[#002D62]/10 bg-[#EFF6FF] p-3">
                          <p className="text-sm font-semibold text-gray-900">
                            Linked Incident
                          </p>
                          <p className="mt-1 text-sm text-gray-700">
                            {linkedIncident.incident_code} -{" "}
                            {formatIncidentStatus(linkedIncident.status_code)}
                          </p>
                        </div>
                      </div>
                    ) : null}
                  </CardContent>
                </CompactCard>

                <CompactCard>
                  <CardHeader className="border-b border-[#002D62]/10 !px-4 !py-3">
                    <div className="flex items-center justify-between gap-3">
                      <div className="flex items-center gap-3">
                        <div className="flex h-9 w-9 items-center justify-center rounded-full bg-[#EFF6FF] text-[#002D62]">
                          <History className="h-5 w-5" aria-hidden />
                        </div>
                        <h2 className="text-base font-bold text-[#002D62]">
                          Location History
                        </h2>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent className="!px-4 !py-4">
                    <LocationHistory history={history} />
                  </CardContent>
                </CompactCard>
              </div>

              <div className="min-w-0 lg:min-h-0 lg:overflow-y-auto lg:overscroll-y-contain lg:pl-1">
                <CompactCard className="overflow-hidden">
                  <CardHeader className="border-b border-[#002D62]/10 !px-4 !py-3">
                    <div className="flex items-center gap-3">
                      <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-[#006747] text-white">
                        <MapPin className="h-5 w-5" aria-hidden />
                      </div>
                      <div>
                        <h2 className="text-base font-bold text-[#002D62]">
                          {locationReadOnly
                            ? "Reported Location"
                            : "Update Reported Location"}
                        </h2>
                        <p className="mt-1 text-sm text-gray-600">
                          {locationReadOnly
                            ? "Location updates are no longer available because this report has already been resolved."
                            : "Save only the structured location object."}
                        </p>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent className="!px-4 !py-4">
                    {locationError && (
                      <div className="mb-3 rounded-xl bg-red-50 p-3 text-sm text-red-700">
                        {locationError}
                      </div>
                    )}
                    {locationMessage && (
                      <div className="mb-3 rounded-xl bg-green-50 p-3 text-sm text-green-700">
                        {locationMessage}
                      </div>
                    )}
                    {!locationReadOnly ? (
                      <form onSubmit={handleLocationSubmit} className="space-y-3">
                        <LocationPicker
                          value={selectedLocation}
                          onChange={handleLocationChange}
                          selectedAddress={locationForm.addressText}
                          selectedPlaceName={locationForm.placeName}
                          syncSearchQueryToSelectedLabel={false}
                          embedded
                          embeddedCompact
                          searchPlaceholder="Search address, place, or landmark..."
                          mapClassName="h-[clamp(200px,27vh,250px)] w-full"
                          mapWrapperClassName="w-full"
                          embeddedMapSectionClassName="mt-3 w-full shrink-0"
                          showSelectionSummary={false}
                        />
                        <div
                          className="rounded-lg border border-slate-200/80 bg-slate-50/80 px-3 py-2"
                          aria-live="polite"
                        >
                          {selectedLocation ? (
                            <div className="space-y-1">
                              <p className="text-xs font-semibold text-slate-900">
                                Selected location
                              </p>
                              <p className="text-sm font-medium leading-snug text-slate-900">
                                {selectedLocationLabel}
                              </p>
                              {showDistinctPlaceName ? (
                                <p className="text-xs text-slate-500">
                                  {selectedPlaceName}
                                </p>
                              ) : null}
                            </div>
                          ) : (
                            <div className="space-y-0.5">
                              <p className="text-xs font-semibold text-slate-900">
                                No map point selected
                              </p>
                              <p className="text-xs leading-snug text-slate-600">
                                Choose a map point before saving.
                              </p>
                            </div>
                          )}
                        </div>
                        <div className="rounded-lg border border-slate-100 bg-slate-50/40 px-3 py-2">
                          <p className="text-xs font-medium text-slate-700">
                            Optional location details
                          </p>
                          <div className="mt-2 grid gap-2 sm:grid-cols-2 lg:grid-cols-1 2xl:grid-cols-2">
                            <div>
                              <label
                                htmlFor="report-location-address"
                                className="block text-xs font-semibold text-slate-700"
                              >
                                Location Name or Address
                              </label>
                              <input
                                id="report-location-address"
                                value={locationForm.addressText}
                                onChange={(event) =>
                                  setLocationForm((current) => ({
                                    ...current,
                                    addressText: event.target.value,
                                  }))
                                }
                                className="mt-1 w-full rounded-lg border border-[#002D62]/20 bg-white px-3 py-2 text-sm text-slate-900 placeholder:text-slate-400 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35"
                                placeholder="Building, road, or landmark description"
                              />
                            </div>
                            <div>
                              <label
                                htmlFor="report-location-place"
                                className="block text-xs font-semibold text-slate-700"
                              >
                                Place Name
                              </label>
                              <input
                                id="report-location-place"
                                value={locationForm.placeName}
                                onChange={(event) =>
                                  setLocationForm((current) => ({
                                    ...current,
                                    placeName: event.target.value,
                                  }))
                                }
                                className="mt-1 w-full rounded-lg border border-[#002D62]/20 bg-white px-3 py-2 text-sm text-slate-900 placeholder:text-slate-400 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35"
                                placeholder="Optional landmark or place name"
                              />
                            </div>
                          </div>
                          <div className="mt-3 flex justify-end">
                            <Button
                              type="submit"
                              size="sm"
                              isLoading={savingLocation}
                            >
                              Save Location
                            </Button>
                          </div>
                        </div>
                      </form>
                    ) : null}
                    {locationReadOnly ? (
                      <div className="space-y-3">
                        <div className="rounded-xl border border-[#002D62]/10 bg-[#EFF6FF] p-3 text-sm text-[#002D62]">
                          Location updates are no longer available because this report has already been resolved.
                        </div>
                        {report.location ? (
                          <OpenLocationMapButton
                            latitude={report.location.latitude}
                            longitude={report.location.longitude}
                            previewKey={report.public_uuid}
                            title="Reported location"
                            addressText={report.location.address_text ?? undefined}
                            placeName={report.location.place_name ?? undefined}
                            label="Open location in map"
                            className="inline-flex text-sm font-semibold text-[#006747] hover:text-[#002D62]"
                          />
                        ) : null}
                      </div>
                    ) : null}

                  </CardContent>
                </CompactCard>
              </div>
            </div>
        )}
      </div>
    </DashboardLayout>
  );
}
