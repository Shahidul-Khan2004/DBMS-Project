"use client";

import dynamic from "next/dynamic";
import { type FormEvent, type ReactNode, useCallback, useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import {
  AlertTriangle,
  CalendarClock,
  ClipboardList,
  Clock3,
  FileText,
  Flag,
  Folder,
  Globe2,
  History,
  MapPin,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardContent, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import { EmptyState, PageLoading } from "@/components/ui/StatusState";
import type {
  LocationPickerSelectionDetails,
  LocationPickerValue,
} from "@/components/location/LocationPicker";
import { apiJson } from "@/lib/api";
import { clearAuthSession } from "@/lib/auth-store";
import { getMyIncidents } from "@/lib/citizen-incidents-api";
import { formatBangladeshTime } from "@/lib/datetime";
import { formatIncidentStatus, isTerminalIncident } from "@/lib/incident-status";
import { formatReportStatus, getReportStatusTone } from "@/lib/report-status";
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

function LocationObjectDetails({
  location,
}: {
  location: IntakeLocation | null | undefined;
}) {
  if (!location) {
    return (
      <div className="rounded-2xl border border-dashed border-[#002D62]/20 bg-white p-4 text-sm text-gray-600">
        No structured reported location is stored for this report.
      </div>
    );
  }

  return (
    <dl className="grid gap-3 rounded-xl border border-[#002D62]/10 bg-white p-3 sm:grid-cols-2">
      <DetailRow label="Address Text" value={location.address_text} />
      <DetailRow label="Place Name" value={location.place_name} />
      <DetailRow label="Source" value={formatBadgeLabel(location.source)} />
    </dl>
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
    <ul className="space-y-3">
      {history.slice(0, 5).map((item, index) => (
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
      {history.length > 5 ? (
        <li className="pt-3 text-xs text-[#42547A]">
          Showing latest 5 of {history.length} location changes.
        </li>
      ) : null}
    </ul>
  );
}

function isLinkedIncidentTerminal(
  report: IntakeReport | null,
  linkedIncident: CitizenIncident | null,
) {
  return (
    Boolean(report?.incident_is_terminal) ||
    isTerminalIncident(report?.incident_status_code) ||
    (linkedIncident ? isTerminalIncident(linkedIncident.status_code) : false)
  );
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
  const [history, setHistory] = useState<IntakeLocationHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [incidentError, setIncidentError] = useState("");
  const [locationMessage, setLocationMessage] = useState("");
  const [locationError, setLocationError] = useState("");
  const [savingLocation, setSavingLocation] = useState(false);
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
      const [detailResult, historyResult, incidentsResult] =
        await Promise.allSettled([
        apiJson<IntakeReportDetailResponse>(
          `/intake/reports/${reportPublicUuid}`,
        ),
        apiJson<IntakeLocationHistoryResponse>(
          `/intake/reports/${reportPublicUuid}/reported-location-history`,
        ),
        getMyIncidents(),
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

      setLocationForm({
        latitude: nextReport.location?.latitude?.toString() ?? "",
        longitude: nextReport.location?.longitude?.toString() ?? "",
        addressText:
          nextReport.location?.address_text ?? nextReport.location_text ?? "",
        placeName: nextReport.location?.place_name ?? "",
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

    if (isLinkedIncidentTerminal(report, linkedIncident)) {
      setLocationError(
        "This report is linked to a final incident, so its reported location is view-only.",
      );
      return;
    }

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
              source: "user_shared",
            },
          }),
        },
      );

      setReport(data.report);
      setLocationForm({
        latitude: data.report.location?.latitude?.toString() ?? "",
        longitude: data.report.location?.longitude?.toString() ?? "",
        addressText:
          data.report.location?.address_text ?? data.report.location_text ?? "",
        placeName: data.report.location?.place_name ?? "",
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
  const linkedIncidentTerminal = isLinkedIncidentTerminal(report, linkedIncident);

  return (
    <DashboardLayout
      title="Report Details"
      subtitle={`Report ${report?.report_code ?? reportPublicUuid}`}
      onLogout={handleLogout}
    >
      <div className="space-y-5">
        <Button
          type="button"
          variant="secondary"
          size="sm"
          className="h-9 rounded-full border border-[#002D62]/15 bg-white px-3 text-[#002D62] shadow-sm shadow-[#002D62]/5"
          onClick={() => router.push("/dashboard/citizen/reports")}
        >
          Back to My Reports
        </Button>

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
          <>
            <div className="grid items-start gap-5 xl:grid-cols-[minmax(0,1.04fr)_minmax(420px,0.96fr)]">
              <div className="space-y-4">
                <CompactCard>
                  <CardContent className="!p-0">
                    <div className="flex items-start justify-between gap-4 p-5">
                      <div className="flex min-w-0 gap-4">
                        <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-full bg-[#DFF2CE] text-[#2D6B1F]">
                          <FileText className="h-6 w-6" aria-hidden />
                        </div>
                        <div className="min-w-0">
                          <h2 className="text-base font-bold text-[#002D62]">
                            Report Details
                          </h2>
                          <p className="mt-3 text-xs font-bold uppercase tracking-wide text-[#006747]">
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

                    <dl className="grid border-t border-[#002D62]/10 sm:grid-cols-2 lg:grid-cols-3">
                      <ReportDetailMetric label="Status" value={null} icon={ClipboardList}>
                        <Badge tone={getReportStatusTone(report.intake_status)} size="compact">
                          {formatReportStatus(report.intake_status)}
                        </Badge>
                      </ReportDetailMetric>
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
                      <ReportDetailMetric
                        label="Urgency"
                        value={formatBadgeLabel(report.urgency_type)}
                        icon={AlertTriangle}
                      />
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
                      <ReportDetailMetric
                        label="Final Disposition"
                        value={report.final_disposition}
                        icon={Flag}
                      />
                    </dl>

                    {report.intake_status === "linked_to_incident" ? (
                      <div className="border-t border-[#002D62]/10 p-5">
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
                      <div className="border-t border-[#002D62]/10 p-5">
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
                  <CardHeader className="border-b border-[#002D62]/10 !px-5 !py-4">
                    <div className="flex items-center justify-between gap-3">
                      <div className="flex items-center gap-3">
                        <div className="flex h-10 w-10 items-center justify-center rounded-full bg-[#EFF6FF] text-[#002D62]">
                          <History className="h-5 w-5" aria-hidden />
                        </div>
                        <h2 className="text-base font-bold text-[#002D62]">
                          Location History
                        </h2>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent className="!px-5 !py-5">
                    <LocationHistory history={history} />
                  </CardContent>
                </CompactCard>
              </div>

              <div className="space-y-4">
                <CompactCard>
                  <CardHeader className="border-b border-[#002D62]/10 !px-5 !py-4">
                    <div className="flex items-center gap-3">
                      <div className="flex h-12 w-12 items-center justify-center rounded-full bg-[#006747] text-white">
                        <MapPin className="h-6 w-6" aria-hidden />
                      </div>
                      <div>
                        <h2 className="text-base font-bold text-[#002D62]">
                          {linkedIncidentTerminal
                            ? "Reported Location"
                            : "Update Reported Location"}
                        </h2>
                        <p className="mt-1 text-sm text-gray-600">
                          {linkedIncidentTerminal
                            ? "This report is linked to a final incident and is view-only."
                            : "Save only the structured location object."}
                        </p>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent className="!px-5 !py-4">
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

                    {!linkedIncidentTerminal ? (
                      <form onSubmit={handleLocationSubmit} className="space-y-3">
                        <LocationPicker
                          value={selectedLocation}
                          onChange={handleLocationChange}
                          selectedAddress={locationForm.addressText}
                          selectedPlaceName={locationForm.placeName}
                          syncSearchQueryToSelectedLabel={false}
                          embedded
                          embeddedCompact
                          mapClassName="h-[300px] w-full"
                          showSelectionSummary={false}
                        />
                        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-1 2xl:grid-cols-2">
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
                              className="mt-1 w-full rounded-xl border border-[#002D62]/20 bg-white px-3 py-2 text-gray-900"
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
                              className="mt-1 w-full rounded-xl border border-[#002D62]/20 bg-white px-3 py-2 text-gray-900"
                              placeholder="Optional place name"
                            />
                          </div>
                        </div>
                        <Button type="submit" size="sm" isLoading={savingLocation}>
                          Save Location
                        </Button>
                      </form>
                    ) : null}

                    <div className={linkedIncidentTerminal ? "" : "mt-4"}>
                      <h3 className="mb-2 text-sm font-semibold text-[#002D62]">
                        Structured Location
                      </h3>
                      <LocationObjectDetails location={report.location} />
                    </div>
                    {report.location ? (
                      <a
                        href={`https://www.openstreetmap.org/?mlat=${report.location.latitude}&mlon=${report.location.longitude}#map=16/${report.location.latitude}/${report.location.longitude}`}
                        target="_blank"
                        rel="noreferrer"
                        className="mt-3 inline-flex text-sm font-semibold text-[#006747] hover:text-[#002D62]"
                      >
                        Open location in map
                      </a>
                    ) : null}
                  </CardContent>
                </CompactCard>
              </div>
            </div>
          </>
        )}
      </div>
    </DashboardLayout>
  );
}
