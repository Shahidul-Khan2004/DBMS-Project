"use client";

import dynamic from "next/dynamic";
import { type FormEvent, useCallback, useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { Clock3, History, MapPin } from "lucide-react";
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
import { formatBangladeshTime } from "@/lib/datetime";
import { useAuthGuard } from "@/lib/use-auth-guard";
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
      <div className="h-[420px] animate-pulse rounded-2xl bg-slate-100" />
    ),
  },
);

function DetailRow({ label, value }: { label: string; value: string | null }) {
  return (
    <div>
      <dt className="text-sm font-medium text-gray-600">{label}</dt>
      <dd className="mt-1 break-words text-sm text-gray-900">{value || "-"}</dd>
    </div>
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
    <dl className="grid gap-3 rounded-2xl border border-[#002D62]/10 bg-white p-4 sm:grid-cols-2">
      <DetailRow label="Address Text" value={location.address_text} />
      <DetailRow label="Place Name" value={location.place_name} />
      <DetailRow label="Source" value={formatBadgeLabel(location.source)} />
      <DetailRow label="Location UUID" value={location.public_uuid} />
    </dl>
  );
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
              <div className="mt-2 grid gap-2 text-sm text-gray-700">
                <p>
                  <span className="font-medium text-gray-900">Location:</span>{" "}
                  {formatLocation(item.location)}
                </p>
                <p>
                  <span className="font-medium text-gray-900">
                    Previous Location:
                  </span>{" "}
                  {formatLocation(item.previous_location)}
                </p>
              </div>
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

export default function CitizenReportDetailPage() {
  const router = useRouter();
  const params = useParams();
  const reportPublicUuid = params.reportPublicUuid as string;
  const isChecking = useAuthGuard(["citizen"]);
  const [report, setReport] = useState<IntakeReport | null>(null);
  const [history, setHistory] = useState<IntakeLocationHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
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
    try {
      const [detailData, historyData] = await Promise.all([
        apiJson<IntakeReportDetailResponse>(
          `/intake/reports/${reportPublicUuid}`,
        ),
        apiJson<IntakeLocationHistoryResponse>(
          `/intake/reports/${reportPublicUuid}/reported-location-history`,
        ),
      ]);

      const nextReport = detailData.report;
      setReport(nextReport);
      setHistory(historyData.history ?? []);
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

  return (
    <DashboardLayout
      title="Report Details"
      subtitle={`Report ${report?.report_code ?? reportPublicUuid}`}
      onLogout={handleLogout}
    >
      <div className="space-y-6">
        <Button
          type="button"
          variant="secondary"
          onClick={() => router.push("/dashboard/citizen/reports")}
        >
          Back to My Reports
        </Button>

        {error && <ErrorAlert message={error} />}

        <Card className="shadow-md">
          <CardHeader>
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-[#002D62] text-white">
                <Clock3 className="h-5 w-5" aria-hidden />
              </div>
              <h2 className="text-lg font-semibold text-[#002D62]">
                Report Snapshot
              </h2>
            </div>
          </CardHeader>
          <CardContent>
            {loading ? (
              <LoadingSkeleton lines={6} />
            ) : !report ? (
              <EmptyState
                title="Report not found"
                description="The backend did not return a report for this identifier, or it is not available to this account."
              />
            ) : (
              <div className="space-y-6">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                  <div>
                    <p className="text-sm font-bold uppercase tracking-wide text-gray-600">
                      Report ID
                    </p>
                    <p className="mt-0.5 text-sm text-gray-600">
                      {report.report_code}
                    </p>
                    <h3 className="mt-1 text-xl font-semibold text-gray-900">
                      {report.summary}
                    </h3>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Badge tone={report.intake_status}>
                      {formatBadgeLabel(report.intake_status)}
                    </Badge>
                    <Badge tone={report.urgency_type}>
                      {formatBadgeLabel(report.urgency_type)}
                    </Badge>
                  </div>
                </div>

                <p className="whitespace-pre-wrap text-sm leading-6 text-gray-700">
                  {report.description || "No description provided."}
                </p>

                <dl className="grid gap-4 sm:grid-cols-2">
                  <DetailRow label="Status" value={formatBadgeLabel(report.intake_status)} />
                  <DetailRow label="Urgency" value={formatBadgeLabel(report.urgency_type)} />
                  <DetailRow
                    label="Category"
                    value={formatBadgeLabel(report.category_code)}
                  />
                  <DetailRow label="Channel" value={formatBadgeLabel(report.channel_code)} />
                  <DetailRow label="Location" value={formatLocation(report.location)} />
                  <DetailRow label="Location Text" value={report.location_text} />
                  <DetailRow label="Reported At" value={formatBangladeshTime(report.reported_at)} />
                  <DetailRow label="Created At" value={formatBangladeshTime(report.created_at)} />
                  <DetailRow label="Updated At" value={formatBangladeshTime(report.updated_at)} />
                  <DetailRow label="Final Disposition" value={report.final_disposition} />
                  <DetailRow label="Public UUID" value={report.public_uuid} />
                </dl>

                <div>
                  <h3 className="mb-3 text-sm font-semibold text-[#002D62]">
                    Structured Location Object
                  </h3>
                  <LocationObjectDetails location={report.location} />
                </div>

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

                {report.incident_code && (
                  <div className="rounded-2xl border border-[#002D62]/10 bg-[#EFF6FF] p-4">
                    <h3 className="text-sm font-semibold text-gray-900">
                      Linked Incident
                    </h3>
                    <p className="mt-1 text-sm text-gray-700">
                      {report.incident_code} -{" "}
                      {formatBadgeLabel(report.incident_status_code)}
                    </p>
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>

        {report && (
          <Card className="shadow-md">
            <CardHeader>
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-[#006747] text-white">
                  <MapPin className="h-5 w-5" aria-hidden />
                </div>
                <div>
                  <h2 className="text-lg font-semibold text-[#002D62]">
                    Update Reported Location
                  </h2>
                  <p className="mt-1 text-sm text-gray-600">
                    This sends only a structured location object for the report.
                  </p>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {locationError && (
                <div className="mb-4 rounded-2xl bg-red-50 p-3 text-sm text-red-700">
                  {locationError}
                </div>
              )}
              {locationMessage && (
                <div className="mb-4 rounded-2xl bg-green-50 p-3 text-sm text-green-700">
                  {locationMessage}
                </div>
              )}
              <form onSubmit={handleLocationSubmit} className="space-y-4">
                <LocationPicker
                  value={selectedLocation}
                  onChange={handleLocationChange}
                  selectedAddress={locationForm.addressText}
                  selectedPlaceName={locationForm.placeName}
                  syncSearchQueryToSelectedLabel={false}
                />
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
                <Button type="submit" isLoading={savingLocation}>
                  Save Location
                </Button>
              </form>
            </CardContent>
          </Card>
        )}

        <Card className="shadow-md">
          <CardHeader>
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-[#EFF6FF] text-[#002D62]">
                <History className="h-5 w-5" aria-hidden />
              </div>
              <h2 className="text-lg font-semibold text-[#002D62]">
                Location History
              </h2>
            </div>
          </CardHeader>
          <CardContent>
            {loading ? <LoadingSkeleton lines={4} /> : <LocationHistory history={history} />}
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
}
