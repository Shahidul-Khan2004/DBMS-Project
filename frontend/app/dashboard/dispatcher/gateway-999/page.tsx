"use client";

import dynamic from "next/dynamic";
import Link from "next/link";
import { type ChangeEvent, type FormEvent, type ReactNode, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import {
  AlertTriangle,
  BadgeCheck,
  ClipboardList,
  Clock3,
  FileText,
  MapPin,
  PhoneCall,
  ShieldAlert,
} from "lucide-react";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { PageHeader, PageLoading } from "@/components/ui/StatusState";
import { ApiError, apiPost } from "@/lib/api";
import {
  getCurrentBangladeshDatetimeLocal,
  isValidBangladeshLocalDatetime,
  toBangladeshIsoDatetime,
} from "@/lib/datetime";
import { clearAuthSession } from "@/lib/auth-store";
import { useAuthGuard } from "@/lib/use-auth-guard";
import type {
  LocationPickerSelectionDetails,
  LocationPickerValue,
} from "@/components/location/LocationPicker";

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

type Disposition = "service_case" | "emergency_incident";

type Gateway999Payload = {
  disposition: Disposition;
  categoryCode: string;
  summary: string;
  description?: string;
  urgencyType?: "non_emergency" | "emergency" | "unknown";
  reportedAt?: string;
  location?: {
    latitude: number;
    longitude: number;
    address_text?: string;
    place_name?: string;
    source: "dispatcher_selected";
  };
  callerPhoneNumber?: string;
  callStartedAt?: string;
  incidentTitle?: string;
  incidentDescription?: string;
  severityCode?: "low" | "medium" | "high" | "critical";
  priorityLevel?: "low" | "medium" | "high" | "urgent";
};

type GatewayEntity = Record<string, unknown>;

type GatewayResponse = {
  message?: string;
  intake?: GatewayEntity;
  emergency_call?: GatewayEntity;
  service_case?: GatewayEntity;
  emergency_incident?: GatewayEntity;
  incident?: GatewayEntity;
  incident_report_link?: GatewayEntity;
  [key: string]: unknown;
};

type ResultItem = {
  title: string;
  href?: string;
  data: GatewayEntity;
};

const fieldClassName =
  "mt-1 w-full rounded-2xl border border-[#002D62]/20 bg-white px-3 py-2 text-gray-900 placeholder-gray-400 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35 disabled:bg-slate-100 disabled:text-slate-500";
const labelClassName = "block text-sm font-semibold text-slate-700";
const sectionClassName =
  "rounded-3xl border border-[#002D62]/10 bg-zinc-200 p-5 shadow-lg shadow-[#002D62]/5";
const sectionHeaderClassName =
  "flex items-center gap-3 border-b border-[#002D62]/10 pb-4";
const displayKeys = [
  "public_uuid",
  "publicUuid",
  "report_code",
  "call_code",
  "case_code",
  "incident_code",
  "intake_status",
  "status_code",
  "category_code",
  "severity_code",
  "priority_level",
  "created_at",
  "reported_at",
];

function formatApiError(error: unknown) {
  if (error instanceof ApiError) {
    const prefix = error.code ? `${error.code}: ` : "";
    const details =
      Array.isArray(error.details) && error.details.length > 0
        ? ` Details: ${error.details
            .map((detail) =>
              typeof detail === "string" ? detail : JSON.stringify(detail),
            )
            .join("; ")}`
        : "";
    return `${prefix}${error.message}${details}`;
  }

  return error instanceof Error ? error.message : "999 gateway flow failed.";
}

function getStringValue(data: GatewayEntity, key: string) {
  const value = data[key];
  return typeof value === "string" && value.trim() ? value : null;
}

function getEntityRows(data: GatewayEntity) {
  const rows = displayKeys
    .map((key) => [key, data[key]] as const)
    .filter(([, value]) => value !== undefined && value !== null && value !== "");

  if (rows.length > 0) return rows;

  return Object.entries(data)
    .filter(([, value]) => value !== undefined && value !== null && typeof value !== "object")
    .slice(0, 6);
}

function ResultCard({ item }: { item: ResultItem }) {
  const rows = getEntityRows(item.data);

  return (
    <div className="rounded-2xl border border-[#006747]/20 bg-white p-4 shadow-sm">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h3 className="text-base font-semibold text-[#002D62]">{item.title}</h3>
        {item.href ? (
          <Link
            href={item.href}
            className="rounded-full border border-[#002D62]/20 px-3 py-1 text-sm font-semibold text-[#002D62] transition-colors hover:bg-[#EFF6FF]"
          >
            Open
          </Link>
        ) : null}
      </div>

      <dl className="mt-3 grid gap-2 text-sm">
        {rows.map(([key, value]) => (
          <div
            key={key}
            className="grid gap-1 rounded-xl bg-[#EFF6FF]/70 px-3 py-2 sm:grid-cols-[150px_minmax(0,1fr)]"
          >
            <dt className="font-medium text-slate-600">{key}</dt>
            <dd className="min-w-0 break-words text-slate-900">
              {String(value)}
            </dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function Section({
  icon,
  title,
  children,
}: {
  icon: ReactNode;
  title: string;
  children: ReactNode;
}) {
  return (
    <section className={sectionClassName}>
      <div className={sectionHeaderClassName}>
        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl bg-[#002D62] text-white">
          {icon}
        </div>
        <h2 className="text-lg font-bold text-[#002D62]">{title}</h2>
      </div>
      <div className="mt-5 space-y-4">{children}</div>
    </section>
  );
}

function getResultItems(result: GatewayResponse | null): ResultItem[] {
  if (!result) return [];

  const emergencyIncident = result.emergency_incident ?? result.incident;
  const incidentUuid =
    emergencyIncident && typeof emergencyIncident === "object"
      ? getStringValue(emergencyIncident, "public_uuid")
      : null;

  return [
    result.intake && typeof result.intake === "object"
      ? { title: "Intake", data: result.intake }
      : null,
    result.emergency_call && typeof result.emergency_call === "object"
      ? { title: "Emergency Call", data: result.emergency_call }
      : null,
    result.service_case && typeof result.service_case === "object"
      ? { title: "Service Case", data: result.service_case }
      : null,
    emergencyIncident && typeof emergencyIncident === "object"
      ? {
          title: "Emergency Incident",
          data: emergencyIncident,
          href: incidentUuid
            ? `/dashboard/dispatcher/incidents/${incidentUuid}`
            : undefined,
        }
      : null,
  ].filter((item): item is ResultItem => Boolean(item));
}

export default function Gateway999Page() {
  const router = useRouter();
  const isChecking = useAuthGuard(["dispatcher", "system_admin"]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<GatewayResponse | null>(null);
  const [form, setForm] = useState({
    disposition: "emergency_incident" as Disposition,
    categoryCode: "medical",
    summary: "",
    description: "",
    urgencyType: "emergency" as "non_emergency" | "emergency" | "unknown",
    callerPhoneNumber: "",
    callStartedAt: getCurrentBangladeshDatetimeLocal(),
    reportedAt: getCurrentBangladeshDatetimeLocal(),
    severityCode: "high" as "low" | "medium" | "high" | "critical",
    priorityLevel: "medium" as "low" | "medium" | "high" | "urgent",
    incidentTitle: "",
    incidentDescription: "",
    latitude: "",
    longitude: "",
    addressText: "",
    placeName: "",
  });

  const resultItems = useMemo(() => getResultItems(result), [result]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  function updateField(
    event: ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>,
  ) {
    const { name, value } = event.target;
    setForm((current) => ({ ...current, [name]: value }));
    setError("");
  }

  function handleLocationChange(
    location: LocationPickerValue,
    details?: LocationPickerSelectionDetails,
  ) {
    setForm((current) => ({
      ...current,
      latitude: location.latitude.toString(),
      longitude: location.longitude.toString(),
      addressText: details?.addressText ?? current.addressText,
      placeName: details?.placeName ?? current.placeName,
    }));
    setError("");
  }

  function clearMapLocation() {
    setForm((current) => ({
      ...current,
      latitude: "",
      longitude: "",
      addressText: "",
      placeName: "",
    }));
    setError("");
  }

  function buildPayload(): Gateway999Payload | null {
    const summary = form.summary.trim();
    const categoryCode = form.categoryCode.trim();
    const description = form.description.trim();
    const callerPhoneNumber = form.callerPhoneNumber.trim();
    const incidentTitle = form.incidentTitle.trim();
    const incidentDescription = form.incidentDescription.trim();
    const addressText = form.addressText.trim();
    const placeName = form.placeName.trim();

    if (!form.disposition) {
      setError("Choose a disposition before completing the 999 flow.");
      return null;
    }

    if (!categoryCode) {
      setError("Choose a report category.");
      return null;
    }

    if (!summary) {
      setError("Add a call summary.");
      return null;
    }

    if (form.callStartedAt && !isValidBangladeshLocalDatetime(form.callStartedAt)) {
      setError("Call started time must be a valid Bangladesh date and time.");
      return null;
    }

    if (form.reportedAt && !isValidBangladeshLocalDatetime(form.reportedAt)) {
      setError("Reported time must be a valid Bangladesh date and time.");
      return null;
    }

    const latitude = Number(form.latitude);
    const longitude = Number(form.longitude);

    if (!Number.isFinite(latitude) || !Number.isFinite(longitude)) {
      setError("Choose a valid incident location on the map.");
      return null;
    }

    if (addressText.length > 255) {
      setError("Location address must be 255 characters or fewer.");
      return null;
    }

    if (placeName.length > 150) {
      setError("Place name must be 150 characters or fewer.");
      return null;
    }

    if (form.disposition === "emergency_incident" && !form.severityCode) {
      setError("Choose a severity for emergency incident disposition.");
      return null;
    }

    const payload: Gateway999Payload = {
      disposition: form.disposition,
      categoryCode,
      summary,
      description: description || undefined,
      urgencyType: form.urgencyType,
      reportedAt: toBangladeshIsoDatetime(form.reportedAt),
      callerPhoneNumber: callerPhoneNumber || undefined,
      callStartedAt: toBangladeshIsoDatetime(form.callStartedAt),
      incidentTitle: incidentTitle || undefined,
      incidentDescription: incidentDescription || undefined,
      severityCode:
        form.disposition === "emergency_incident"
          ? form.severityCode
          : undefined,
      priorityLevel:
        form.disposition === "service_case" && form.priorityLevel
          ? form.priorityLevel
          : undefined,
    };

    payload.location = {
      latitude,
      longitude,
      address_text: addressText || undefined,
      place_name: placeName || undefined,
      source: "dispatcher_selected",
    };

    return payload;
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setResult(null);

    const payload = buildPayload();
    if (!payload) return;

    setLoading(true);
    try {
      const data = await apiPost<GatewayResponse, Gateway999Payload>(
        "/operations/gateway/999/intake-and-incident",
        payload,
      );
      setResult(data);
      setForm((current) => ({
        ...current,
        summary: "",
        description: "",
        callerPhoneNumber: "",
        callStartedAt: getCurrentBangladeshDatetimeLocal(),
        reportedAt: getCurrentBangladeshDatetimeLocal(),
        incidentTitle: "",
        incidentDescription: "",
        latitude: "",
        longitude: "",
        addressText: "",
        placeName: "",
      }));
    } catch (err) {
      setError(formatApiError(err));
    } finally {
      setLoading(false);
    }
  }

  if (isChecking) {
    return <PageLoading label="Loading 999 gateway" />;
  }

  const selectedLocation =
    form.latitude.trim() &&
    form.longitude.trim() &&
    Number.isFinite(Number(form.latitude)) &&
    Number.isFinite(Number(form.longitude))
      ? {
          latitude: Number(form.latitude),
          longitude: Number(form.longitude),
        }
      : null;

  return (
    <DashboardLayout
      title="999 Gateway"
      subtitle="Rapid call intake, location capture, and immediate disposition"
      onLogout={handleLogout}
    >
      <div className="mx-auto max-w-screen-2xl space-y-6">
        <PageHeader
          eyebrow="999 call intake"
          title="Rapid emergency intake"
          description="Capture call facts, disposition, and location before sending the supported gateway flow to the backend."
        />

        {error && <ErrorAlert message={error} />}

        {result && (
          <section className="rounded-3xl border border-[#006747]/20 bg-[#F0F7F4] p-5 shadow-lg shadow-[#006747]/10">
            <div className="flex items-start gap-3">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl bg-[#006747] text-white">
                <BadgeCheck className="h-5 w-5" aria-hidden />
              </div>
              <div>
                <h2 className="text-lg font-bold text-[#002D62]">
                  {result.message || "999 intake and incident flow completed"}
                </h2>
                <p className="mt-1 text-sm text-slate-700">
                  Created backend records returned by the gateway endpoint.
                </p>
              </div>
            </div>

            {resultItems.length > 0 ? (
              <div className="mt-5 grid gap-4 lg:grid-cols-2">
                {resultItems.map((item) => (
                  <ResultCard key={item.title} item={item} />
                ))}
              </div>
            ) : null}
          </section>
        )}

        <form onSubmit={handleSubmit} className="grid gap-6 xl:grid-cols-[minmax(0,0.92fr)_minmax(480px,1.08fr)]">
          <div className="space-y-6">
            <Section
              icon={<PhoneCall className="h-5 w-5" aria-hidden />}
              title="Call Information"
            >
              <div className="grid gap-4 md:grid-cols-3">
                <div>
                  <label className={labelClassName}>Caller Phone Number</label>
                  <input
                    name="callerPhoneNumber"
                    value={form.callerPhoneNumber}
                    onChange={updateField}
                    className={fieldClassName}
                    placeholder="01700000000"
                  />
                </div>
                <div>
                  <label className={labelClassName}>Call Started At</label>
                  <input
                    type="datetime-local"
                    name="callStartedAt"
                    value={form.callStartedAt}
                    onChange={updateField}
                    className={fieldClassName}
                  />
                </div>
                <div>
                  <label className={labelClassName}>Reported At</label>
                  <input
                    type="datetime-local"
                    name="reportedAt"
                    value={form.reportedAt}
                    onChange={updateField}
                    className={fieldClassName}
                  />
                </div>
              </div>
            </Section>

            <Section
              icon={<ClipboardList className="h-5 w-5" aria-hidden />}
              title="Report Information"
            >
              <div className="grid gap-4 md:grid-cols-2">
                <div>
                  <label className={labelClassName}>Category Code</label>
                  <select
                    name="categoryCode"
                    value={form.categoryCode}
                    onChange={updateField}
                    className={fieldClassName}
                    required
                  >
                    <option value="medical">Medical</option>
                    <option value="fire">Fire</option>
                    <option value="crime_public_safety">Crime / Public Safety</option>
                    <option value="natural_disaster">Natural Disaster</option>
                    <option value="infrastructure_emergency">Infrastructure Emergency</option>
                    <option value="relief_request">Relief Request</option>
                    <option value="blood_request">Blood Request</option>
                  </select>
                </div>
                <div>
                  <label className={labelClassName}>Urgency Type</label>
                  <select
                    name="urgencyType"
                    value={form.urgencyType}
                    onChange={updateField}
                    className={fieldClassName}
                  >
                    <option value="emergency">Emergency</option>
                    <option value="unknown">Unknown</option>
                    <option value="non_emergency">Non-emergency</option>
                  </select>
                </div>
              </div>

              <div>
                <label className={labelClassName}>Summary</label>
                <input
                  name="summary"
                  value={form.summary}
                  onChange={updateField}
                  className={fieldClassName}
                  placeholder="Caller reports smoke at building entrance"
                  maxLength={255}
                  required
                />
              </div>

              <div>
                <label className={labelClassName}>Description</label>
                <textarea
                  name="description"
                  value={form.description}
                  onChange={updateField}
                  className={fieldClassName}
                  rows={4}
                  placeholder="Call-taker notes, visible hazards, people involved, response requested"
                />
              </div>
            </Section>

            <Section
              icon={<ShieldAlert className="h-5 w-5" aria-hidden />}
              title="Disposition"
            >
              <div className="grid gap-3 sm:grid-cols-2">
                {(
                  [
                    {
                      value: "emergency_incident",
                      title: "Emergency Incident",
                      copy: "Creates the 999 emergency branch with severity.",
                      icon: <AlertTriangle className="h-5 w-5" aria-hidden />,
                    },
                    {
                      value: "service_case",
                      title: "Service Case",
                      copy: "Creates a service case after intake.",
                      icon: <FileText className="h-5 w-5" aria-hidden />,
                    },
                  ] as const
                ).map((option) => (
                  <label
                    key={option.value}
                    className={`cursor-pointer rounded-2xl border p-4 transition-colors ${
                      form.disposition === option.value
                        ? "border-[#DA291C]/50 bg-red-50 text-[#002D62]"
                        : "border-[#002D62]/10 bg-white text-slate-700 hover:bg-[#EFF6FF]"
                    }`}
                  >
                    <input
                      type="radio"
                      name="disposition"
                      value={option.value}
                      checked={form.disposition === option.value}
                      onChange={updateField}
                      className="sr-only"
                      required
                    />
                    <span className="flex items-center gap-3 font-bold">
                      {option.icon}
                      {option.title}
                    </span>
                    <span className="mt-2 block text-sm leading-5 text-slate-600">
                      {option.copy}
                    </span>
                  </label>
                ))}
              </div>
            </Section>

            <Section
              icon={<Clock3 className="h-5 w-5" aria-hidden />}
              title="Emergency/Service Case Details"
            >
              <div className="grid gap-4 md:grid-cols-2">
                {form.disposition === "emergency_incident" ? (
                  <div>
                    <label className={labelClassName}>Severity Code</label>
                    <select
                      name="severityCode"
                      value={form.severityCode}
                      onChange={updateField}
                      className={fieldClassName}
                      required
                    >
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                      <option value="critical">Critical</option>
                    </select>
                  </div>
                ) : (
                  <div>
                    <label className={labelClassName}>Priority Level</label>
                    <select
                      name="priorityLevel"
                      value={form.priorityLevel}
                      onChange={updateField}
                      className={fieldClassName}
                    >
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                      <option value="urgent">Urgent</option>
                    </select>
                  </div>
                )}

                <div>
                  <label className={labelClassName}>Incident Title</label>
                  <input
                    name="incidentTitle"
                    value={form.incidentTitle}
                    onChange={updateField}
                    className={fieldClassName}
                    placeholder="Optional title override"
                    maxLength={255}
                  />
                </div>
              </div>

              <div>
                <label className={labelClassName}>Incident Description</label>
                <textarea
                  name="incidentDescription"
                  value={form.incidentDescription}
                  onChange={updateField}
                  className={fieldClassName}
                  rows={4}
                  placeholder="Optional branch-specific description override"
                />
              </div>
            </Section>

            <div className="flex flex-wrap gap-3">
              <Button type="submit" isLoading={loading}>
                Complete 999 Flow
              </Button>
              <Button
                type="button"
                variant="secondary"
                onClick={() => router.push("/dashboard/dispatcher")}
              >
                Cancel
              </Button>
            </div>
          </div>

          <Section
            icon={<MapPin className="h-5 w-5" aria-hidden />}
            title="Location"
          >
            <div className="grid gap-4 md:grid-cols-2">
              <div>
                <label className={labelClassName}>Address Text</label>
                <input
                  name="addressText"
                  value={form.addressText}
                  onChange={updateField}
                  className={fieldClassName}
                  placeholder="Optional address or landmark"
                  maxLength={255}
                />
              </div>
              <div>
                <label className={labelClassName}>Place Name</label>
                <input
                  name="placeName"
                  value={form.placeName}
                  onChange={updateField}
                  className={fieldClassName}
                  placeholder="Optional place name"
                  maxLength={150}
                />
              </div>
            </div>

            <LocationPicker
              value={selectedLocation}
              onChange={handleLocationChange}
              selectedAddress={form.addressText}
              selectedPlaceName={form.placeName}
            />

            <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl bg-white px-4 py-3 text-sm text-slate-700">
              <p>
                {selectedLocation
                  ? "Structured location object is ready with dispatcher_selected source."
                  : "Choose one map point before completing the 999 flow."}
              </p>
              <Button
                type="button"
                variant="secondary"
                size="sm"
                onClick={clearMapLocation}
                disabled={!selectedLocation || loading}
              >
                Clear Location
              </Button>
            </div>
          </Section>
        </form>
      </div>
    </DashboardLayout>
  );
}
