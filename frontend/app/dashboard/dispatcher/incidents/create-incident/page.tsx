"use client";

import Link from "next/link";
import { useCallback, useMemo, useState } from "react";
import type { FormEvent } from "react";
import { useRouter } from "next/navigation";
import { toast } from "sonner";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { DispatcherOpsShell } from "@/components/dispatcher/DispatcherOpsShell";
import {
  CreateStandaloneIncidentDetailsPanel,
  CreateStandaloneIncidentLocationPanel,
  CreateStandaloneIncidentWorkspace,
  type SelectedIncidentLocation,
  type SeverityCode,
} from "@/components/dispatcher/incidents/create";
import {
  getValidReportedCoordinates,
} from "@/components/dispatcher/triage/reportedLocationCoords";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { PageLoading } from "@/components/ui/StatusState";
import { ensureAuthSession } from "@/lib/api";
import { clearAuthSession } from "@/lib/auth-store";
import { useDispatcherWorkspaceGuard } from "@/lib/use-dispatcher-workspace-guard";
import {
  DISPATCHER_DASHBOARD_SUBTITLE,
  DISPATCHER_DASHBOARD_TITLE,
} from "@/lib/dispatcher-dashboard";
import { mapCreateStandaloneIncidentError } from "@/lib/create-standalone-incident-errors";
import {
  getCurrentBangladeshDatetimeLocal,
  isValidBangladeshLocalDatetime,
  toBangladeshIsoDatetime,
} from "@/lib/datetime";
import { createStandaloneIncident } from "@/lib/operations-incident-api";
import type { CreateStandaloneIncidentPayload } from "@/types/operations-incident";

export default function CreateStandaloneIncidentPage() {
  const router = useRouter();

  const [categoryCode, setCategoryCode] = useState("");
  const [severityCode, setSeverityCode] = useState<SeverityCode | "">("");
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [reportedAt, setReportedAt] = useState(getCurrentBangladeshDatetimeLocal());
  const [selectedLocation, setSelectedLocation] =
    useState<SelectedIncidentLocation | null>(null);
  const [addressText, setAddressText] = useState("");
  const [placeName, setPlaceName] = useState("");

  const isChecking = useDispatcherWorkspaceGuard("incidentMutate");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [showValidation, setShowValidation] = useState(false);

  const redirectToLogin = useCallback(() => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/auth/login");
  }, [router]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  const validLocationCoords = useMemo(
    () =>
      selectedLocation
        ? getValidReportedCoordinates(
            selectedLocation.latitude,
            selectedLocation.longitude,
          )
        : null,
    [selectedLocation],
  );

  const canSubmit =
    Boolean(categoryCode.trim()) &&
    Boolean(severityCode) &&
    Boolean(title.trim()) &&
    validLocationCoords != null &&
    !isSubmitting;

  const handleLocationChange = useCallback(
    (location: SelectedIncidentLocation | null) => {
      setSelectedLocation(location);
      if (!location) {
        setAddressText("");
        setPlaceName("");
      }
      setError("");
    },
    [],
  );

  const handleAddressTextChange = useCallback((value: string) => {
    setAddressText(value);
    setSelectedLocation((current) =>
      current ? { ...current, addressText: value.trim() || undefined } : current,
    );
    setError("");
  }, []);

  const handlePlaceNameChange = useCallback((value: string) => {
    setPlaceName(value);
    setSelectedLocation((current) =>
      current ? { ...current, placeName: value.trim() || undefined } : current,
    );
    setError("");
  }, []);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setShowValidation(true);

    const titleText = title.trim();
    const descriptionText = description.trim();

    if (!categoryCode.trim()) {
      setError("Choose a category for the incident.");
      return;
    }

    if (!severityCode) {
      setError("Choose a severity level for the incident.");
      return;
    }

    if (!titleText) {
      setError("Add a title for the incident.");
      return;
    }

    if (!validLocationCoords) {
      setError("Select a confirmed incident location before creating.");
      return;
    }

    if (reportedAt && !isValidBangladeshLocalDatetime(reportedAt)) {
      setError("Reported time must be a valid Bangladesh date and time.");
      return;
    }

    const manualAddress = addressText.trim();
    const manualPlace = placeName.trim();
    const pickerAddress = selectedLocation?.addressText?.trim() ?? "";
    const pickerPlace = selectedLocation?.placeName?.trim() ?? "";

    const resolvedAddress =
      manualAddress || pickerAddress || "Selected map point";
    const resolvedPlace = manualPlace || pickerPlace || null;

    if (resolvedAddress.length > 255) {
      setError("Location address must be 255 characters or fewer.");
      return;
    }

    if (resolvedPlace && resolvedPlace.length > 150) {
      setError("Place name must be 150 characters or fewer.");
      return;
    }

    const token = await ensureAuthSession();
    if (!token) {
      redirectToLogin();
      return;
    }

    const locationPayload: CreateStandaloneIncidentPayload["location"] = {
      latitude: validLocationCoords.latitude,
      longitude: validLocationCoords.longitude,
      address_text: resolvedAddress,
      place_name: resolvedPlace,
      source: "dispatcher_selected",
    };

    const body: CreateStandaloneIncidentPayload = {
      categoryCode: categoryCode.trim(),
      severityCode,
      title: titleText,
      location: locationPayload,
    };

    if (descriptionText) {
      body.description = descriptionText;
    }

    const reportedAtPayload = toBangladeshIsoDatetime(reportedAt);
    if (reportedAtPayload) {
      body.reportedAt = reportedAtPayload;
    }

    setIsSubmitting(true);

    try {
      const data = await createStandaloneIncident(body);
      toast.success("Incident created. Opening Incident Command.");
      router.push(
        `/dashboard/dispatcher/incidents/${data.incident.public_uuid}`,
      );
    } catch (err) {
      setError(mapCreateStandaloneIncidentError(err));
    } finally {
      setIsSubmitting(false);
    }
  }

  if (isChecking) {
    return <PageLoading label="Loading incident form" />;
  }

  return (
    <DashboardLayout
      title={DISPATCHER_DASHBOARD_TITLE}
      subtitle={DISPATCHER_DASHBOARD_SUBTITLE}
      onLogout={handleLogout}
      hideSidebar
      showHealthBadge={false}
      contentClassName="flex min-h-0 flex-col lg:h-[calc(100vh-11.5rem)]"
    >
      <DispatcherOpsShell className="flex min-h-0 flex-1 flex-col lg:overflow-hidden lg:min-h-0 lg:py-2">
        <div className="flex w-full min-h-0 flex-1 flex-col gap-2.5 pb-2 pt-0 lg:min-h-0 lg:flex-1 lg:overflow-hidden lg:pb-2 lg:pt-0">
          {error ? (
            <div className="shrink-0">
              <ErrorAlert message={error} />
            </div>
          ) : null}

          <CreateStandaloneIncidentWorkspace
            pageHeader={
              <header className="shrink-0 space-y-1">
                <nav
                  aria-label="Standalone incident context"
                  className="flex min-w-0 flex-wrap items-center gap-x-1 text-xs leading-tight"
                >
                  <Link
                    href="/dashboard/dispatcher/incidents"
                    className="font-medium text-[#006747] transition hover:text-[#002D62] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#006747]/30 focus-visible:ring-offset-1"
                  >
                    ← Active Incidents
                  </Link>
                  <span className="text-slate-400" aria-hidden>
                    /
                  </span>
                  <span className="text-slate-500">New Standalone Incident</span>
                </nav>

                <div>
                  <h1 className="text-xl font-semibold text-slate-900">
                    New Standalone Incident
                  </h1>
                  <p className="mt-0.5 text-sm text-slate-600">
                    Record an emergency incident identified outside an existing
                    intake report.
                  </p>
                </div>
              </header>
            }
            detailsPanel={
              <CreateStandaloneIncidentDetailsPanel
                categoryCode={categoryCode}
                severityCode={severityCode}
                reportedAt={reportedAt}
                title={title}
                description={description}
                isSubmitting={isSubmitting}
                canSubmit={canSubmit}
                showValidation={showValidation}
                onCategoryChange={(value) => {
                  setCategoryCode(value);
                  setError("");
                }}
                onSeverityChange={(value) => {
                  setSeverityCode(value);
                  setError("");
                }}
                onReportedAtChange={setReportedAt}
                onTitleChange={(value) => {
                  setTitle(value);
                  setError("");
                }}
                onDescriptionChange={setDescription}
                onSubmit={(event) => void handleSubmit(event)}
                onCancel={() =>
                  router.push("/dashboard/dispatcher/incidents")
                }
              />
            }
            locationPanel={
              <CreateStandaloneIncidentLocationPanel
                selectedLocation={selectedLocation}
                addressText={addressText}
                placeName={placeName}
                isSubmitting={isSubmitting}
                showValidation={showValidation}
                onLocationChange={handleLocationChange}
                onAddressTextChange={handleAddressTextChange}
                onPlaceNameChange={handlePlaceNameChange}
              />
            }
          />
        </div>
      </DispatcherOpsShell>
    </DashboardLayout>
  );
}
