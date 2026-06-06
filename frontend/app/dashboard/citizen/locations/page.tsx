"use client";

import dynamic from "next/dynamic";
import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { MapPin, PlusCircle, RefreshCw } from "lucide-react";
import {
  CitizenSectionCard,
  getCitizenFriendlyError,
} from "@/components/citizen/CitizenPortal";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { EmptyState, PageLoading } from "@/components/ui/StatusState";
import type {
  LocationPickerSelectionDetails,
  LocationPickerValue,
} from "@/components/location/LocationPicker";
import { clearAuthSession } from "@/lib/auth-store";
import { formatBangladeshTime } from "@/lib/datetime";
import {
  createSavedLocation,
  getMySavedLocations,
} from "@/lib/locations-api";
import { useAuthGuard } from "@/lib/use-auth-guard";
import type { SavedLocation } from "@/types/locations";

const LocationPicker = dynamic(
  () =>
    import("@/components/location/LocationPicker").then((mod) => ({
      default: mod.LocationPicker,
    })),
  {
    ssr: false,
    loading: () => (
      <div className="h-[210px] animate-pulse rounded-2xl bg-slate-100" />
    ),
  },
);

function formatLocation(location: SavedLocation) {
  return (
    location.placeName ||
    location.addressText ||
    "Map location selected"
  );
}

function getFormLocation(form: { latitude: string; longitude: string }) {
  if (!form.latitude.trim() || !form.longitude.trim()) {
    return null;
  }

  const latitude = Number(form.latitude);
  const longitude = Number(form.longitude);

  if (!Number.isFinite(latitude) || !Number.isFinite(longitude)) {
    return null;
  }

  return { latitude, longitude };
}

function getLocationsByNewest(locations: SavedLocation[]) {
  return [...locations].sort(
    (a, b) =>
      new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
  );
}

export default function CitizenLocationsPage() {
  const router = useRouter();
  const isChecking = useAuthGuard(["citizen"]);
  const [locations, setLocations] = useState<SavedLocation[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [loadError, setLoadError] = useState("");
  const [message, setMessage] = useState("");
  const [showAllLocations, setShowAllLocations] = useState(true);
  const [form, setForm] = useState({
    latitude: "",
    longitude: "",
    addressText: "",
    placeName: "",
  });

  const loadLocations = useCallback(async () => {
    setLoading(true);
    setLoadError("");
    try {
      const data = await getMySavedLocations();
      const nextLocations = data.locations;
      setLocations(nextLocations);
      return nextLocations;
    } catch (err) {
      console.error("Failed to load saved locations", err);
      setLoadError(
        getCitizenFriendlyError(
          err,
          "We could not load your saved locations right now.",
        ),
      );
      return [];
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (isChecking) return;
    void loadLocations();
  }, [isChecking, loadLocations]);

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
      setForm((current) => ({
        ...current,
        latitude: location.latitude.toString(),
        longitude: location.longitude.toString(),
        addressText: details?.addressText ?? "",
        placeName: details?.placeName ?? "",
      }));
      setError("");
      setMessage("");
    },
    [],
  );

  async function handleSaveLocation() {
    setError("");
    setMessage("");

    const selectedLocation = getFormLocation(form);

    if (!selectedLocation) {
      setError("Search for a place or click the map to choose a location.");
      return;
    }

    setSaving(true);
    try {
      const data = await createSavedLocation({
        latitude: selectedLocation.latitude,
        longitude: selectedLocation.longitude,
        address_text: form.addressText.trim() || undefined,
        place_name: form.placeName.trim() || undefined,
        source: "user_shared",
      });

      setForm({ latitude: "", longitude: "", addressText: "", placeName: "" });
      setMessage(data.message || "Location saved.");
      await loadLocations();
    } catch (err) {
      console.error("Failed to save location", err);
      setError(
        getCitizenFriendlyError(
          err,
          "We could not save this location right now. Please try again.",
        ),
      );
    } finally {
      setSaving(false);
    }
  }

  if (isChecking) {
    return <PageLoading label="Loading saved locations" />;
  }

  const formSelectedLocation = getFormLocation(form);
  const selectedLocationLabel =
    form.addressText.trim() ||
    form.placeName.trim() ||
    "Selected map point";
  const showDistinctPlaceName =
    Boolean(form.placeName.trim()) &&
    form.placeName.trim() !== form.addressText.trim() &&
    form.placeName.trim() !== selectedLocationLabel;
  const locationsByNewest = getLocationsByNewest(locations);
  const displayedLocations = showAllLocations
    ? locationsByNewest
    : locationsByNewest.slice(0, 5);

  return (
    <DashboardLayout
      title="Saved Locations"
      subtitle="Manage your saved locations for faster reporting."
      onLogout={handleLogout}
    >
      <div className="space-y-3">
       <div className="grid items-start gap-3 xl:grid-cols-[minmax(420px,1.15fr)_minmax(340px,0.85fr)]">
        <CitizenSectionCard
          title="Add Location"
          subtitle="Search or place a marker for the location you want to save."
          icon={<PlusCircle className="h-5 w-5" aria-hidden />}
          className="flex flex-col xl:h-[calc(100dvh-11rem)] xl:min-h-[34rem] xl:max-h-[46rem] [&_header]:px-4 [&_header]:py-3"
          contentClassName="min-h-0 flex-1 overflow-y-auto overscroll-y-contain !p-4"
        >
            {error && <ErrorAlert message={error} />}
            {message && (
              <div className="rounded-xl border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-700">
                {message}
              </div>
            )}
            <div className="flex flex-col gap-3">
              <LocationPicker
                value={formSelectedLocation}
                onChange={handleLocationChange}
                selectedAddress={form.addressText}
                selectedPlaceName={form.placeName}
                syncSearchQueryToSelectedLabel={false}
                embedded
                embeddedCompact
                searchPlaceholder="Search address, place, or landmark..."
                mapClassName="h-[clamp(210px,30vh,250px)] w-full"
                mapWrapperClassName="w-full"
                embeddedMapSectionClassName="mt-3 w-full shrink-0"
                showSelectionSummary={false}
              />

              <div
                className="shrink-0 rounded-lg border border-slate-200/80 bg-slate-50/80 px-3 py-2"
                aria-live="polite"
              >
                {formSelectedLocation ? (
                  <div className="space-y-1">
                    <p className="text-xs font-semibold text-slate-900">
                      Selected location
                    </p>
                    <p className="text-sm font-medium leading-snug text-slate-900">
                      {selectedLocationLabel}
                    </p>
                    {showDistinctPlaceName ? (
                      <p className="text-xs text-slate-500">
                        {form.placeName.trim()}
                      </p>
                    ) : null}
                    <button
                      type="button"
                      onClick={() => {
                        setForm({
                          latitude: "",
                          longitude: "",
                          addressText: "",
                          placeName: "",
                        });
                        setError("");
                        setMessage("");
                      }}
                      disabled={saving}
                      className="text-xs font-medium text-[#006747] underline-offset-2 transition hover:text-[#002D62] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#006747]/30 disabled:cursor-not-allowed disabled:text-slate-400"
                    >
                      Clear Location
                    </button>
                  </div>
                ) : (
                  <div className="space-y-0.5">
                    <p className="text-xs font-semibold text-slate-900">
                      No map point selected
                    </p>
                    <p className="text-xs leading-snug text-slate-600">
                      Choose a map point before saving this location.
                    </p>
                  </div>
                )}
              </div>

              <div className="shrink-0 rounded-lg border border-slate-100 bg-slate-50/40 px-3 py-2">
                <p className="text-xs font-medium text-slate-700">
                  Optional location details
                </p>
                <div className="mt-2 grid gap-2 sm:grid-cols-2">
                  <div>
                    <label
                      htmlFor="saved-location-address"
                      className="block text-xs font-semibold text-slate-700"
                    >
                      Location Name or Address
                    </label>
                    <input
                      id="saved-location-address"
                      value={form.addressText}
                      onChange={(event) =>
                        setForm((current) => ({
                          ...current,
                          addressText: event.target.value,
                        }))
                      }
                      disabled={saving}
                      placeholder="Building, road, or landmark description"
                      className="mt-1 w-full rounded-lg border border-[#002D62]/20 bg-white px-3 py-2 text-sm text-slate-900 placeholder:text-slate-400 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35 disabled:bg-slate-50"
                    />
                  </div>
                  <div>
                    <label
                      htmlFor="saved-location-place"
                      className="block text-xs font-semibold text-slate-700"
                    >
                      Place Name
                    </label>
                    <input
                      id="saved-location-place"
                      value={form.placeName}
                      onChange={(event) =>
                        setForm((current) => ({
                          ...current,
                          placeName: event.target.value,
                        }))
                      }
                      disabled={saving}
                      placeholder="Optional landmark or place name"
                      className="mt-1 w-full rounded-lg border border-[#002D62]/20 bg-white px-3 py-2 text-sm text-slate-900 placeholder:text-slate-400 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35 disabled:bg-slate-50"
                    />
                  </div>
                </div>
                <div className="mt-3 flex justify-end">
                  <Button
                    type="button"
                    isLoading={saving}
                    onClick={() => void handleSaveLocation()}
                    disabled={!formSelectedLocation}
                    size="sm"
                    className="whitespace-nowrap"
                  >
                    Save Location
                  </Button>
                </div>
              </div>
            </div>
        </CitizenSectionCard>

        <CitizenSectionCard
          title="My Recent Locations"
          icon={<MapPin className="h-5 w-5" aria-hidden />}
          className="flex flex-col xl:h-[calc(100dvh-11rem)] xl:min-h-[34rem] xl:max-h-[46rem] [&_header]:px-4 [&_header]:py-3"
          contentClassName="flex min-h-0 flex-1 flex-col !p-0"
        >
          <div className="border-b border-[#002D62]/10 px-4 py-3">
            <div className="flex flex-col gap-2 lg:flex-row lg:items-center lg:justify-between">
              <p className="text-sm leading-5 text-[#42547A]">
                Saved places are listed newest first.
              </p>
              <div className="flex flex-wrap items-center gap-2 lg:justify-end">
                {!loading && locations.length > 0 ? (
                  <span className="rounded-full bg-[#EFF6FF] px-3 py-1 text-xs font-semibold text-[#002D62]">
                    Showing {displayedLocations.length} of {locations.length}
                  </span>
                ) : null}
                {!loading && locations.length > 3 ? (
                  <Button
                    type="button"
                    variant="secondary"
                    size="sm"
                    className="h-8 px-3"
                    onClick={() => setShowAllLocations((current) => !current)}
                  >
                    {showAllLocations ? "Show Recent" : "View All"}
                  </Button>
                ) : null}
                <Button
                  type="button"
                  variant="secondary"
                  size="sm"
                  className="h-8 px-3"
                  onClick={() => void loadLocations()}
                  disabled={loading}
                >
                  <RefreshCw className="h-3.5 w-3.5" aria-hidden />
                  Refresh
                </Button>
              </div>
            </div>
          </div>
            {loading ? (
              <div className="flex flex-1 items-center justify-center px-6 py-10 text-center text-sm text-gray-500">
                Loading locations...
              </div>
            ) : loadError ? (
              <div className="flex flex-1 flex-col justify-center space-y-3 px-6 py-6">
                <ErrorAlert message={loadError} />
                <Button
                  type="button"
                  variant="secondary"
                  size="sm"
                  onClick={() => void loadLocations()}
                >
                  Retry
                </Button>
              </div>
            ) : locations.length === 0 ? (
              <div className="flex flex-1 items-center p-6">
                <EmptyState
                  title="No saved locations yet."
                  description="Add your home, workplace, school, or another place you report from often."
                  icon={<MapPin className="h-6 w-6" aria-hidden />}
                />
              </div>
            ) : (
              <ul className="min-h-0 flex-1 space-y-3 overflow-y-auto overscroll-y-contain p-4">
                {displayedLocations.map((location) => (
                  <li
                    key={location.publicUuid}
                    className="rounded-2xl border border-[#002D62]/10 bg-white p-4 shadow-sm"
                  >
                    <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center">
                      <div className="min-w-0">
                        <h3 className="truncate text-sm font-semibold text-gray-900">
                          {formatLocation(location)}
                        </h3>
                        <p className="mt-1 line-clamp-1 text-xs text-[#42547A]">
                          {location.addressText || location.placeName || "-"}
                        </p>
                        <p className="mt-1 text-xs text-gray-500">
                          Saved {formatBangladeshTime(location.createdAt)}
                        </p>
                      </div>
                      <div className="flex shrink-0 sm:justify-end">
                        <a
                          href={`https://www.openstreetmap.org/?mlat=${location.latitude}&mlon=${location.longitude}#map=16/${location.latitude}/${location.longitude}`}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex h-8 min-w-[5.5rem] items-center justify-center whitespace-nowrap rounded-full border border-[#002D62]/20 bg-[#E8F2FF] px-3 text-xs font-semibold text-[#002D62] shadow-sm transition-colors hover:border-[#002D62]/30 hover:bg-[#DCEBFF]"
                        >
                          Open map
                        </a>
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            )}
        </CitizenSectionCard>
        </div>
      </div>
    </DashboardLayout>
  );
}
