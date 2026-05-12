"use client";

import dynamic from "next/dynamic";
import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Eye, MapPin, PlusCircle } from "lucide-react";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardContent, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { Input } from "@/components/ui/Input";
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
  CreateSavedLocationResponse,
  SavedLocation,
  SavedLocationResponse,
  SavedLocationsResponse,
} from "@/types/locations";

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

function formatLocation(location: SavedLocation) {
  return (
    location.addressText ||
    location.placeName ||
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
  const [activeLocation, setActiveLocation] =
    useState<SavedLocation | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadingDetailUuid, setLoadingDetailUuid] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [showAllLocations, setShowAllLocations] = useState(false);
  const [form, setForm] = useState({
    latitude: "",
    longitude: "",
    addressText: "",
    placeName: "",
  });

  const loadLocations = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const data = await apiJson<SavedLocationsResponse>("/locations/my");
      setLocations(data.locations ?? []);
      setActiveLocation((current) => {
        if (!current) return null;
        return (
          data.locations?.find(
            (location) => location.publicUuid === current.publicUuid,
          ) ?? null
        );
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load locations.");
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
      const data = await apiJson<CreateSavedLocationResponse>("/locations", {
        method: "POST",
        body: JSON.stringify({
          latitude: selectedLocation.latitude,
          longitude: selectedLocation.longitude,
          address_text: form.addressText.trim() || undefined,
          place_name: form.placeName.trim() || undefined,
          source: "user_shared",
        }),
      });

      setLocations((current) => [data.location, ...current]);
      setActiveLocation(data.location);
      setForm({ latitude: "", longitude: "", addressText: "", placeName: "" });
      setMessage(data.message || "Location saved.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save location.");
    } finally {
      setSaving(false);
    }
  }

  async function handleViewLocation(publicUuid: string) {
    setError("");
    setMessage("");
    setLoadingDetailUuid(publicUuid);

    try {
      const data = await apiJson<SavedLocationResponse>(
        `/locations/${publicUuid}`,
      );
      setActiveLocation(data.location);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Could not load location details.",
      );
    } finally {
      setLoadingDetailUuid("");
    }
  }

  if (isChecking) {
    return <PageLoading label="Loading saved locations" />;
  }

  const formSelectedLocation = getFormLocation(form);
  const locationsByNewest = getLocationsByNewest(locations);
  const displayedLocations = showAllLocations
    ? locationsByNewest
    : locationsByNewest.slice(0, 3);

  return (
    <DashboardLayout
      title="Saved Locations"
      subtitle="Keep reusable places for future citizen reports"
      onLogout={handleLogout}
    >
      <div className="grid items-start gap-6 xl:grid-cols-[minmax(620px,1.25fr)_minmax(360px,0.75fr)]">
        <Card className="h-fit overflow-hidden bg-white shadow-md">
          <CardHeader>
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-[#006747] text-white">
                <PlusCircle className="h-5 w-5" aria-hidden />
              </div>
              <h2 className="text-lg font-semibold text-[#002D62]">
                Add Location
              </h2>
            </div>
          </CardHeader>
          <CardContent className="space-y-5">
            {error && <ErrorAlert message={error} />}
            {message && (
              <div className="rounded-2xl border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-700">
                {message}
              </div>
            )}
            <div className="space-y-5">
              <LocationPicker
                value={formSelectedLocation}
                onChange={handleLocationChange}
                selectedAddress={form.addressText}
                selectedPlaceName={form.placeName}
              />

              <div className="rounded-2xl border border-[#002D62]/10 bg-[#EFF6FF] p-4">
                <div className="mb-4">
                  <h3 className="text-sm font-semibold text-[#002D62]">
                    Location Details
                  </h3>
                  <p className="mt-1 text-xs leading-5 text-gray-600">
                    These labels help responders recognize the place.
                  </p>
                </div>
                <div className="grid gap-4 sm:grid-cols-2">
                  <Input
                    value={form.addressText}
                    onChange={(event) =>
                      setForm((current) => ({
                        ...current,
                        addressText: event.target.value,
                      }))
                    }
                    label="Address Text"
                    placeholder="Optional address or landmark"
                  />
                  <Input
                    value={form.placeName}
                    onChange={(event) =>
                      setForm((current) => ({
                        ...current,
                        placeName: event.target.value,
                      }))
                    }
                    label="Place Name"
                    placeholder="Home, office, school gate"
                  />
                </div>
                <Button
                  type="button"
                  isLoading={saving}
                  onClick={() => void handleSaveLocation()}
                  fullWidth
                  className="mt-4"
                >
                  Save Location
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="h-fit overflow-hidden bg-white shadow-md">
          <CardHeader>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-[#002D62] text-white">
                  <MapPin className="h-5 w-5" aria-hidden />
                </div>
                <h2 className="text-lg font-semibold text-[#002D62]">
                  My Recent Locations
                </h2>
              </div>
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
                  onClick={() => setShowAllLocations((current) => !current)}
                >
                  {showAllLocations ? "Show Recent" : "View All"}
                </Button>
              ) : null}
              <Button
                type="button"
                variant="secondary"
                size="sm"
                onClick={() => void loadLocations()}
                disabled={loading}
              >
                Refresh
              </Button>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            {loading ? (
              <div className="px-6 py-10 text-center text-sm text-gray-500">
                Loading locations...
              </div>
            ) : locations.length === 0 ? (
              <div className="p-6">
                <EmptyState
                  title="No saved locations yet"
                  description="Add your home, workplace, school, or another place you report from often."
                  icon={<MapPin className="h-6 w-6" aria-hidden />}
                />
              </div>
            ) : (
              <ul className="divide-y divide-[#002D62]/10">
                {displayedLocations.map((location) => (
                  <li key={location.publicUuid} className="px-6 py-4">
                    <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                      <div>
                        <h3 className="font-semibold text-gray-900">
                          {formatLocation(location)}
                        </h3>
                        <div className="mt-2 grid gap-1 text-sm text-gray-600">
                          <p>Address: {location.addressText || "-"}</p>
                          <p>Place: {location.placeName || "-"}</p>
                          <p>Source: {location.source}</p>
                        </div>
                        <p className="mt-2 text-xs text-gray-500">
                          Saved {formatBangladeshTime(location.createdAt)}
                        </p>
                      </div>
                      <div className="flex flex-wrap gap-2 sm:justify-end">
                        <Button
                          type="button"
                          variant="secondary"
                          size="sm"
                          isLoading={loadingDetailUuid === location.publicUuid}
                          onClick={() =>
                            void handleViewLocation(location.publicUuid)
                          }
                        >
                          <Eye className="h-4 w-4" aria-hidden />
                          View
                        </Button>
                        <a
                          href={`https://www.openstreetmap.org/?mlat=${location.latitude}&mlon=${location.longitude}#map=16/${location.latitude}/${location.longitude}`}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center justify-center rounded-2xl border border-[#002D62]/20 bg-[#E8F2FF] px-3 py-2 text-sm font-semibold text-[#002D62] shadow-sm transition-colors hover:border-[#002D62]/30 hover:bg-[#DCEBFF]"
                        >
                          Open map
                        </a>
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        {activeLocation && (
          <Card className="shadow-md xl:col-span-2">
            <CardHeader>
              <h2 className="text-lg font-semibold text-[#002D62]">
                Location Details
              </h2>
            </CardHeader>
            <CardContent>
              <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                <div>
                  <dt className="text-sm font-medium text-gray-600">
                    Place Name
                  </dt>
                  <dd className="mt-1 text-sm text-gray-900">
                    {activeLocation.placeName || "-"}
                  </dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-600">
                    Address Text
                  </dt>
                  <dd className="mt-1 text-sm text-gray-900">
                    {activeLocation.addressText || "-"}
                  </dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-600">Source</dt>
                  <dd className="mt-1 text-sm text-gray-900">
                    {activeLocation.source}
                  </dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-600">
                    Public UUID
                  </dt>
                  <dd className="mt-1 break-words text-sm text-gray-900">
                    {activeLocation.publicUuid}
                  </dd>
                </div>
              </dl>
            </CardContent>
          </Card>
        )}
      </div>
    </DashboardLayout>
  );
}
