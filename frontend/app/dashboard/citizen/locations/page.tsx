"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { MapPin, RefreshCw } from "lucide-react";
import {
  CitizenPageContent,
  CitizenSectionCard,
} from "@/components/citizen/CitizenPortal";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { EmptyState, PageLoading } from "@/components/ui/StatusState";
import { clearAuthSession } from "@/lib/auth-store";
import { formatBangladeshTime } from "@/lib/datetime";
import { getMySavedLocations } from "@/lib/locations-api";
import { useAuthGuard } from "@/lib/use-auth-guard";
import type { SavedLocation } from "@/types/locations";

function formatLocationName(location: SavedLocation) {
  return location.placeName || location.addressText || "Saved location";
}

function formatLocationAddress(location: SavedLocation) {
  if (location.addressText && location.placeName && location.addressText !== location.placeName) {
    return location.addressText;
  }

  return location.addressText || location.placeName || "-";
}

function getLocationsByNewest(locations: SavedLocation[]) {
  return [...locations].sort(
    (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
  );
}

export default function CitizenLocationsPage() {
  const router = useRouter();
  const isChecking = useAuthGuard(["citizen"]);
  const [locations, setLocations] = useState<SavedLocation[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");

  const loadLocations = useCallback(async () => {
    setLoading(true);
    setLoadError("");
    try {
      const data = await getMySavedLocations();
      setLocations(data.locations);
    } catch (err) {
      console.error("Failed to load saved locations", err);
      setLoadError("We couldn’t load your saved locations. Please try again.");
      setLocations([]);
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

  if (isChecking) {
    return <PageLoading label="Loading saved locations" />;
  }

  const locationsByNewest = getLocationsByNewest(locations);

  return (
    <DashboardLayout
      title="Saved Locations"
      subtitle="Places you have saved for faster reporting."
      onLogout={handleLogout}
    >
      <CitizenPageContent>
        <CitizenSectionCard
          title="My Saved Locations"
          icon={<MapPin className="h-5 w-5" aria-hidden />}
          headerAction={
            <div className="flex flex-wrap items-center justify-end gap-2">
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
          }
        >
          {loading ? (
            <p className="text-sm text-[#42547A]">Loading saved locations...</p>
          ) : loadError ? (
            <div className="space-y-3">
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
            <EmptyState
              title="No saved locations yet."
              description="Locations you use while reporting incidents will appear here."
              icon={<MapPin className="h-6 w-6" aria-hidden />}
            />
          ) : (
            <ul className="space-y-3">
              {locationsByNewest.map((location) => (
                <li
                  key={location.publicUuid}
                  className="rounded-2xl border border-slate-200/80 bg-white p-4 shadow-sm"
                >
                  <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center">
                    <div className="min-w-0">
                      <h3 className="truncate text-sm font-semibold text-slate-900">
                        {formatLocationName(location)}
                      </h3>
                      <p className="mt-1 line-clamp-2 text-sm text-[#42547A]">
                        {formatLocationAddress(location)}
                      </p>
                      <p className="mt-2 text-xs text-slate-500">
                        Saved {formatBangladeshTime(location.createdAt)}
                      </p>
                    </div>
                    <div className="flex shrink-0 sm:justify-end">
                      <a
                        href={`https://www.openstreetmap.org/?mlat=${location.latitude}&mlon=${location.longitude}#map=16/${location.latitude}/${location.longitude}`}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex h-9 items-center justify-center whitespace-nowrap rounded-full border border-[#002D62]/20 bg-[#EFF6FF] px-4 text-xs font-semibold text-[#002D62] transition-colors hover:border-[#002D62]/30 hover:bg-[#DCEBFF]"
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
      </CitizenPageContent>
    </DashboardLayout>
  );
}
