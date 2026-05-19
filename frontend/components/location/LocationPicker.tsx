"use client";

import { KeyboardEvent, useEffect, useRef, useState } from "react";
import {
  CircleMarker,
  MapContainer,
  TileLayer,
  useMap,
  useMapEvents,
} from "react-leaflet";
import { LocateFixed, Search } from "lucide-react";
import { apiGet } from "@/lib/api";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";

const DEFAULT_CENTER: [number, number] = [23.8103, 90.4125];
const DEFAULT_ZOOM = 12;
const SELECTED_ZOOM = 15;
const BANGALADESH_BOUNDS: [[number, number], [number, number]] = [
  [20.7421, 88.0840],
  [26.7100, 92.6720],
];

export type LocationPickerValue = {
  latitude: number;
  longitude: number;
};

export type LocationPickerSelectionDetails = {
  addressText?: string;
  placeName?: string;
};

const CLEARED_LOCATION_DETAILS: LocationPickerSelectionDetails = {
  addressText: "",
  placeName: "",
};

function isLocationInBangladesh(location: LocationPickerValue) {
  return (
    location.latitude >= BANGALADESH_BOUNDS[0][0] &&
    location.latitude <= BANGALADESH_BOUNDS[1][0] &&
    location.longitude >= BANGALADESH_BOUNDS[0][1] &&
    location.longitude <= BANGALADESH_BOUNDS[1][1]
  );
}

function getLocationSearchErrorMessage(error: unknown) {
  if (error instanceof DOMException && error.name === "AbortError") {
    return "Could not search places right now. Location search took too long. Please try again.";
  }

  return error instanceof Error
    ? `Could not search places right now. ${error.message}`
    : "Could not search places right now. Please try again.";
}

type SearchResult = {
  id: string;
  latitude: number;
  longitude: number;
  label: string;
  addressText?: string;
  placeName?: string;
};

type BackendLocationSearchResult = {
  id?: string;
  latitude: number;
  longitude: number;
  label: string;
  addressText?: string;
  placeName?: string;
};

type LocationPickerProps = {
  value: LocationPickerValue | null;
  onChange: (
    value: LocationPickerValue,
    details?: LocationPickerSelectionDetails,
  ) => void;
  selectedAddress?: string;
  selectedPlaceName?: string;
  syncSearchQueryToSelectedLabel?: boolean;
  showCurrentLocation?: boolean;
  disabled?: boolean;
  className?: string;
};


function getSearchResultSignature(result: SearchResult) {
  return [
    result.id,
    result.latitude.toFixed(6),
    result.longitude.toFixed(6),
    result.label,
  ].join("|");
}

function getSearchResultKey(result: SearchResult, index: number) {
  return [
    result.id,
    result.latitude.toFixed(6),
    result.longitude.toFixed(6),
    index.toString(),
  ].join("|");
}

function normalizeSearchResults(results: SearchResult[]) {
  const seenSignatures = new Set<string>();

  return results.reduce<SearchResult[]>((uniqueResults, result) => {
    const signature = getSearchResultSignature(result);
    if (seenSignatures.has(signature)) return uniqueResults;

    seenSignatures.add(signature);
    uniqueResults.push({
      ...result,
      id: getSearchResultKey(result, uniqueResults.length),
    });
    return uniqueResults;
  }, []);
}

function MapClickHandler({
  disabled,
  onPick,
}: {
  disabled: boolean;
  onPick: (value: LocationPickerValue) => void;
}) {
  useMapEvents({
    click(event) {
      if (disabled) return;
      onPick({
        latitude: event.latlng.lat,
        longitude: event.latlng.lng,
      });
    },
  });

  return null;
}

function MapRecenter({ value }: { value: LocationPickerValue | null }) {
  const map = useMap();
  const lastCenteredLocationRef = useRef<string | null>(null);

  useEffect(() => {
    if (!value) {
      lastCenteredLocationRef.current = null;
      return;
    }

    const locationKey = `${value.latitude.toFixed(6)},${value.longitude.toFixed(6)}`;
    if (lastCenteredLocationRef.current === locationKey) return;

    lastCenteredLocationRef.current = locationKey;
    map.setView(
      [value.latitude, value.longitude],
      Math.max(map.getZoom(), SELECTED_ZOOM),
    );
  }, [map, value]);

  return null;
}

function MapResizeHandler() {
  const map = useMap();

  useEffect(() => {
    const handleResize = () => {
      map.invalidateSize();
    };

    const resizeObserver = new ResizeObserver(handleResize);
    const mapContainer = map.getContainer();
    if (mapContainer) {
      resizeObserver.observe(mapContainer);
    }

    window.addEventListener("resize", handleResize);

    // Invalidate size once on mount to ensure proper initialization
    setTimeout(() => map.invalidateSize(), 100);

    return () => {
      window.removeEventListener("resize", handleResize);
      resizeObserver.disconnect();
    };
  }, [map]);

  return null;
}

export function LocationPicker({
  value,
  onChange,
  selectedAddress,
  selectedPlaceName,
  syncSearchQueryToSelectedLabel = true,
  showCurrentLocation = true,
  disabled = false,
  className = "",
}: LocationPickerProps) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<SearchResult[]>([]);
  const [isSearching, setIsSearching] = useState(false);
  const [isLocating, setIsLocating] = useState(false);
  const [isResolvingLocation, setIsResolvingLocation] = useState(false);
  const [searchError, setSearchError] = useState("");
  const [locationError, setLocationError] = useState("");
  const [hasSearched, setHasSearched] = useState(false);
  const selectionRequestRef = useRef(0);
  const resolvingRequestRef = useRef(0);
  const lastSyncedSelectedLabelRef = useRef("");
  const mapCenter = value
    ? ([value.latitude, value.longitude] as [number, number])
    : DEFAULT_CENTER;

  const isSearchDisabled = disabled || isSearching;
  const selectedLabel = selectedPlaceName || selectedAddress;

  useEffect(() => {
    if (!value) {
      selectionRequestRef.current += 1;
    }
  }, [value]);

  useEffect(() => {
    if (!syncSearchQueryToSelectedLabel) return;
    if (!selectedLabel) return;
    if (lastSyncedSelectedLabelRef.current === selectedLabel) return;

    lastSyncedSelectedLabelRef.current = selectedLabel;
    setQuery(selectedLabel);
  }, [selectedLabel, syncSearchQueryToSelectedLabel]);

  const handleSearch = async () => {
    setLocationError("");

    const trimmedQuery = query.trim();
    if (trimmedQuery.length < 2) {
      setSearchError("Enter at least two characters to search.");
      setResults([]);
      setHasSearched(false);
      return;
    }

    setIsSearching(true);
    setSearchError("");
    setHasSearched(true);

    try {
      const nextResults = await searchBarikoiPlaces(trimmedQuery);
      setResults(normalizeSearchResults(nextResults));
    } catch (error) {
      setSearchError(getLocationSearchErrorMessage(error));
      setResults([]);
    } finally {
      setIsSearching(false);
    }
  };

  const handleSearchKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key !== "Enter") return;
    event.preventDefault();
    void handleSearch();
  };

  const searchBarikoiPlaces = async (text: string) => {
    const controller = new AbortController();
    const timeoutId = window.setTimeout(() => controller.abort(), 18_000);

    try {
      const response = await apiGet<{ places?: BackendLocationSearchResult[] }>(
        `/locations/search?query=${encodeURIComponent(text)}`,
        { signal: controller.signal },
      );

      return (response.places ?? [])
        .map((result, index) => ({
          id:
            result.id ||
            `${result.latitude}-${result.longitude}-${index}`,
          latitude: result.latitude,
          longitude: result.longitude,
          label: result.label,
          addressText: result.addressText,
          placeName: result.placeName,
        }))
        .filter((result) =>
          isLocationInBangladesh({
            latitude: result.latitude,
            longitude: result.longitude,
          }),
        );
    } finally {
      window.clearTimeout(timeoutId);
    }
  };

  const handleResultSelect = (result: SearchResult) => {
    selectionRequestRef.current += 1;
    onChange(
      { latitude: result.latitude, longitude: result.longitude },
      {
        addressText: result.addressText || result.label,
        placeName: result.placeName,
      },
    );
    setQuery(result.label);
    setResults([]);
    setSearchError("");
    setLocationError("");
  };

  const resolveLocationDetails = async (
    location: LocationPickerValue,
  ): Promise<LocationPickerSelectionDetails> => {
    const resolvingRequestId = resolvingRequestRef.current + 1;
    resolvingRequestRef.current = resolvingRequestId;
    setIsResolvingLocation(true);
    try {
      const response = await apiGet<{ addressText?: string; placeName?: string }>(
        `/locations/reverse?latitude=${location.latitude}&longitude=${location.longitude}`,
      );

      return {
        addressText: response.addressText,
        placeName: response.placeName,
      };
    } catch {
      return {};
    } finally {
      if (resolvingRequestRef.current === resolvingRequestId) {
        setIsResolvingLocation(false);
      }
    }
  };

  const handleMapPick = (location: LocationPickerValue) => {
    setSearchError("");
    setLocationError("");

    if (!isLocationInBangladesh(location)) {
      setLocationError("Please choose a location inside Bangladesh.");
      return;
    }

    const requestId = selectionRequestRef.current + 1;
    selectionRequestRef.current = requestId;
    onChange(location, CLEARED_LOCATION_DETAILS);
    setQuery("");

    void resolveLocationDetails(location).then((details) => {
      if (selectionRequestRef.current !== requestId) return;
      if (!details.addressText && !details.placeName) return;
      onChange(location, details);
    });
  };

  const handleCurrentLocation = () => {
    setSearchError("");
    setLocationError("");

    if (!navigator.geolocation) {
      setLocationError("This browser does not support live location.");
      return;
    }

    const requestId = selectionRequestRef.current + 1;
    selectionRequestRef.current = requestId;
    setIsLocating(true);
    navigator.geolocation.getCurrentPosition(
      (position) => {
        if (selectionRequestRef.current !== requestId) {
          setIsLocating(false);
          return;
        }

        const location = {
          latitude: position.coords.latitude,
          longitude: position.coords.longitude,
        };

        if (!isLocationInBangladesh(location)) {
          setLocationError(
            "Live location is outside Bangladesh. Please pick a point on the map.",
          );
          setIsLocating(false);
          return;
        }

        onChange(location, CLEARED_LOCATION_DETAILS);
        setQuery("");
        void resolveLocationDetails(location).then((details) => {
          if (selectionRequestRef.current !== requestId) return;
          if (!details.addressText && !details.placeName) return;
          onChange(location, details);
        });
        setIsLocating(false);
      },
      () => {
        if (selectionRequestRef.current !== requestId) {
          setIsLocating(false);
          return;
        }
        setLocationError(
          "Could not read your live location. Allow location permission or choose a point on the map.",
        );
        setIsLocating(false);
      },
      { enableHighAccuracy: true, timeout: 10_000, maximumAge: 0 },
    );
  };

  return (
    <div className={`space-y-4 ${className}`}>
      <div className="rounded-2xl border border-[#002D62]/10 bg-white p-4">
        <div className="flex flex-col gap-1">
          <p className="text-sm font-semibold text-[#002D62]">
            Find Location
          </p>
          <p className="text-xs leading-5 text-gray-600">
            {showCurrentLocation
              ? "Search, use live location, or click directly on the map."
              : "Search or click directly on the map."}
          </p>
        </div>

        <div className="mt-3 space-y-3">
          <Input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={handleSearchKeyDown}
            placeholder="Search for an area, road, landmark, or address"
            disabled={disabled || isSearching}
            aria-label="Search for a location"
          />
          <div className={showCurrentLocation ? "grid gap-2 sm:grid-cols-2" : "grid gap-2"}>
            <Button
              type="button"
              variant="secondary"
              isLoading={isSearching}
              disabled={isSearchDisabled}
              onClick={() => void handleSearch()}
              fullWidth
              className="h-[46px] whitespace-nowrap text-sm"
            >
              <Search className="h-4 w-4" aria-hidden />
              Search
            </Button>
            {showCurrentLocation ? (
              <Button
                type="button"
                variant="outline"
                isLoading={isLocating}
                disabled={disabled || isLocating}
                onClick={handleCurrentLocation}
                fullWidth
                className="h-[46px] whitespace-nowrap text-sm"
              >
                <LocateFixed className="h-4 w-4" aria-hidden />
                My Location
              </Button>
            ) : null}
          </div>
        </div>


        {searchError && (
          <p className="mt-2 rounded-2xl bg-red-50 px-3 py-2 text-sm text-red-700">
            {searchError}
          </p>
        )}

        {locationError && (
          <p className="mt-2 rounded-2xl bg-red-50 px-3 py-2 text-sm text-red-700">
            {locationError}
          </p>
        )}

        {isResolvingLocation && (
          <p className="mt-2 rounded-2xl bg-[#EFF6FF] px-3 py-2 text-xs leading-5 text-slate-700">
            Reading the selected map location...
          </p>
        )}

        {!searchError && hasSearched && !isSearching && results.length === 0 && (
          <p className="mt-2 rounded-2xl bg-zinc-100 px-3 py-2 text-sm text-gray-600">
            No places found. Try a nearby road, area, or landmark.
          </p>
        )}

        {results.length > 0 && (
          <div className="mt-3 overflow-hidden rounded-2xl border border-[#002D62]/10 bg-white shadow-sm">
            {results.map((result) => (
              <button
                key={result.id}
                type="button"
                onClick={() => handleResultSelect(result)}
                className="block w-full border-b border-gray-100 px-4 py-3 text-left text-sm text-gray-800 transition-colors last:border-b-0 hover:bg-[#EFF6FF] focus:bg-[#EFF6FF] focus:outline-none"
              >
                <span className="block font-medium text-gray-900">
                  {result.label}
                </span>
              </button>
            ))}
          </div>
        )}
      </div>

      <div className="overflow-hidden rounded-2xl border border-[#002D62]/10 bg-slate-100 shadow-sm">
        <MapContainer
          center={mapCenter}
          zoom={value ? SELECTED_ZOOM : DEFAULT_ZOOM}
          scrollWheelZoom
          className="h-[320px] w-full sm:h-[380px]"
          maxBounds={BANGALADESH_BOUNDS}
          maxBoundsViscosity={1}
        >
          <TileLayer
            attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
            url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
            maxZoom={19}
          />
          <MapClickHandler disabled={disabled} onPick={handleMapPick} />
          <MapResizeHandler />
          <MapRecenter value={value} />
          {value && (
            <CircleMarker
              center={[value.latitude, value.longitude]}
              radius={9}
              pathOptions={{
                color: "#ffffff",
                fillColor: "#DA291C",
                fillOpacity: 1,
                weight: 3,
              }}
            />
          )}
        </MapContainer>
      </div>

      <div className="rounded-2xl border border-[#002D62]/10 bg-white px-4 py-3 text-sm text-gray-700 shadow-sm">
        {value ? (
          <div className="grid gap-2 sm:grid-cols-2">
            {selectedLabel && (
              <p className="sm:col-span-2">
                <span className="font-medium text-gray-900">Selected place:</span>{" "}
                {selectedLabel}
              </p>
            )}
            <p className="sm:col-span-2">
              Map location selected.
            </p>
          </div>
        ) : (
          <p className="text-gray-500">No map location selected yet.</p>
        )}
      </div>
    </div>
  );
}
