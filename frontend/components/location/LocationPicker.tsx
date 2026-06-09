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
  adminAreaId?: number;
  adminAreaLabel?: string;
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

const DEFAULT_MAP_CLASS_NAME = "h-[320px] w-full sm:h-[380px]";

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
  showSelectionSummary?: boolean;
  scrollWheelZoom?: boolean;
  searchPlaceholder?: string;
  sectionTitle?: string;
  sectionDescription?: string;
  disabled?: boolean;
  className?: string;
  /** When true, omits the inner section title card wrapper for panel embedding. */
  embedded?: boolean;
  /** Custom map container height classes; defaults to responsive fixed height. */
  mapClassName?: string;
  /** Wrapper class for the map container when embedded in a flex panel. */
  mapWrapperClassName?: string;
  /** Class for the embedded map section wrapper; defaults to flex-fill behaviour. */
  embeddedMapSectionClassName?: string;
  /** Tighter embedded search row and control spacing for compact panels. */
  embeddedCompact?: boolean;
  /** When the search input is empty or too short, use this text for the search query. */
  fallbackSearchQuery?: string;
};

const DEFAULT_EMBEDDED_MAP_SECTION_CLASS_NAME =
  "mt-2 flex min-h-0 min-w-0 flex-1 flex-col";


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
    try {
      map.setView(
        [value.latitude, value.longitude],
        Math.max(map.getZoom(), SELECTED_ZOOM),
      );
    } catch {
      // Map may be tearing down during route or panel transitions.
    }
  }, [map, value]);

  return null;
}

function MapResizeHandler() {
  const map = useMap();

  useEffect(() => {
    let cancelled = false;

    const handleResize = () => {
      if (cancelled) return;
      const container = map.getContainer();
      if (!container?.isConnected) return;
      try {
        map.invalidateSize();
      } catch {
        // Ignore races while Leaflet unmounts.
      }
    };

    const resizeObserver = new ResizeObserver(handleResize);
    const mapContainer = map.getContainer();
    if (mapContainer) {
      resizeObserver.observe(mapContainer);
    }

    window.addEventListener("resize", handleResize);
    const timeoutId = window.setTimeout(handleResize, 100);

    return () => {
      cancelled = true;
      window.clearTimeout(timeoutId);
      window.removeEventListener("resize", handleResize);
      resizeObserver.disconnect();
    };
  }, [map]);

  return null;
}

function MapLoadingPlaceholder({ className }: { className: string }) {
  return (
    <div
      className={`animate-pulse rounded-2xl bg-slate-100 ${className}`}
      aria-hidden
    />
  );
}

export function LocationPicker({
  value,
  onChange,
  selectedAddress,
  selectedPlaceName,
  syncSearchQueryToSelectedLabel = true,
  showCurrentLocation = true,
  showSelectionSummary = true,
  scrollWheelZoom = false,
  searchPlaceholder = "Search for an area, road, landmark, or address",
  sectionTitle = "Find Location",
  sectionDescription,
  disabled = false,
  className = "",
  embedded = false,
  mapClassName = DEFAULT_MAP_CLASS_NAME,
  mapWrapperClassName = "",
  embeddedMapSectionClassName = DEFAULT_EMBEDDED_MAP_SECTION_CLASS_NAME,
  embeddedCompact = false,
  fallbackSearchQuery,
}: LocationPickerProps) {
  const helperText =
    sectionDescription ??
    (showCurrentLocation
      ? "Search, use live location, or click directly on the map."
      : "Search or click directly on the map.");
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
  const [isClientReady, setIsClientReady] = useState(false);
  const mapCenter = value
    ? ([value.latitude, value.longitude] as [number, number])
    : DEFAULT_CENTER;

  useEffect(() => {
    setIsClientReady(true);
  }, []);

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

    const trimmedQuery =
      query.trim() || fallbackSearchQuery?.trim() || "";
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

  const handleQueryChange = (nextQuery: string) => {
    setQuery(nextQuery);
    if (searchError) {
      setSearchError("");
    }
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
    const requestId = selectionRequestRef.current + 1;
    selectionRequestRef.current = requestId;
    const location = { latitude: result.latitude, longitude: result.longitude };
    onChange(location, {
      addressText: result.addressText || result.label,
      placeName: result.placeName,
    });
    setQuery(result.label);
    setResults([]);
    setSearchError("");
    setLocationError("");

    void resolveLocationDetails(location).then((details) => {
      if (selectionRequestRef.current !== requestId) return;
      onChange(location, {
        addressText: details.addressText || result.addressText || result.label,
        placeName: result.placeName || details.placeName,
        adminAreaId: details.adminAreaId,
        adminAreaLabel: details.adminAreaLabel,
      });
    });
  };

  const resolveLocationDetails = async (
    location: LocationPickerValue,
  ): Promise<LocationPickerSelectionDetails> => {
    const resolvingRequestId = resolvingRequestRef.current + 1;
    resolvingRequestRef.current = resolvingRequestId;
    setIsResolvingLocation(true);
    try {
      const response = await apiGet<{
        addressText?: string;
        placeName?: string;
        adminAreaId?: number;
        adminAreaLabel?: string;
      }>(
        `/locations/reverse?latitude=${location.latitude}&longitude=${location.longitude}`,
      );

      return {
        addressText: response.addressText,
        placeName: response.placeName,
        adminAreaId: response.adminAreaId,
        adminAreaLabel: response.adminAreaLabel,
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
      if (
        !details.addressText &&
        !details.placeName &&
        !details.adminAreaLabel &&
        details.adminAreaId == null
      ) {
        return;
      }
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
          if (
            !details.addressText &&
            !details.placeName &&
            !details.adminAreaLabel &&
            details.adminAreaId == null
          ) {
            return;
          }
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

  const searchControls = (
    <>
      {embedded && embeddedCompact ? (
        <div
          className="flex flex-col gap-2 sm:flex-row sm:items-center"
        >
          <Input
            value={query}
            onChange={(event) => handleQueryChange(event.target.value)}
            onKeyDown={handleSearchKeyDown}
            placeholder={searchPlaceholder}
            disabled={disabled || isSearching}
            aria-label="Search for a location"
            className="min-w-0 flex-1 rounded-xl px-3 py-2 text-sm leading-tight"
          />
          <Button
            type="button"
            variant="secondary"
            isLoading={isSearching}
            disabled={isSearchDisabled}
            onClick={() => void handleSearch()}
            className="h-[44px] shrink-0 whitespace-nowrap px-4 text-sm sm:min-w-[5.5rem]"
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
              className="h-[44px] shrink-0 whitespace-nowrap px-4 text-sm"
            >
              <LocateFixed className="h-4 w-4" aria-hidden />
              My Location
            </Button>
          ) : null}
        </div>
      ) : (
        <div className={embedded ? "space-y-2" : "mt-3 space-y-3"}>
          <Input
            value={query}
            onChange={(event) => handleQueryChange(event.target.value)}
            onKeyDown={handleSearchKeyDown}
            placeholder={searchPlaceholder}
            disabled={disabled || isSearching}
            aria-label="Search for a location"
          />
          <div
            className={
              showCurrentLocation
                ? "grid gap-2 sm:grid-cols-2"
                : embedded
                  ? "flex gap-2"
                  : "grid gap-2"
            }
          >
            <Button
              type="button"
              variant="secondary"
              isLoading={isSearching}
              disabled={isSearchDisabled}
              onClick={() => void handleSearch()}
              fullWidth={!embedded}
              className={`h-[46px] whitespace-nowrap text-sm ${embedded && !showCurrentLocation ? "shrink-0 px-5" : ""}`}
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
      )}

      {searchError ? (
        <p
          className={`mt-1.5 rounded-xl bg-red-50 px-3 text-red-700 ${embedded ? "py-1.5 text-xs" : "py-2 text-sm"}`}
        >
          {searchError}
        </p>
      ) : null}

      {locationError ? (
        <p
          className={`mt-1.5 rounded-xl bg-red-50 px-3 text-red-700 ${embedded ? "py-1.5 text-xs" : "py-2 text-sm"}`}
        >
          {locationError}
        </p>
      ) : null}

      {isResolvingLocation ? (
        <p
          className={`mt-1.5 rounded-xl bg-[#EFF6FF] px-3 leading-5 text-slate-700 ${embedded ? "py-1.5 text-xs" : "py-2 text-xs"}`}
        >
          Reading the selected map location...
        </p>
      ) : null}

      {!searchError && hasSearched && !isSearching && results.length === 0 ? (
        <p
          className={`mt-1.5 rounded-xl bg-zinc-100 px-3 text-gray-600 ${embedded ? "py-1.5 text-xs" : "py-2 text-sm"}`}
        >
          No places found. Try a nearby road, area, or landmark.
        </p>
      ) : null}

      {results.length > 0 ? (
        <div
          className={`mt-2 overflow-hidden rounded-xl border border-[#002D62]/10 bg-white shadow-sm ${embedded ? "max-h-[7.5rem] overflow-y-auto overscroll-y-contain" : ""}`}
        >
          {results.map((result) => (
            <button
              key={result.id}
              type="button"
              onClick={() => handleResultSelect(result)}
              className={`block w-full cursor-pointer border-b border-gray-100 px-3 text-left text-gray-800 transition-colors last:border-b-0 hover:bg-[#EFF6FF] focus-visible:bg-[#EFF6FF] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#002D62]/30 ${embedded ? "py-2 text-xs" : "px-4 py-3 text-sm"}`}
            >
              <span className="block font-medium text-gray-900">
                {result.label}
              </span>
            </button>
          ))}
        </div>
      ) : null}
    </>
  );

  const mapBlock = (
    <>
      <div
        className={`relative isolate z-0 overflow-hidden rounded-2xl border border-[#002D62]/10 bg-slate-100 shadow-sm ${mapWrapperClassName}`}
      >
        {!isClientReady ? (
          <MapLoadingPlaceholder className={mapClassName} />
        ) : (
          <MapContainer
            center={mapCenter}
            zoom={value ? SELECTED_ZOOM : DEFAULT_ZOOM}
            scrollWheelZoom={scrollWheelZoom}
            className={mapClassName}
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
            {value ? (
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
            ) : null}
          </MapContainer>
        )}
      </div>
      {!scrollWheelZoom && !embedded ? (
        <p className="mt-1.5 text-center text-xs text-slate-500">
          Use + / - to zoom
        </p>
      ) : null}
    </>
  );

  if (embedded) {
    return (
      <div className={`flex shrink-0 flex-col ${className}`}>
        <div
          className={
            embeddedCompact ? "shrink-0 space-y-1" : "shrink-0 space-y-2"
          }
        >
          {searchControls}
        </div>
        <div className={embeddedMapSectionClassName}>{mapBlock}</div>
      </div>
    );
  }

  return (
    <div className={`space-y-4 ${className}`}>
      <div className="rounded-2xl border border-[#002D62]/10 bg-white p-4">
        <div className="flex flex-col gap-1">
          <p className="text-sm font-semibold text-[#002D62]">{sectionTitle}</p>
          <p className="text-xs leading-5 text-gray-600">{helperText}</p>
        </div>
        {searchControls}
      </div>

      {mapBlock}

      {showSelectionSummary ? (
        <div className="rounded-2xl border border-[#002D62]/10 bg-white px-4 py-3 text-sm text-gray-700 shadow-sm">
          {value ? (
            <div className="grid gap-2 sm:grid-cols-2">
              {selectedLabel ? (
                <p className="sm:col-span-2">
                  <span className="font-medium text-gray-900">Selected place:</span>{" "}
                  {selectedLabel}
                </p>
              ) : null}
              <p className="sm:col-span-2">Map location selected.</p>
            </div>
          ) : (
            <p className="text-gray-500">No map location selected yet.</p>
          )}
        </div>
      ) : null}
    </div>
  );
}
