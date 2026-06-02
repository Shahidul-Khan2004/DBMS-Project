export function getValidReportedCoordinates(
  latitude?: number,
  longitude?: number,
): { latitude: number; longitude: number } | null {
  if (
    latitude == null ||
    longitude == null ||
    !Number.isFinite(latitude) ||
    !Number.isFinite(longitude)
  ) {
    return null;
  }

  if (latitude < -90 || latitude > 90 || longitude < -180 || longitude > 180) {
    return null;
  }

  return { latitude, longitude };
}

export function formatReportedCoordinates(
  latitude: number,
  longitude: number,
): string {
  return `${latitude.toFixed(6)}, ${longitude.toFixed(6)}`;
}

export function hasValidReportedLocation(location: {
  latitude?: number;
  longitude?: number;
}): boolean {
  return getValidReportedCoordinates(location.latitude, location.longitude) != null;
}
