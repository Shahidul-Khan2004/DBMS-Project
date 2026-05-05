/**
 * Convert ISO-ish timestamp input to UTC MySQL DATETIME literal (`YYYY-MM-DD HH:MM:SS`).
 * Returns null when value is falsy or not parseable as a date.
 */
export function toMySqlDateTimeOrNull(value) {
  if (!value) return null;

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return null;
  }

  return date.toISOString().slice(0, 19).replace("T", " ");
}
