const EXPLICIT_TIMEZONE_PATTERN = /(?:Z|[+-]\d{2}:?\d{2})$/i;
const TIMESTAMP_WITHOUT_TIMEZONE_PATTERN =
  /^\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?$/;
const BD_TIMEZONE_OFFSET = "+06:00";

function parseBangladeshTimestamp(value: string) {
  const trimmedValue = value.trim();

  if (!trimmedValue) return null;

  const normalizedValue =
    TIMESTAMP_WITHOUT_TIMEZONE_PATTERN.test(trimmedValue) &&
    !EXPLICIT_TIMEZONE_PATTERN.test(trimmedValue)
      ? `${trimmedValue.replace(" ", "T")}Z`
      : trimmedValue.replace(" ", "T");

  return new Date(normalizedValue);
}

function parseBangladeshLocalDatetime(value: string) {
  const trimmedValue = value.trim();
  if (!trimmedValue) return null;

  const match = trimmedValue.match(
    /^(\d{4})-(\d{2})-(\d{2})[T\s](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,3}))?)?$/,
  );

  if (!match) return null;

  const [, year, month, day, hour, minute, second = "0", ms = "0"] = match;
  const parsedMs = Number((ms + "000").slice(0, 3));

  return new Date(
    Date.UTC(
      Number(year),
      Number(month) - 1,
      Number(day),
      Number(hour) - 6,
      Number(minute),
      Number(second),
      parsedMs,
    ),
  );
}

export function formatBangladeshTime(value?: string | null): string {
  if (!value) return "N/A";

  const date = parseBangladeshTimestamp(value);

  if (!date || Number.isNaN(date.getTime())) {
    return "Invalid date";
  }

  return date.toLocaleString("en-US", {
    timeZone: "Asia/Dhaka",
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
    hour12: true,
  });
}

export function isValidBangladeshLocalDatetime(
  value?: string | null,
): boolean {
  const date = parseBangladeshLocalDatetime(value ?? "");
  return !!date && !Number.isNaN(date.getTime());
}

export function toBangladeshIsoDatetime(value?: string | null): string | undefined {
  const date = parseBangladeshLocalDatetime(value ?? "");
  if (!date || Number.isNaN(date.getTime())) return undefined;

  const normalizedValue = (value ?? "").trim().replace(" ", "T");
  const withSeconds = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(
    normalizedValue,
  )
    ? `${normalizedValue}:00`
    : normalizedValue;

  return `${withSeconds}${BD_TIMEZONE_OFFSET}`;
}

export function getCurrentBangladeshDatetimeLocal(): string {
  return new Date(Date.now() + 6 * 60 * 60 * 1000)
    .toISOString()
    .slice(0, 16);
}
