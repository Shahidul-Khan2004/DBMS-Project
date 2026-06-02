function timestampMs(value: string | null | undefined) {
  if (!value) return 0;

  const time = new Date(value).getTime();
  return Number.isFinite(time) ? time : 0;
}

function newestTimestamp(values: Array<string | null | undefined>) {
  return values.reduce((latest, value) => {
    const next = timestampMs(value);
    return next > latest ? next : latest;
  }, 0);
}

export function sortNewestFirst<T>(
  items: T[],
  getTimestampValues: (item: T) => Array<string | null | undefined>,
) {
  return [...items].sort(
    (left, right) =>
      newestTimestamp(getTimestampValues(right)) -
      newestTimestamp(getTimestampValues(left)),
  );
}

export function sortOldestFirst<T>(
  items: T[],
  getTimestampValues: (item: T) => Array<string | null | undefined>,
) {
  return [...items].sort(
    (left, right) =>
      newestTimestamp(getTimestampValues(left)) -
      newestTimestamp(getTimestampValues(right)),
  );
}
