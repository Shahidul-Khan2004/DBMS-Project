/**
 * Timestamp helpers for SQL-bound parameters (works for MySQL and PostgreSQL).
 */
export function toSqlDateTimeOrNull(value) {
  if (!value) return null;

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return null;
  }

  return date.toISOString().slice(0, 19).replace("T", " ");
}

/** @deprecated use toSqlDateTimeOrNull */
export const toMySqlDateTimeOrNull = toSqlDateTimeOrNull;
