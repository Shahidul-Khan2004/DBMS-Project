function titleCaseWord(word: string): string {
  if (!word) return "";
  return word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();
}

export function formatNotificationType(
  value: string | null | undefined,
): string {
  if (!value?.trim()) return "Notification";
  return value
    .split("_")
    .filter(Boolean)
    .map(titleCaseWord)
    .join(" ");
}
