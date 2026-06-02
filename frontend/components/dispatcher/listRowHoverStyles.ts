type SelectableRowVariant = "card" | "flat" | "inset";

interface SelectableRowClassOptions {
  selected?: boolean;
  disabled?: boolean;
  variant?: SelectableRowVariant;
}

const SELECTED_ROW_CLASSES =
  "border-[#002D62]/35 bg-[#E8F2FF] ring-1 ring-[#002D62]/15 hover:bg-[#DCEBFF]/70";

const DISABLED_ROW_CLASSES =
  "cursor-not-allowed border-slate-100 bg-slate-50/80 opacity-70";

const HOVER_BY_VARIANT: Record<SelectableRowVariant, string> = {
  card: "hover:bg-[#F0F7F4] hover:border-[#006747]/25 hover:shadow-md hover:shadow-[#006747]/10",
  flat: "hover:bg-[#F0F7F4] hover:border-[#006747]/25",
  inset: "hover:bg-[#F0F7F4]",
};

/** Clickable/selectable dispatcher list or card row surfaces. */
export function getDispatcherSelectableRowClasses({
  selected = false,
  disabled = false,
  variant = "flat",
}: SelectableRowClassOptions = {}): string {
  if (disabled) {
    return DISABLED_ROW_CLASSES;
  }

  if (selected) {
    return `cursor-pointer transition-colors duration-150 ${SELECTED_ROW_CLASSES}`;
  }

  const shadow = variant === "card" ? "shadow-sm" : "";
  return `cursor-pointer border-slate-200/90 bg-white transition-all duration-150 ${HOVER_BY_VARIANT[variant]} ${shadow}`.trim();
}

/** Link-style card rows that always include shadow and rounded border treatment. */
export function getDispatcherClickableCardRowClasses(
  options: Omit<SelectableRowClassOptions, "variant"> = {},
): string {
  return getDispatcherSelectableRowClasses({ ...options, variant: "card" });
}

/** Flat selectable rows inside dialogs and forms. */
export function getDispatcherClickableFlatRowClasses(
  options: Omit<SelectableRowClassOptions, "variant"> = {},
): string {
  return getDispatcherSelectableRowClasses({ ...options, variant: "flat" });
}

/** Inset list rows (notifications, linked reports) without border hover emphasis. */
export function getDispatcherClickableInsetRowClasses(): string {
  return "transition-colors duration-150 hover:bg-[#F0F7F4]";
}

/** Unread notification row base — blue tint means current/unread, green only on hover. */
export function getDispatcherNotificationRowClasses(unread: boolean): string {
  return unread
    ? "border-l-2 border-l-[#002D62]/40 bg-[#EFF6FF]/40 hover:bg-[#F0F7F4]"
    : `${getDispatcherClickableInsetRowClasses()} border-l-2 border-l-transparent`;
}
