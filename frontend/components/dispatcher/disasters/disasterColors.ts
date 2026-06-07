/** Dispatcher national disaster protocol palette — green, distinct from emergency red. */
export const DISPATCHER_DISASTER = {
  default: "#006747",
  hover: "#00543A",
  active: "#004530",
  bg: "#F0F7F4",
  text: "#006747",
} as const;

export function getDisasterPrimaryButtonClasses(active = false): string {
  return [
    "inline-flex shrink-0 cursor-pointer items-center rounded-md border border-[#006747] bg-[#006747] px-3 py-1.5 text-sm font-medium text-white shadow-sm transition-colors hover:bg-[#00543A] hover:border-[#00543A]",
    active ? getDisasterActiveRingClasses() : "",
  ]
    .filter(Boolean)
    .join(" ");
}

export function getDisasterOutlineButtonClasses(): string {
  return "inline-flex shrink-0 cursor-pointer items-center rounded-md border-2 border-[#006747] bg-white px-3 py-1.5 text-sm font-medium text-[#006747] shadow-sm transition-colors hover:bg-[#F0F7F4]";
}

export function getDisasterActiveRingClasses(): string {
  return "ring-2 ring-[#006747]/30 ring-offset-1";
}

export function getDisasterSegmentActiveClasses(): string {
  return "bg-[#F0F7F4] text-[#006747] shadow-sm";
}
