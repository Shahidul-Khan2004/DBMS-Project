export const NOTIFICATION_POPOVER_WIDTH = 440;
const GAP_BELOW_BELL_PX = 8;
const VIEWPORT_MARGIN_PX = 16;
const MAX_POPOVER_HEIGHT_PX = 520;
const BOTTOM_SAFE_PX = 24;

export type PopoverPosition = {
  top: number;
  left: number;
  width: number;
  maxHeight: number;
};

export function computeNotificationPopoverPosition(
  bellRect: DOMRect,
  viewport: { width: number; height: number } = {
    width: window.innerWidth,
    height: window.innerHeight,
  },
): PopoverPosition {
  const width = Math.min(
    NOTIFICATION_POPOVER_WIDTH,
    viewport.width - VIEWPORT_MARGIN_PX * 2,
  );
  const top = bellRect.bottom + GAP_BELOW_BELL_PX;

  let left = bellRect.right - width;
  if (left < VIEWPORT_MARGIN_PX) {
    left = VIEWPORT_MARGIN_PX;
  }
  if (left + width > viewport.width - VIEWPORT_MARGIN_PX) {
    left = viewport.width - VIEWPORT_MARGIN_PX - width;
  }

  const maxHeight = Math.min(
    MAX_POPOVER_HEIGHT_PX,
    viewport.height - top - BOTTOM_SAFE_PX,
  );

  return {
    top,
    left,
    width,
    maxHeight: Math.max(maxHeight, 120),
  };
}
