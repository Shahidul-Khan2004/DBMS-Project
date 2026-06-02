export function AgencySkeletonBlock({ className = "h-4 w-full" }: { className?: string }) {
  return (
    <div
      className={`animate-pulse rounded-lg bg-slate-200/80 ${className}`.trim()}
      aria-hidden
    />
  );
}
