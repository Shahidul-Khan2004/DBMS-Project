export function LoadingSkeleton({ lines = 3 }: { lines?: number }) {
  return (
    <div className="space-y-3" aria-hidden>
      {Array.from({ length: lines }).map((_, index) => (
        <div
          key={index}
          className="h-4 animate-pulse rounded bg-slate-200"
          style={{ width: `${92 - index * 12}%` }}
        />
      ))}
    </div>
  );
}
