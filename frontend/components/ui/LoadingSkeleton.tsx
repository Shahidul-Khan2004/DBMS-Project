export function LoadingSkeleton({ lines = 3 }: { lines?: number }) {
  return (
    <div className="space-y-3 rounded-3xl border border-[#002D62]/10 bg-white p-5" aria-hidden>
      {Array.from({ length: lines }).map((_, index) => (
        <div
          key={index}
          className="h-4 animate-pulse rounded-full bg-[#002D62]/10"
          style={{ width: `${92 - index * 12}%` }}
        />
      ))}
    </div>
  );
}
