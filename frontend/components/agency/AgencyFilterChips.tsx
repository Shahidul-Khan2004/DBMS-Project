"use client";

const chipClass = (active: boolean) =>
  `shrink-0 rounded-full px-3 py-1 text-xs font-medium transition-colors ${
    active
      ? "bg-[#002D62] text-white"
      : "border border-slate-200 bg-white text-slate-600 hover:bg-slate-50"
  }`;

export function AgencyFilterChips<T extends string>({
  options,
  value,
  onChange,
}: {
  options: Array<{ value: T; label: string }>;
  value: T;
  onChange: (value: T) => void;
}) {
  return (
    <div className="flex flex-wrap gap-2" role="tablist">
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          role="tab"
          aria-selected={value === option.value}
          className={chipClass(value === option.value)}
          onClick={() => onChange(option.value)}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}
