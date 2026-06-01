"use client";

interface ArchiveSegmentedControlOption<T extends string> {
  value: T;
  label: string;
}

interface ArchiveSegmentedControlProps<T extends string> {
  label: string;
  value: T;
  options: ReadonlyArray<ArchiveSegmentedControlOption<T>>;
  onChange: (value: T) => void;
  ariaLabel?: string;
}

export function ArchiveSegmentedControl<T extends string>({
  label,
  value,
  options,
  onChange,
  ariaLabel,
}: ArchiveSegmentedControlProps<T>) {
  const controlId = label.toLowerCase().replace(/\s+/g, "-");

  return (
    <div className="flex min-w-0 flex-col gap-1.5">
      <span
        id={`${controlId}-label`}
        className="text-xs font-medium uppercase tracking-wide text-slate-500"
      >
        {label}
      </span>
      <div
        role="tablist"
        aria-label={ariaLabel ?? label}
        aria-labelledby={`${controlId}-label`}
        className="inline-flex w-fit max-w-full flex-wrap gap-1 rounded-lg border border-slate-200 bg-slate-50/80 p-1"
      >
        {options.map((option) => {
          const isActive = option.value === value;
          return (
            <button
              key={option.value}
              type="button"
              role="tab"
              aria-selected={isActive}
              tabIndex={isActive ? 0 : -1}
              onClick={() => onChange(option.value)}
              className={`inline-flex shrink-0 items-center rounded-md px-3 py-1.5 text-sm font-medium transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#002D62] ${
                isActive
                  ? "bg-[#E8F2FF] text-[#002D62] shadow-sm"
                  : "text-slate-600 hover:bg-slate-100 hover:text-slate-900"
              }`}
            >
              {option.label}
            </button>
          );
        })}
      </div>
    </div>
  );
}
