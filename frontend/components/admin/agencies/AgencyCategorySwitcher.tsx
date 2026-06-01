"use client";

import type { AgencyCategoryOption } from "@/lib/admin-agency-types";

type AgencyCategorySwitcherProps = {
  options: AgencyCategoryOption[];
  selectedCode: string;
  onSelect: (code: string) => void;
  disabled?: boolean;
};

export function AgencyCategorySwitcher({
  options,
  selectedCode,
  onSelect,
  disabled = false,
}: AgencyCategorySwitcherProps) {
  if (options.length === 0) {
    return null;
  }

  return (
    <div
      className="flex flex-wrap gap-2"
      role="tablist"
      aria-label="Agency category"
    >
      {options.map((option) => {
        const active = option.code === selectedCode;
        return (
          <button
            key={option.code}
            type="button"
            role="tab"
            aria-selected={active}
            disabled={disabled}
            onClick={() => onSelect(option.code)}
            className={`cursor-pointer rounded-md px-3 py-1.5 text-sm font-medium transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#002D62] disabled:cursor-not-allowed disabled:opacity-50 ${
              active
                ? "bg-[#002D62] text-white shadow-sm"
                : "border border-slate-200 bg-white text-slate-600 hover:bg-slate-50"
            }`}
          >
            {option.label} {option.count}
          </button>
        );
      })}
    </div>
  );
}
