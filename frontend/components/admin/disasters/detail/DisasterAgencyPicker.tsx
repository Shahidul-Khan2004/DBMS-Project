"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import { listAdminAgencies } from "@/lib/admin-agency-api";
import type { AdminAgencyListItem } from "@/types/admin-agency";

type DisasterAgencyPickerProps = {
  selectedAgencyPublicUuid: string;
  onSelect: (agencyPublicUuid: string) => void;
  disabled?: boolean;
};

export function DisasterAgencyPicker({
  selectedAgencyPublicUuid,
  onSelect,
  disabled = false,
}: DisasterAgencyPickerProps) {
  const [agencies, setAgencies] = useState<AdminAgencyListItem[]>([]);
  const [query, setQuery] = useState("");
  const [isLoading, setIsLoading] = useState(true);

  const loadAgencies = useCallback(async () => {
    setIsLoading(true);
    try {
      const data = await listAdminAgencies({ limit: 100, offset: 0 });
      setAgencies((data.agencies ?? []).filter((a) => a.is_active));
    } catch {
      setAgencies([]);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadAgencies();
  }, [loadAgencies]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return agencies;
    return agencies.filter(
      (a) =>
        a.name.toLowerCase().includes(q) ||
        a.agency_code.toLowerCase().includes(q),
    );
  }, [agencies, query]);

  if (isLoading) {
    return <LoadingSkeleton lines={4} />;
  }

  return (
    <div className="space-y-2">
      <input
        type="search"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder="Search agencies by name or code"
        className={triageFieldClassName}
        disabled={disabled}
      />
      <ul className="max-h-48 space-y-1 overflow-y-auto overscroll-y-contain rounded-lg border border-slate-200 p-1">
        {filtered.length === 0 ? (
          <li className="px-2 py-2 text-sm text-slate-600">No agencies found.</li>
        ) : (
          filtered.map((agency) => {
            const selected = agency.public_uuid === selectedAgencyPublicUuid;
            return (
              <li key={agency.public_uuid}>
                <button
                  type="button"
                  disabled={disabled}
                  onClick={() => onSelect(agency.public_uuid)}
                  className={`w-full rounded-md px-2 py-2 text-left text-sm transition-colors ${
                    selected
                      ? "bg-[#002D62] text-white"
                      : "text-slate-900 hover:bg-slate-50"
                  }`}
                >
                  <span className="font-medium">{agency.name}</span>
                  <span
                    className={
                      selected ? "text-white/80" : "text-slate-500"
                    }
                  >
                    {" "}
                    · {agency.agency_code}
                  </span>
                </button>
              </li>
            );
          })
        )}
      </ul>
    </div>
  );
}
