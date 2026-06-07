"use client";

import { useEffect, useId, useState } from "react";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import { listOperationsDisasters } from "@/lib/disaster-operations-api";
import { filterDispatcherActiveDisasters } from "@/lib/disaster-operations-format";
import type { OperationsDisasterSummary } from "@/lib/disaster-operations-types";

type DisasterLinkSelectorProps = {
  selectedDisasterPublicUuid: string | null;
  onChange: (uuid: string | null) => void;
  disabled?: boolean;
  className?: string;
};

export function DisasterLinkSelector({
  selectedDisasterPublicUuid,
  onChange,
  disabled = false,
  className = "",
}: DisasterLinkSelectorProps) {
  const checkboxId = useId();
  const selectId = useId();
  const [activeDisasters, setActiveDisasters] = useState<
    OperationsDisasterSummary[]
  >([]);
  const [enabled, setEnabled] = useState(selectedDisasterPublicUuid != null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let cancelled = false;
    void listOperationsDisasters()
      .then((data) => {
        if (!cancelled) {
          setActiveDisasters(filterDispatcherActiveDisasters(data));
        }
      })
      .catch(() => {
        if (!cancelled) setActiveDisasters([]);
      })
      .finally(() => {
        if (!cancelled) setLoaded(true);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!enabled) {
      if (selectedDisasterPublicUuid != null) onChange(null);
      return;
    }
    if (activeDisasters.length === 1 && !selectedDisasterPublicUuid) {
      onChange(activeDisasters[0].public_uuid);
    }
  }, [
    activeDisasters,
    enabled,
    onChange,
    selectedDisasterPublicUuid,
  ]);

  if (!loaded || activeDisasters.length === 0) {
    return null;
  }

  const isDisabled = disabled;

  return (
    <div
      className={`rounded-lg border border-[#006747]/25 bg-[#F0F7F4] p-2.5 ${className}`.trim()}
    >
      <label
        htmlFor={checkboxId}
        className="flex cursor-pointer items-start gap-2 text-sm text-slate-700"
      >
        <input
          id={checkboxId}
          type="checkbox"
          checked={enabled}
          disabled={isDisabled}
          onChange={(event) => {
            const next = event.target.checked;
            setEnabled(next);
            if (!next) onChange(null);
          }}
          className="mt-0.5 h-4 w-4 shrink-0 rounded border-slate-300 text-[#006747] focus:ring-[#006747]/30"
        />
        <span>Attach resulting incident to national disaster</span>
      </label>

      {enabled ? (
        <div className="mt-2">
          <label
            htmlFor={selectId}
            className="mb-1 block text-sm font-medium text-[#006747]"
          >
            Disaster:
          </label>
          <select
            id={selectId}
            value={selectedDisasterPublicUuid ?? ""}
            disabled={isDisabled}
            onChange={(event) => {
              const value = event.target.value;
              onChange(value || null);
            }}
            className={triageFieldClassName}
          >
            <option value="">Select an active disaster</option>
            {activeDisasters.map((disaster) => (
              <option key={disaster.public_uuid} value={disaster.public_uuid}>
                {disaster.event_code} — {disaster.title}
              </option>
            ))}
          </select>
        </div>
      ) : null}
    </div>
  );
}
