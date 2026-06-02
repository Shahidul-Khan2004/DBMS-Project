"use client";

import { type FormEvent, useState } from "react";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import { ResponseTimingDisplay } from "@/components/admin/reports/ResponseTimingDisplay";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import { ApiError } from "@/lib/api";
import { getIncidentResponseTiming } from "@/lib/admin-reports-api";
import { UUID_PATTERN } from "@/lib/admin-role-errors";
import type { OperationsResponseTiming } from "@/types/operations-incident";

export function ResponseTimingReport() {
  const [incidentUuid, setIncidentUuid] = useState("");
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [forbidden, setForbidden] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [timing, setTiming] = useState<OperationsResponseTiming | null>(null);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const trimmed = incidentUuid.trim();
    if (!trimmed) {
      setFieldError("Incident public UUID is required.");
      return;
    }
    if (!UUID_PATTERN.test(trimmed)) {
      setFieldError("Enter a valid incident public UUID.");
      return;
    }

    setFieldError(null);
    setSubmitError(null);
    setForbidden(false);
    setIsLoading(true);
    setTiming(null);

    try {
      const data = await getIncidentResponseTiming(trimmed);
      setTiming(data.timing);
    } catch (err) {
      if (err instanceof ApiError && err.status === 403) {
        setForbidden(true);
      } else {
        setSubmitError(
          err instanceof ApiError
            ? err.message
            : err instanceof Error
              ? err.message
              : "Failed to load response timing.",
        );
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <form
        className="flex flex-wrap items-end gap-3"
        onSubmit={(event) => void handleSubmit(event)}
      >
        <div className="min-w-[16rem] flex-1">
          <FieldLabel htmlFor="timing-incident-uuid" required>
            Incident public UUID
          </FieldLabel>
          <input
            id="timing-incident-uuid"
            type="text"
            value={incidentUuid}
            onChange={(e) => {
              setIncidentUuid(e.target.value);
              setFieldError(null);
              setSubmitError(null);
            }}
            className={triageFieldClassName}
            autoComplete="off"
            required
          />
          {fieldError ? (
            <p className="mt-1 text-xs text-red-600">{fieldError}</p>
          ) : null}
        </div>
        <Button type="submit" size="sm" isLoading={isLoading}>
          Load timing
        </Button>
      </form>

      {submitError ? <ErrorAlert message={submitError} /> : null}

      {forbidden ? (
        <p className="text-sm text-slate-600">
          You do not have permission to view incident response timing.
        </p>
      ) : null}

      {isLoading ? <LoadingSkeleton lines={6} /> : null}

      {timing && !isLoading ? <ResponseTimingDisplay timing={timing} /> : null}
    </div>
  );
}
