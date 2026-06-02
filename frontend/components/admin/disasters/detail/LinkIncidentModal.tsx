"use client";

import { type FormEvent, useEffect, useState } from "react";
import { toast } from "sonner";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import { ApiError, getApiErrorMessage } from "@/lib/api";
import {
  getDisasterIncidentCandidates,
  postLinkDisasterIncident,
} from "@/lib/disaster-operations-api";
import type { DisasterIncidentCandidate } from "@/types/disaster-operations";

type LinkIncidentModalProps = {
  open: boolean;
  disasterPublicUuid: string;
  onClose: () => void;
  onSuccess: () => Promise<void>;
};

export function LinkIncidentModal({
  open,
  disasterPublicUuid,
  onClose,
  onSuccess,
}: LinkIncidentModalProps) {
  const [candidates, setCandidates] = useState<DisasterIncidentCandidate[]>([]);
  const [selectedUuid, setSelectedUuid] = useState("");
  const [linkNote, setLinkNote] = useState("");
  const [query, setQuery] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (!open) return;
    setSelectedUuid("");
    setLinkNote("");
    setQuery("");
    setSubmitError(null);
    setIsLoading(true);
    void getDisasterIncidentCandidates(disasterPublicUuid)
      .then((data) => setCandidates(data.incidents ?? []))
      .catch(() => setCandidates([]))
      .finally(() => setIsLoading(false));
  }, [open, disasterPublicUuid]);

  if (!open) return null;

  const filtered = candidates.filter((c) => {
    const q = query.trim().toLowerCase();
    if (!q) return true;
    return (
      (c.title ?? "").toLowerCase().includes(q) ||
      (c.incident_code ?? "").toLowerCase().includes(q)
    );
  });

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (!selectedUuid) {
      setSubmitError("Select an incident to link.");
      return;
    }
    setIsSubmitting(true);
    setSubmitError(null);
    try {
      await postLinkDisasterIncident(disasterPublicUuid, {
        incidentPublicUuid: selectedUuid,
        linkNote: linkNote.trim() || undefined,
      });
      toast.success("Incident linked.");
      onClose();
      await onSuccess();
    } catch (err) {
      setSubmitError(
        err instanceof ApiError
          ? getApiErrorMessage(err, err.message)
          : "Failed to link incident.",
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4">
      <form
        onSubmit={(e) => void handleSubmit(e)}
        className="flex max-h-[90vh] w-full max-w-lg flex-col rounded-xl border border-slate-200 bg-white shadow-xl"
      >
        <div className="border-b border-slate-100 px-5 py-4">
          <h2 className="text-lg font-semibold text-slate-900">Link Incident</h2>
        </div>
        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-5 py-4">
          {isLoading ? (
            <LoadingSkeleton lines={5} />
          ) : (
            <>
              <input
                type="search"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search incidents"
                className={triageFieldClassName}
                disabled={isSubmitting}
              />
              <ul className="max-h-52 space-y-1 overflow-y-auto overscroll-y-contain rounded-lg border border-slate-200 p-1">
                {filtered.length === 0 ? (
                  <li className="px-2 py-2 text-sm text-slate-600">
                    No linkable incidents found.
                  </li>
                ) : (
                  filtered.map((inc) => {
                    const selected = inc.incident_public_uuid === selectedUuid;
                    return (
                      <li key={inc.incident_public_uuid}>
                        <button
                          type="button"
                          disabled={isSubmitting}
                          onClick={() => setSelectedUuid(inc.incident_public_uuid)}
                          className={`w-full rounded-md px-2 py-2 text-left text-sm ${
                            selected
                              ? "bg-[#002D62] text-white"
                              : "hover:bg-slate-50"
                          }`}
                        >
                          <span className="font-medium">
                            {inc.title ?? "Incident"}
                          </span>
                          <span className={selected ? "text-white/80" : "text-slate-500"}>
                            {" "}
                            · {inc.incident_code}
                            {inc.incident_status
                              ? ` · ${formatBadgeLabel(inc.incident_status)}`
                              : ""}
                          </span>
                          {inc.in_affected_upazila ? (
                            <span className="mt-1 inline-block">
                              <Badge size="compact" tone="active">
                                In affected area
                              </Badge>
                            </span>
                          ) : null}
                        </button>
                      </li>
                    );
                  })
                )}
              </ul>
              <div>
                <FieldLabel htmlFor="link-note">Link note (optional)</FieldLabel>
                <textarea
                  id="link-note"
                  value={linkNote}
                  onChange={(e) => setLinkNote(e.target.value)}
                  rows={2}
                  className={triageFieldClassName}
                  disabled={isSubmitting}
                />
              </div>
            </>
          )}
          {submitError ? <ErrorAlert message={submitError} /> : null}
        </div>
        <div className="flex justify-end gap-2 border-t border-slate-100 px-5 py-4">
          <Button type="button" variant="secondary" onClick={onClose} disabled={isSubmitting}>
            Cancel
          </Button>
          <Button type="submit" isLoading={isSubmitting} disabled={isSubmitting || isLoading}>
            Link incident
          </Button>
        </div>
      </form>
    </div>
  );
}
