"use client";

import { type FormEvent, useEffect, useState } from "react";
import { toast } from "sonner";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { ApiError, getApiErrorMessage } from "@/lib/api";
import { patchDisasterAffectedAreaAssessment } from "@/lib/disaster-operations-api";
import {
  DISASTER_IMPACT_LEVEL_OPTIONS,
  formatAffectedAreaLabel,
} from "@/lib/disaster-operations-format";
import type { DisasterAffectedArea } from "@/types/disaster-operations";

type EditAffectedAreaModalProps = {
  open: boolean;
  disasterPublicUuid: string;
  area: DisasterAffectedArea | null;
  onClose: () => void;
  onSuccess: () => Promise<void>;
};

export function EditAffectedAreaModal({
  open,
  disasterPublicUuid,
  area,
  onClose,
  onSuccess,
}: EditAffectedAreaModalProps) {
  const [impactLevel, setImpactLevel] = useState("medium");
  const [estimatedPeople, setEstimatedPeople] = useState("");
  const [shelterRequired, setShelterRequired] = useState(false);
  const [reliefRequired, setReliefRequired] = useState(false);
  const [assessmentNote, setAssessmentNote] = useState("");
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (!open || !area) return;
    setImpactLevel(area.impact_level ?? "medium");
    setEstimatedPeople(
      area.estimated_affected_people != null
        ? String(area.estimated_affected_people)
        : "",
    );
    setShelterRequired(Boolean(area.shelter_support_required));
    setReliefRequired(Boolean(area.relief_support_required));
    setAssessmentNote(area.assessment_note ?? "");
    setSubmitError(null);
  }, [open, area]);

  if (!open || !area) return null;

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setIsSubmitting(true);
    setSubmitError(null);
    try {
      const people =
        estimatedPeople.trim() === ""
          ? undefined
          : Number(estimatedPeople);
      if (people != null && (!Number.isFinite(people) || people < 0)) {
        setSubmitError("Estimated affected people must be a non-negative number.");
        setIsSubmitting(false);
        return;
      }
      await patchDisasterAffectedAreaAssessment(
        disasterPublicUuid,
        area.affected_area_public_uuid,
        {
          impactLevel: impactLevel as "low" | "medium" | "high" | "severe",
          estimatedAffectedPeople: people,
          shelterSupportRequired: shelterRequired,
          reliefSupportRequired: reliefRequired,
          assessmentNote: assessmentNote.trim() || undefined,
        },
      );
      toast.success("Assessment updated.");
      onClose();
      await onSuccess();
    } catch (err) {
      setSubmitError(
        err instanceof ApiError
          ? getApiErrorMessage(err, err.message)
          : "Failed to update assessment.",
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
          <h2 className="text-lg font-semibold text-slate-900">Edit Assessment</h2>
          <p className="mt-1 text-sm text-slate-600">{formatAffectedAreaLabel(area)}</p>
        </div>
        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-5 py-4">
          <div>
            <FieldLabel htmlFor="impact-level" required>
              Impact level
            </FieldLabel>
            <select
              id="impact-level"
              value={impactLevel}
              onChange={(e) => setImpactLevel(e.target.value)}
              className={triageFieldClassName}
              disabled={isSubmitting}
            >
              {DISASTER_IMPACT_LEVEL_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </div>
          <div>
            <FieldLabel htmlFor="estimated-people">Est. affected people</FieldLabel>
            <input
              id="estimated-people"
              type="number"
              min={0}
              value={estimatedPeople}
              onChange={(e) => setEstimatedPeople(e.target.value)}
              className={triageFieldClassName}
              disabled={isSubmitting}
            />
          </div>
          <label className="flex items-center gap-2 text-sm text-slate-700">
            <input
              type="checkbox"
              checked={shelterRequired}
              onChange={(e) => setShelterRequired(e.target.checked)}
              disabled={isSubmitting}
            />
            Shelter support required
          </label>
          <label className="flex items-center gap-2 text-sm text-slate-700">
            <input
              type="checkbox"
              checked={reliefRequired}
              onChange={(e) => setReliefRequired(e.target.checked)}
              disabled={isSubmitting}
            />
            Relief support required
          </label>
          <div>
            <FieldLabel htmlFor="assessment-note">Assessment note</FieldLabel>
            <textarea
              id="assessment-note"
              value={assessmentNote}
              onChange={(e) => setAssessmentNote(e.target.value)}
              rows={3}
              maxLength={1000}
              className={triageFieldClassName}
              disabled={isSubmitting}
            />
          </div>
          {submitError ? <ErrorAlert message={submitError} /> : null}
        </div>
        <div className="flex justify-end gap-2 border-t border-slate-100 px-5 py-4">
          <Button type="button" variant="secondary" onClick={onClose} disabled={isSubmitting}>
            Cancel
          </Button>
          <Button type="submit" isLoading={isSubmitting} disabled={isSubmitting}>
            Save assessment
          </Button>
        </div>
      </form>
    </div>
  );
}
