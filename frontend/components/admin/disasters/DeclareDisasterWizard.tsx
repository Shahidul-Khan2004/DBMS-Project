"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  type FormEvent,
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { ApiError, getApiErrorMessage } from "@/lib/api";
import {
  addDisasterAffectedAreas,
  createDisaster,
  postInitialDisasterDeclaration,
} from "@/lib/disaster-operations-api";
import {
  DISASTER_EVENT_TYPE_OPTIONS,
  DISASTER_SEVERITY_OPTIONS,
} from "@/lib/disaster-operations-format";
import { searchAdministrativeAreas } from "@/lib/reference-api";
import type {
  DisasterAssessmentInput,
  DisasterDashboardResponse,
} from "@/types/disaster-operations";
import type { AdministrativeAreaSearchResult } from "@/types/reference";
import { toast } from "sonner";

const STEPS = ["Event", "Affected Areas", "Declaration"] as const;

type AreaMode = "upazila" | "district";

function getStepPillClasses(active: boolean, clickable: boolean) {
  if (active) {
    return "border border-[#002D62] bg-[#002D62] text-white";
  }
  if (clickable) {
    return "border border-[#B7D4F5] bg-[#E8F2FF] text-[#002D62] hover:border-[#8DBEEF] hover:bg-[#D8EAFF]";
  }
  return "border border-slate-200 bg-slate-100 text-slate-500";
}

function buildAssessment(
  estimatedAffectedPeople: string,
  assessmentNote: string,
  impactLevel: string,
  shelterSupportRequired: boolean,
  reliefSupportRequired: boolean,
): DisasterAssessmentInput | undefined {
  const people = estimatedAffectedPeople.trim();
  const note = assessmentNote.trim();
  const impact = impactLevel.trim();

  if (!people && !note && !impact && !shelterSupportRequired && !reliefSupportRequired) {
    return undefined;
  }

  const assessment: DisasterAssessmentInput = {};
  if (people) {
    const n = Number.parseInt(people, 10);
    if (Number.isFinite(n) && n >= 0) {
      assessment.estimatedAffectedPeople = n;
    }
  }
  if (note) assessment.assessmentNote = note;
  if (
    impact === "low" ||
    impact === "medium" ||
    impact === "high" ||
    impact === "severe"
  ) {
    assessment.impactLevel = impact;
  }
  if (shelterSupportRequired) assessment.shelterSupportRequired = true;
  if (reliefSupportRequired) assessment.reliefSupportRequired = true;
  return assessment;
}

export function DeclareDisasterWizard() {
  const router = useRouter();
  const [step, setStep] = useState(0);
  const [eventDraftReady, setEventDraftReady] = useState(false);
  const [disasterPublicUuid, setDisasterPublicUuid] = useState<string | null>(
    null,
  );
  const [dashboard, setDashboard] = useState<DisasterDashboardResponse | null>(
    null,
  );
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [eventTypeCode, setEventTypeCode] = useState<string>(
    DISASTER_EVENT_TYPE_OPTIONS[0].value,
  );
  const [title, setTitle] = useState("");
  const [severityLevel, setSeverityLevel] = useState("high");
  const [description, setDescription] = useState("");
  const [startedAt, setStartedAt] = useState("");

  const [areaMode, setAreaMode] = useState<AreaMode>("upazila");
  const [areaQuery, setAreaQuery] = useState("");
  const [searchResults, setSearchResults] = useState<
    AdministrativeAreaSearchResult[]
  >([]);
  const [isSearching, setIsSearching] = useState(false);
  const [selectedUpazilas, setSelectedUpazilas] = useState<
    AdministrativeAreaSearchResult[]
  >([]);
  const [selectedDistricts, setSelectedDistricts] = useState<
    AdministrativeAreaSearchResult[]
  >([]);
  const [estimatedAffectedPeople, setEstimatedAffectedPeople] = useState("");
  const [assessmentNote, setAssessmentNote] = useState("");
  const [impactLevel, setImpactLevel] = useState("");
  const [shelterSupportRequired, setShelterSupportRequired] = useState(false);
  const [reliefSupportRequired, setReliefSupportRequired] = useState(false);

  const [declarationTitle, setDeclarationTitle] = useState("");
  const [publicGuidance, setPublicGuidance] = useState("");
  const [reason, setReason] = useState("");
  const [legalReference, setLegalReference] = useState("");

  const [isComplete, setIsComplete] = useState(false);
  const [areasCompleted, setAreasCompleted] = useState(false);
  const [maxStepReached, setMaxStepReached] = useState(0);

  const eventCompleted = eventDraftReady;

  const invalidateAreasCompletion = useCallback(() => {
    setAreasCompleted(false);
    setMaxStepReached((prev) => Math.min(prev, 1));
  }, []);

  const invalidateAreasOnEventEdit = useCallback(() => {
    if (areasCompleted) {
      setAreasCompleted(false);
      setMaxStepReached((prev) => Math.min(prev, 1));
    }
  }, [areasCompleted]);

  const resetWizard = useCallback(() => {
    setStep(0);
    setEventDraftReady(false);
    setDisasterPublicUuid(null);
    setDashboard(null);
    setError(null);
    setEventTypeCode(DISASTER_EVENT_TYPE_OPTIONS[0].value);
    setTitle("");
    setSeverityLevel("high");
    setDescription("");
    setStartedAt("");
    setAreaMode("upazila");
    setAreaQuery("");
    setSearchResults([]);
    setSelectedUpazilas([]);
    setSelectedDistricts([]);
    setEstimatedAffectedPeople("");
    setAssessmentNote("");
    setImpactLevel("");
    setShelterSupportRequired(false);
    setReliefSupportRequired(false);
    setDeclarationTitle("");
    setPublicGuidance("");
    setReason("");
    setLegalReference("");
    setIsComplete(false);
    setAreasCompleted(false);
    setMaxStepReached(0);
  }, []);

  useEffect(() => {
    const q = areaQuery.trim();
    if (q.length < 2) {
      setSearchResults([]);
      return;
    }

    const timer = window.setTimeout(() => {
      void (async () => {
        setIsSearching(true);
        try {
          const data = await searchAdministrativeAreas({
            areaType: areaMode === "district" ? "district" : "upazila",
            q,
            limit: 20,
          });
          setSearchResults(data.areas);
        } catch {
          setSearchResults([]);
        } finally {
          setIsSearching(false);
        }
      })();
    }, 300);

    return () => window.clearTimeout(timer);
  }, [areaQuery, areaMode]);

  useEffect(() => {
    if (step === 2 && !areasCompleted) {
      setStep(1);
    }
  }, [step, areasCompleted]);

  useEffect(() => {
    setMaxStepReached((prev) => Math.max(prev, step));
  }, [step]);

  const stepNav = useMemo(
    () =>
      STEPS.map((label, index) => {
        const active = step === index;
        const completed =
          index === 0
            ? eventCompleted
            : index === 1
              ? areasCompleted
              : false;
        const clickable =
          active ||
          completed ||
          (index <= maxStepReached && !(index === 2 && !areasCompleted));
        return { label, index, active, completed, clickable };
      }),
    [step, eventCompleted, areasCompleted, maxStepReached],
  );

  const handleStepNavigate = useCallback(
    (targetStep: number) => {
      const target = stepNav[targetStep];
      if (!target?.clickable || target.active) return;
      setError(null);
      setStep(targetStep);
    },
    [stepNav],
  );

  const handleCreateEvent = (event: FormEvent) => {
    event.preventDefault();
    if (!title.trim()) {
      setError("Title is required.");
      return;
    }

    setError(null);
    setEventDraftReady(true);
    if (!declarationTitle.trim()) {
      setDeclarationTitle(title.trim());
    }
    setMaxStepReached(1);
    setStep(1);
  };

  const addUpazila = (area: AdministrativeAreaSearchResult) => {
    invalidateAreasCompletion();
    setSelectedUpazilas((prev) =>
      prev.some((a) => a.id === area.id) ? prev : [...prev, area],
    );
    setAreaQuery("");
    setSearchResults([]);
  };

  const addDistrict = (area: AdministrativeAreaSearchResult) => {
    invalidateAreasCompletion();
    setSelectedDistricts((prev) =>
      prev.some((a) => a.id === area.id) ? prev : [...prev, area],
    );
    setAreaQuery("");
    setSearchResults([]);
  };

  const handleAddAffectedAreas = async (event: FormEvent) => {
    event.preventDefault();

    if (areaMode === "upazila") {
      if (selectedUpazilas.length === 0) {
        setError("Select at least one upazila.");
        return;
      }
    } else if (selectedDistricts.length === 0) {
      setError("Select at least one district.");
      return;
    }

    setError(null);
    setAreasCompleted(true);
    setStep(2);
  };

  const handleDeclare = async (event: FormEvent) => {
    event.preventDefault();

    if (!declarationTitle.trim()) {
      setError("Declaration title is required.");
      return;
    }
    if (!publicGuidance.trim()) {
      setError("Public guidance is required.");
      return;
    }
    if (!reason.trim()) {
      setError("Reason is required.");
      return;
    }

    setError(null);
    setIsSubmitting(true);
    try {
      const createBody: Parameters<typeof createDisaster>[0] = {
        eventTypeCode,
        title: title.trim(),
        severityLevel,
      };
      const desc = description.trim();
      if (desc) createBody.description = desc;
      if (startedAt.trim()) {
        createBody.startedAt = new Date(startedAt).toISOString();
      }

      const created = await createDisaster(createBody);
      const disasterUuid = created.disaster.public_uuid;
      setDisasterPublicUuid(disasterUuid);

      const assessment = buildAssessment(
        estimatedAffectedPeople,
        assessmentNote,
        impactLevel,
        shelterSupportRequired,
        reliefSupportRequired,
      );
      if (areaMode === "upazila") {
        await addDisasterAffectedAreas(disasterUuid, {
          upazilaAdminAreaIds: selectedUpazilas.map((a) => a.id),
          ...(assessment ? { assessment } : {}),
        });
      } else {
        for (const district of selectedDistricts) {
          await addDisasterAffectedAreas(disasterUuid, {
            districtAdminAreaId: district.id,
            ...(assessment ? { assessment } : {}),
          });
        }
      }

      const declared = await postInitialDisasterDeclaration(disasterUuid, {
        title: declarationTitle.trim(),
        publicGuidance: publicGuidance.trim(),
        reason: reason.trim(),
        ...(legalReference.trim()
          ? { legalReference: legalReference.trim() }
          : {}),
      });

      setDashboard(declared);
      setIsComplete(true);
      toast.success("Disaster declared successfully.");
    } catch (err) {
      setError(
        err instanceof ApiError
          ? getApiErrorMessage(err, err.message)
          : err instanceof Error
            ? err.message
            : "Failed to issue declaration.",
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  if (isComplete && disasterPublicUuid) {
    return (
      <div className="mx-auto flex w-full max-w-lg flex-col items-center gap-4 rounded-xl border border-slate-200/90 bg-white p-8 text-center shadow-sm">
        <h2 className="text-xl font-semibold text-slate-900">
          Disaster declared successfully.
        </h2>
        <p className="text-sm text-slate-600">
          {dashboard?.disaster.event_code
            ? `Event ${dashboard.disaster.event_code} is now in declared status.`
            : "The disaster is now in declared status."}
        </p>
        <div className="flex flex-wrap justify-center gap-2 pt-2">
          <Button
            type="button"
            onClick={() =>
              router.push(
                `/dashboard/admin/disasters/${encodeURIComponent(disasterPublicUuid)}`,
              )
            }
          >
            Open Disaster Dashboard
          </Button>
          <Button type="button" variant="secondary" onClick={resetWizard}>
            Declare Another Disaster
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-4">
      <div className="shrink-0">
        <Link
          href="/dashboard/admin/disasters"
          className="text-sm font-medium text-[#002D62] hover:underline"
        >
          ← Natural Disasters
        </Link>
        <h2 className="mt-2 text-xl font-semibold text-slate-900">
          Declare disaster
        </h2>
      </div>

      <nav
        aria-label="Declaration progress"
        className="flex flex-wrap gap-2"
      >
        {stepNav.map(({ label, index, active, completed, clickable }) => (
          <button
            key={label}
            type="button"
            aria-current={active ? "step" : undefined}
            disabled={!clickable}
            onClick={() => handleStepNavigate(index)}
            className={`rounded-full px-3 py-1 text-xs font-semibold transition-colors ${getStepPillClasses(
              active,
              clickable,
            )} ${clickable ? "cursor-pointer" : "cursor-not-allowed"}`}
          >
            {completed && !active ? (
              <span className="mr-1 inline-block text-[10px] opacity-80" aria-hidden>
                ✓
              </span>
            ) : null}
            {index + 1}. {label}
          </button>
        ))}
      </nav>

      <div className="rounded-xl border border-slate-200/90 bg-white p-5 shadow-sm sm:p-6">
        {error ? (
          <div className="mb-4">
            <ErrorAlert message={error} />
          </div>
        ) : null}

        {step === 0 ? (
          <form onSubmit={handleCreateEvent} className="space-y-4">
            <div>
              <FieldLabel htmlFor="event-type" required>
                Event type
              </FieldLabel>
              <select
                id="event-type"
                value={eventTypeCode}
                onChange={(e) => {
                  invalidateAreasOnEventEdit();
                  setEventTypeCode(e.target.value);
                }}
                className={triageFieldClassName}
                disabled={isSubmitting}
              >
                {DISASTER_EVENT_TYPE_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <FieldLabel htmlFor="disaster-title" required>
                Title
              </FieldLabel>
              <input
                id="disaster-title"
                type="text"
                value={title}
                onChange={(e) => {
                  invalidateAreasOnEventEdit();
                  setTitle(e.target.value);
                }}
                className={triageFieldClassName}
                disabled={isSubmitting}
              />
            </div>
            <div>
              <FieldLabel htmlFor="severity" required>
                Severity
              </FieldLabel>
              <select
                id="severity"
                value={severityLevel}
                onChange={(e) => {
                  invalidateAreasOnEventEdit();
                  setSeverityLevel(e.target.value);
                }}
                className={triageFieldClassName}
                disabled={isSubmitting}
              >
                {DISASTER_SEVERITY_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <FieldLabel htmlFor="description">Description</FieldLabel>
              <textarea
                id="description"
                value={description}
                onChange={(e) => {
                  invalidateAreasOnEventEdit();
                  setDescription(e.target.value);
                }}
                className={`${triageFieldClassName} min-h-[72px] resize-y`}
                rows={2}
                disabled={isSubmitting}
              />
            </div>
            <div>
              <FieldLabel htmlFor="started-at">Started at</FieldLabel>
              <input
                id="started-at"
                type="datetime-local"
                value={startedAt}
                onChange={(e) => {
                  invalidateAreasOnEventEdit();
                  setStartedAt(e.target.value);
                }}
                className={triageFieldClassName}
                disabled={isSubmitting}
              />
            </div>
            <div className="flex justify-end">
              <Button type="submit" isLoading={isSubmitting}>
                Continue to affected areas
              </Button>
            </div>
          </form>
        ) : null}

        {step === 1 ? (
          <form
            onSubmit={(e) => void handleAddAffectedAreas(e)}
            className="space-y-4"
          >
            <fieldset>
              <legend className="mb-2 text-sm font-semibold text-slate-900">
                Area selection mode
              </legend>
              <div className="flex flex-wrap gap-4">
                <label
                  className={`flex cursor-pointer items-center gap-2 text-sm transition-colors hover:text-[#002D62] ${
                    areaMode === "upazila"
                      ? "font-medium text-[#002D62]"
                      : "text-slate-600"
                  }`}
                >
                  <input
                    type="radio"
                    name="area-mode"
                    checked={areaMode === "upazila"}
                    onChange={() => {
                      invalidateAreasCompletion();
                      setAreaMode("upazila");
                      setSelectedDistricts([]);
                      setAreaQuery("");
                      setSearchResults([]);
                    }}
                    disabled={isSubmitting}
                    className="size-3.5 accent-[#002D62]"
                  />
                  Specific Upazilas
                </label>
                <label
                  className={`flex cursor-pointer items-center gap-2 text-sm transition-colors hover:text-[#002D62] ${
                    areaMode === "district"
                      ? "font-medium text-[#002D62]"
                      : "text-slate-600"
                  }`}
                >
                  <input
                    type="radio"
                    name="area-mode"
                    checked={areaMode === "district"}
                    onChange={() => {
                      invalidateAreasCompletion();
                      setAreaMode("district");
                      setSelectedUpazilas([]);
                      setAreaQuery("");
                      setSearchResults([]);
                    }}
                    disabled={isSubmitting}
                    className="size-3.5 accent-[#002D62]"
                  />
                  Whole District
                </label>
              </div>
            </fieldset>

            <div>
              <FieldLabel htmlFor="area-search">
                Search {areaMode === "district" ? "districts" : "upazilas"}
              </FieldLabel>
              <input
                id="area-search"
                type="search"
                value={areaQuery}
                onChange={(e) => setAreaQuery(e.target.value)}
                className={triageFieldClassName}
                placeholder="Type at least 2 characters…"
                disabled={isSubmitting}
              />
              {isSearching ? (
                <p className="mt-1 text-xs text-slate-500">Searching…</p>
              ) : null}
              {searchResults.length > 0 ? (
                <ul className="mt-2 max-h-40 overflow-y-auto rounded-lg border border-slate-200">
                  {searchResults.map((area) => (
                    <li key={area.id} className="border-b border-slate-100 last:border-0">
                      <button
                        type="button"
                        className="w-full px-3 py-2 text-left text-sm hover:bg-slate-50"
                        onClick={() => {
                          if (areaMode === "district") {
                            addDistrict(area);
                          } else {
                            addUpazila(area);
                          }
                        }}
                        disabled={isSubmitting}
                      >
                        <span className="font-medium text-slate-900">
                          {area.name}
                        </span>
                        <span className="mt-0.5 block text-xs text-slate-500">
                          {area.hierarchyPath}
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              ) : null}
            </div>

            {areaMode === "upazila" && selectedUpazilas.length > 0 ? (
              <div>
                <p className="mb-2 text-xs font-medium text-slate-600">
                  Selected upazilas
                </p>
                <ul className="flex flex-wrap gap-2">
                  {selectedUpazilas.map((area) => (
                    <li
                      key={area.id}
                      className="flex w-full items-start gap-1 rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs sm:w-auto sm:items-center sm:rounded-full"
                    >
                      <span className="min-w-0 break-words text-slate-800">
                        {area.name}
                        <span className="text-slate-600">
                          {" "}
                          · {area.hierarchyPath}
                        </span>
                      </span>
                      <button
                        type="button"
                        className="ml-1 text-slate-500 hover:text-red-600"
                        onClick={() => {
                          invalidateAreasCompletion();
                          setSelectedUpazilas((prev) =>
                            prev.filter((a) => a.id !== area.id),
                          );
                        }}
                        aria-label={`Remove ${area.name}`}
                        disabled={isSubmitting}
                      >
                        ×
                      </button>
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}

            {areaMode === "district" && selectedDistricts.length > 0 ? (
              <div>
                <p className="mb-2 text-xs font-medium text-slate-600">
                  Selected districts
                </p>
                <ul className="flex flex-wrap gap-2">
                  {selectedDistricts.map((area) => (
                    <li
                      key={area.id}
                      className="flex w-full items-start gap-1 rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs sm:w-auto sm:items-center sm:rounded-full"
                    >
                      <span className="min-w-0 break-words text-slate-800">
                        {area.name}
                        <span className="text-slate-600">
                          {" "}
                          · {area.hierarchyPath}
                        </span>
                      </span>
                      <button
                        type="button"
                        className="ml-1 text-slate-500 hover:text-red-600"
                        onClick={() => {
                          invalidateAreasCompletion();
                          setSelectedDistricts((prev) =>
                            prev.filter((a) => a.id !== area.id),
                          );
                        }}
                        aria-label={`Remove ${area.name}`}
                        disabled={isSubmitting}
                      >
                        ×
                      </button>
                    </li>
                  ))}
                </ul>
                <p className="mt-2 text-xs text-slate-500">
                  Backend will expand each selected district to all upazilas.
                </p>
              </div>
            ) : null}

            {areaMode === "upazila" && selectedUpazilas.length === 0 ? (
              <p className="text-sm text-slate-500">No affected areas selected.</p>
            ) : null}
            {areaMode === "district" && selectedDistricts.length === 0 ? (
              <p className="text-sm text-slate-500">No affected areas selected.</p>
            ) : null}

            <div className="border-t border-slate-100 pt-4">
              <p className="mb-3 text-sm font-semibold text-slate-900">
                Assessment (optional)
              </p>
              <div className="grid gap-3 sm:grid-cols-2">
                <div>
                  <FieldLabel htmlFor="estimated-people">
                    Estimated affected people
                  </FieldLabel>
                  <input
                    id="estimated-people"
                    type="number"
                    min={0}
                    value={estimatedAffectedPeople}
                    onChange={(e) => {
                      invalidateAreasCompletion();
                      setEstimatedAffectedPeople(e.target.value);
                    }}
                    className={triageFieldClassName}
                    disabled={isSubmitting}
                  />
                </div>
                <div>
                  <FieldLabel htmlFor="impact-level">Impact level</FieldLabel>
                  <select
                    id="impact-level"
                    value={impactLevel}
                    onChange={(e) => {
                      invalidateAreasCompletion();
                      setImpactLevel(e.target.value);
                    }}
                    className={triageFieldClassName}
                    disabled={isSubmitting}
                  >
                    <option value="">—</option>
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                    <option value="severe">Severe</option>
                  </select>
                </div>
                <div className="sm:col-span-2">
                  <p className="mb-2 text-xs font-medium text-slate-600">
                    Support requirements
                  </p>
                  <div className="flex flex-col gap-2 sm:flex-row sm:gap-5">
                    <label className="flex cursor-pointer items-center gap-2 text-sm text-slate-700">
                      <input
                        type="checkbox"
                        checked={shelterSupportRequired}
                        onChange={(e) => {
                          invalidateAreasCompletion();
                          setShelterSupportRequired(e.target.checked);
                        }}
                        className="size-3.5 rounded border-slate-300 accent-[#002D62]"
                        disabled={isSubmitting}
                      />
                      Shelter support required
                    </label>
                    <label className="flex cursor-pointer items-center gap-2 text-sm text-slate-700">
                      <input
                        type="checkbox"
                        checked={reliefSupportRequired}
                        onChange={(e) => {
                          invalidateAreasCompletion();
                          setReliefSupportRequired(e.target.checked);
                        }}
                        className="size-3.5 rounded border-slate-300 accent-[#002D62]"
                        disabled={isSubmitting}
                      />
                      Relief support required
                    </label>
                  </div>
                </div>
                <div className="sm:col-span-2">
                  <FieldLabel htmlFor="assessment-note">Assessment note</FieldLabel>
                  <textarea
                    id="assessment-note"
                    value={assessmentNote}
                    onChange={(e) => {
                      invalidateAreasCompletion();
                      setAssessmentNote(e.target.value);
                    }}
                    className={`${triageFieldClassName} min-h-[72px] resize-y`}
                    rows={2}
                    disabled={isSubmitting}
                  />
                </div>
              </div>
            </div>

            <div className="flex justify-between gap-2">
              <Button
                type="button"
                variant="secondary"
                onClick={() => handleStepNavigate(0)}
                disabled={isSubmitting}
              >
                Back
              </Button>
              <Button type="submit" isLoading={isSubmitting}>
                Continue to declaration
              </Button>
            </div>
          </form>
        ) : null}

        {step === 2 ? (
          <form onSubmit={(e) => void handleDeclare(e)} className="space-y-4">
            <div>
              <FieldLabel htmlFor="declaration-title" required>
                Declaration title
              </FieldLabel>
              <input
                id="declaration-title"
                type="text"
                value={declarationTitle}
                onChange={(e) => setDeclarationTitle(e.target.value)}
                className={triageFieldClassName}
                disabled={isSubmitting}
              />
            </div>
            <div>
              <FieldLabel htmlFor="public-guidance" required>
                Public guidance
              </FieldLabel>
              <textarea
                id="public-guidance"
                value={publicGuidance}
                onChange={(e) => setPublicGuidance(e.target.value)}
                className={`${triageFieldClassName} min-h-[88px] resize-y`}
                rows={3}
                disabled={isSubmitting}
              />
            </div>
            <div>
              <FieldLabel htmlFor="declaration-reason" required>
                Reason
              </FieldLabel>
              <textarea
                id="declaration-reason"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                className={`${triageFieldClassName} min-h-[72px] resize-y`}
                rows={2}
                disabled={isSubmitting}
              />
            </div>
            <div>
              <FieldLabel htmlFor="legal-reference">Legal reference</FieldLabel>
              <input
                id="legal-reference"
                type="text"
                value={legalReference}
                onChange={(e) => setLegalReference(e.target.value)}
                className={triageFieldClassName}
                disabled={isSubmitting}
              />
            </div>
            <div className="flex justify-between gap-2">
              <Button
                type="button"
                variant="secondary"
                onClick={() => handleStepNavigate(1)}
                disabled={isSubmitting}
              >
                Back
              </Button>
              <Button type="submit" variant="emergency" isLoading={isSubmitting}>
                Issue declaration
              </Button>
            </div>
          </form>
        ) : null}
      </div>
    </div>
  );
}
