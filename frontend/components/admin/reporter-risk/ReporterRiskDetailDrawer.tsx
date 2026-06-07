"use client";

import { useCallback, useEffect, useState } from "react";
import { X } from "lucide-react";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { Input } from "@/components/ui/Input";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import {
  fetchAdminReporterRiskDetail,
  formatRiskLevelLabel,
  getReporterRiskErrorMessage,
  patchAdminUserAccountStatus,
  postAdminReporterAction,
} from "@/lib/reporter-risk-api";
import type {
  ReporterAccountAction,
  ReporterRecentReport,
  ReporterRiskSummary,
} from "@/types/reporter-risk";

type ReporterRiskDetailDrawerProps = {
  userPublicUuid: string | null;
  onClose: () => void;
  onUpdated: () => void;
};

type PendingAction =
  | { kind: "warning" }
  | { kind: "note" }
  | { kind: "suspend" }
  | { kind: "disable" }
  | { kind: "reactivate" };

const SUSPENSION_DURATION_OPTIONS = [
  { value: "7", label: "7 days" },
  { value: "14", label: "14 days" },
  { value: "30", label: "30 days" },
  { value: "90", label: "90 days" },
  { value: "custom", label: "Custom end date" },
] as const;

function toDatetimeLocalValue(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function defaultCustomSuspensionLocalValue(): string {
  const date = new Date();
  date.setDate(date.getDate() + 30);
  date.setSeconds(0, 0);
  return toDatetimeLocalValue(date);
}

export function ReporterRiskDetailDrawer({
  userPublicUuid,
  onClose,
  onUpdated,
}: ReporterRiskDetailDrawerProps) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [reporterRisk, setReporterRisk] = useState<ReporterRiskSummary | null>(null);
  const [recentReports, setRecentReports] = useState<ReporterRecentReport[]>([]);
  const [accountActions, setAccountActions] = useState<ReporterAccountAction[]>([]);
  const [pendingAction, setPendingAction] = useState<PendingAction | null>(null);
  const [reason, setReason] = useState("");
  const [suspensionDuration, setSuspensionDuration] = useState("30");
  const [customSuspensionUntil, setCustomSuspensionUntil] = useState(
    defaultCustomSuspensionLocalValue,
  );
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  const loadDetail = useCallback(async () => {
    if (!userPublicUuid) return;
    setLoading(true);
    setError(null);
    try {
      const data = await fetchAdminReporterRiskDetail(userPublicUuid);
      setReporterRisk(data.reporter_risk);
      setRecentReports(data.recent_reports ?? []);
      setAccountActions(data.account_actions ?? []);
    } catch (err) {
      setError(getReporterRiskErrorMessage(err, "Unable to load reporter details."));
    } finally {
      setLoading(false);
    }
  }, [userPublicUuid]);

  useEffect(() => {
    if (!userPublicUuid) {
      setReporterRisk(null);
      setRecentReports([]);
      setAccountActions([]);
      return;
    }
    void loadDetail();
  }, [userPublicUuid, loadDetail]);

  useEffect(() => {
    if (!userPublicUuid) return;
    document.body.style.overflow = "hidden";
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => {
      document.body.style.overflow = "";
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [userPublicUuid, onClose]);

  if (!userPublicUuid) return null;

  async function handleConfirmAction() {
    if (!userPublicUuid || !pendingAction) return;
    const trimmed = reason.trim();
    if (trimmed.length < 5) {
      setSubmitError("Reason must be at least 5 characters.");
      return;
    }

    if (pendingAction.kind === "suspend" && suspensionDuration === "custom") {
      if (!customSuspensionUntil.trim()) {
        setSubmitError("Select a suspension end date and time.");
        return;
      }
      const endsAt = new Date(customSuspensionUntil);
      if (Number.isNaN(endsAt.getTime()) || endsAt <= new Date()) {
        setSubmitError("Suspension end must be in the future.");
        return;
      }
    }

    setSubmitting(true);
    setSubmitError(null);
    try {
      if (pendingAction.kind === "warning" || pendingAction.kind === "note") {
        await postAdminReporterAction(userPublicUuid, {
          actionType: pendingAction.kind,
          reason: trimmed,
        });
      } else {
        const status =
          pendingAction.kind === "reactivate"
            ? "active"
            : pendingAction.kind === "suspend"
              ? "suspended"
              : "disabled";
        await patchAdminUserAccountStatus(userPublicUuid, {
          accountStatus: status,
          reason: trimmed,
          ...(pendingAction.kind === "suspend" && suspensionDuration === "custom"
            ? { suspendedUntil: new Date(customSuspensionUntil).toISOString() }
            : pendingAction.kind === "suspend"
              ? { suspensionDays: Number(suspensionDuration) }
              : {}),
        });
      }
      setPendingAction(null);
      setReason("");
      await loadDetail();
      onUpdated();
    } catch (err) {
      setSubmitError(getReporterRiskErrorMessage(err, "Action failed."));
    } finally {
      setSubmitting(false);
    }
  }

  const confirmTitle =
    pendingAction?.kind === "disable"
      ? "Disable reporter account?"
      : pendingAction?.kind === "suspend"
        ? "Suspend reporter account?"
        : pendingAction?.kind === "reactivate"
          ? "Reactivate reporter account?"
          : pendingAction?.kind === "warning"
            ? "Record warning"
            : "Record note";

  return (
    <>
      <div className="fixed inset-0 z-50 flex justify-end">
        <button
          type="button"
          aria-label="Close reporter detail"
          className="absolute inset-0 bg-black/40"
          onClick={onClose}
        />
        <aside className="relative z-10 flex h-full w-full max-w-xl flex-col border-l border-slate-200 bg-white shadow-xl">
          <header className="flex shrink-0 items-start justify-between gap-3 border-b border-slate-100 px-4 py-4">
            <div className="min-w-0">
              <h2 className="text-sm font-semibold text-slate-900">Reporter details</h2>
              {reporterRisk ? (
                <p className="mt-0.5 truncate text-xs text-slate-600">
                  {reporterRisk.reporter_full_name}
                </p>
              ) : null}
            </div>
            <button
              type="button"
              onClick={onClose}
              className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-slate-200 text-slate-600 hover:bg-slate-50"
              aria-label="Close"
            >
              <X className="h-5 w-5" />
            </button>
          </header>

          <div className="min-h-0 flex-1 overflow-y-auto overscroll-y-contain px-4 py-4">
            {loading ? (
              <LoadingSkeleton lines={8} />
            ) : error ? (
              <ErrorAlert message={error} />
            ) : reporterRisk ? (
              <div className="space-y-4">
                <section className="rounded-lg border border-slate-200/90 p-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge tone={reporterRisk.risk_level} size="compact">
                      {formatRiskLevelLabel(reporterRisk.risk_level)} risk
                    </Badge>
                    <Badge tone={reporterRisk.account_status} size="compact">
                      {reporterRisk.account_status.replace(/_/g, " ")}
                    </Badge>
                    {reporterRisk.account_status_expires_at ? (
                      <span className="text-slate-500">
                        until{" "}
                        {new Date(reporterRisk.account_status_expires_at).toLocaleString()}
                      </span>
                    ) : null}
                  </div>
                  <dl className="mt-2 grid grid-cols-2 gap-2 text-xs text-slate-600">
                    <div>
                      <dt className="text-slate-500">Email</dt>
                      <dd>{reporterRisk.reporter_email ?? "—"}</dd>
                    </div>
                    <div>
                      <dt className="text-slate-500">Phone</dt>
                      <dd>{reporterRisk.reporter_phone_number ?? "—"}</dd>
                    </div>
                    <div>
                      <dt className="text-slate-500">Total reports</dt>
                      <dd className="font-medium">{reporterRisk.total_reports}</dd>
                    </div>
                    <div>
                      <dt className="text-slate-500">False (30d)</dt>
                      <dd className="font-medium">{reporterRisk.false_reports_30d}</dd>
                    </div>
                  </dl>
                </section>

                <section>
                  <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                    Recent reports
                  </h3>
                  <ul className="mt-2 space-y-2">
                    {recentReports.map((report) => (
                      <li
                        key={report.intake_report_public_uuid}
                        className="rounded-md border border-slate-100 bg-slate-50/60 px-3 py-2 text-xs"
                      >
                        <div className="font-medium text-slate-900">
                          {report.report_code} — {report.summary}
                        </div>
                        <div className="mt-1 flex flex-wrap gap-2 text-slate-600">
                          {report.latest_verdict ? (
                            <Badge tone={report.latest_verdict} size="compact">
                              {report.latest_verdict.replace(/_/g, " ")}
                            </Badge>
                          ) : (
                            <span>Not verified</span>
                          )}
                          <span>{new Date(report.reported_at).toLocaleString()}</span>
                        </div>
                      </li>
                    ))}
                  </ul>
                </section>

                <section>
                  <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                    Account actions
                  </h3>
                  <ul className="mt-2 space-y-2">
                    {accountActions.length === 0 ? (
                      <li className="text-xs text-slate-500">No actions recorded.</li>
                    ) : (
                      accountActions.map((action) => (
                        <li
                          key={action.public_uuid}
                          className="rounded-md border border-slate-100 px-3 py-2 text-xs"
                        >
                          <div className="flex items-center gap-2">
                            <Badge tone={action.action_type} size="compact">
                              {action.action_type}
                            </Badge>
                            <span className="text-slate-500">
                              {new Date(action.created_at).toLocaleString()}
                            </span>
                          </div>
                          <p className="mt-1 text-slate-700">{action.reason}</p>
                          {action.suspension_ends_at ? (
                            <p className="mt-0.5 text-slate-500">
                              Suspension ends{" "}
                              {new Date(action.suspension_ends_at).toLocaleString()}
                            </p>
                          ) : null}
                        </li>
                      ))
                    )}
                  </ul>
                </section>
              </div>
            ) : null}
          </div>

          {reporterRisk ? (
            <footer className="flex shrink-0 flex-wrap gap-2 border-t border-slate-100 px-4 py-3">
              <Button
                type="button"
                variant="secondary"
                size="sm"
                onClick={() => {
                  setPendingAction({ kind: "warning" });
                  setReason("");
                  setSubmitError(null);
                }}
              >
                Record warning
              </Button>
              {reporterRisk.account_status === "active" ? (
                <Button
                  type="button"
                  variant="secondary"
                  size="sm"
                  onClick={() => {
                    setPendingAction({ kind: "suspend" });
                    setReason("");
                    setSuspensionDuration("30");
                    setCustomSuspensionUntil(defaultCustomSuspensionLocalValue());
                    setSubmitError(null);
                  }}
                >
                  Suspend
                </Button>
              ) : null}
              {reporterRisk.account_status === "active" ||
              reporterRisk.account_status === "suspended" ? (
                <Button
                  type="button"
                  variant="danger"
                  size="sm"
                  onClick={() => {
                    setPendingAction({ kind: "disable" });
                    setReason("");
                    setSubmitError(null);
                  }}
                >
                  Disable
                </Button>
              ) : null}
              {reporterRisk.account_status === "suspended" ||
              reporterRisk.account_status === "disabled" ? (
                <Button
                  type="button"
                  variant="secondary"
                  size="sm"
                  onClick={() => {
                    setPendingAction({ kind: "reactivate" });
                    setReason("");
                    setSubmitError(null);
                  }}
                >
                  Reactivate
                </Button>
              ) : null}
            </footer>
          ) : null}
        </aside>
      </div>

      {pendingAction ? (
        <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/40 px-4">
          <div className="w-full max-w-md rounded-xl border border-slate-200 bg-white p-4 shadow-lg">
            <h3 className="text-sm font-semibold text-slate-900">{confirmTitle}</h3>
            <p className="mt-1 text-xs leading-relaxed text-slate-600">
              {pendingAction.kind === "disable"
                ? "Disabling blocks this user from signing in. Confirm only for repeated malicious false reports."
                : pendingAction.kind === "suspend"
                  ? "Suspension blocks sign-in until the period ends or you reactivate the account manually."
                  : "Use account restrictions only for repeated confirmed malicious false reports. Mistaken or duplicate reports should not be punished as abuse."}
            </p>
            <div className="mt-3 space-y-2">
              {pendingAction.kind === "suspend" ? (
                <div className="space-y-2">
                  <div>
                    <label
                      className="block text-xs font-medium text-slate-700"
                      htmlFor="suspension-duration"
                    >
                      Suspension duration
                    </label>
                    <select
                      id="suspension-duration"
                      className="mt-1 w-full rounded-lg border border-slate-200 px-3 py-2 text-sm text-slate-900"
                      value={suspensionDuration}
                      onChange={(e) => {
                        const next = e.target.value;
                        setSuspensionDuration(next);
                        if (next === "custom" && !customSuspensionUntil.trim()) {
                          setCustomSuspensionUntil(defaultCustomSuspensionLocalValue());
                        }
                      }}
                    >
                      {SUSPENSION_DURATION_OPTIONS.map((opt) => (
                        <option key={opt.value} value={opt.value}>
                          {opt.label}
                        </option>
                      ))}
                    </select>
                  </div>
                  {suspensionDuration === "custom" ? (
                    <div>
                      <label
                        className="block text-xs font-medium text-slate-700"
                        htmlFor="suspension-until"
                      >
                        Suspension ends
                      </label>
                      <Input
                        id="suspension-until"
                        type="datetime-local"
                        className="mt-1"
                        value={customSuspensionUntil}
                        min={toDatetimeLocalValue(new Date())}
                        onChange={(e) => setCustomSuspensionUntil(e.target.value)}
                      />
                      <p className="mt-1 text-xs text-slate-500">
                        Account reactivates automatically after this date and time.
                      </p>
                    </div>
                  ) : null}
                </div>
              ) : null}
              <label className="block text-xs font-medium text-slate-700" htmlFor="action-reason">
                Reason
              </label>
              <Input
                id="action-reason"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="Minimum 5 characters"
              />
              {submitError ? <ErrorAlert message={submitError} /> : null}
            </div>
            <div className="mt-4 flex justify-end gap-2">
              <Button
                type="button"
                variant="secondary"
                size="sm"
                onClick={() => {
                  setPendingAction(null);
                  setReason("");
                  setSuspensionDuration("30");
                  setCustomSuspensionUntil(defaultCustomSuspensionLocalValue());
                  setSubmitError(null);
                }}
              >
                Cancel
              </Button>
              <Button
                type="button"
                variant={pendingAction.kind === "disable" ? "danger" : "primary"}
                size="sm"
                isLoading={submitting}
                onClick={() => void handleConfirmAction()}
              >
                Confirm
              </Button>
            </div>
          </div>
        </div>
      ) : null}
    </>
  );
}
