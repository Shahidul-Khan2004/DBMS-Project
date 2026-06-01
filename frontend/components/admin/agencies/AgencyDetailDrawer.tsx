"use client";

import { useCallback, useEffect, useState } from "react";
import { X } from "lucide-react";
import { AgencyDetailContent } from "@/components/admin/agencies/AgencyDetailContent";
import { AddRepresentativeDialog } from "@/components/admin/agencies/AddRepresentativeDialog";
import { EditAgencyDialog } from "@/components/admin/agencies/EditAgencyDialog";
import { Button } from "@/components/ui/Button";
import { ConfirmModal } from "@/components/ui/ConfirmModal";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import {
  activateAdminAgency,
  deactivateAdminAgency,
  deactivateAgencyMembership,
  getAdminAgency,
} from "@/lib/admin-agency-api";
import type { AdminAgencyDetailResponse } from "@/types/admin-agency";

export type AgencyDetailDrawerProps = {
  open: boolean;
  agencyPublicUuid: string | null;
  onOpenChange: (open: boolean) => void;
  onMutated: () => void;
};

export function AgencyDetailDrawer({
  open,
  agencyPublicUuid,
  onOpenChange,
  onMutated,
}: AgencyDetailDrawerProps) {
  const [detail, setDetail] = useState<AdminAgencyDetailResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [isMutating, setIsMutating] = useState(false);
  const [editOpen, setEditOpen] = useState(false);
  const [addRepOpen, setAddRepOpen] = useState(false);
  const [confirmAction, setConfirmAction] = useState<
    "activate" | "deactivate" | { deactivateMembership: string } | null
  >(null);

  const trimmedUuid = agencyPublicUuid?.trim() ?? "";

  const loadDetail = useCallback(async () => {
    if (!trimmedUuid) return;

    setIsLoading(true);
    setLoadError(null);
    try {
      const data = await getAdminAgency(trimmedUuid);
      setDetail({
        ...data,
        representatives: data.representatives ?? [],
        units: data.units ?? [],
        contacts: data.contacts ?? [],
      });
    } catch {
      setDetail(null);
      setLoadError("Unable to load agency details. Please try again.");
    } finally {
      setIsLoading(false);
    }
  }, [trimmedUuid]);

  useEffect(() => {
    if (!open || !trimmedUuid) {
      setDetail(null);
      setLoadError(null);
      setIsLoading(false);
      return;
    }
    void loadDetail();
  }, [open, trimmedUuid, loadDetail]);

  useEffect(() => {
    if (!open) return;

    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        onOpenChange(false);
      }
    };

    window.addEventListener("keydown", onKeyDown);

    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [open, onOpenChange]);

  const handleMutationSuccess = async () => {
    await loadDetail();
    onMutated();
  };

  const runConfirm = async () => {
    if (!confirmAction || !trimmedUuid) return;

    setIsMutating(true);
    try {
      if (confirmAction === "activate") {
        await activateAdminAgency(trimmedUuid);
      } else if (confirmAction === "deactivate") {
        await deactivateAdminAgency(trimmedUuid);
      } else if ("deactivateMembership" in confirmAction) {
        await deactivateAgencyMembership(confirmAction.deactivateMembership);
      }
      setConfirmAction(null);
      await handleMutationSuccess();
    } catch {
      setLoadError("Action failed. Please try again.");
      setConfirmAction(null);
    } finally {
      setIsMutating(false);
    }
  };

  if (!open) return null;

  const handleClose = () => onOpenChange(false);

  const confirmTitle =
    confirmAction === "activate"
      ? "Activate agency"
      : confirmAction === "deactivate"
        ? "Deactivate agency"
        : confirmAction
          ? "Deactivate membership"
          : "";

  const confirmMessage =
    confirmAction === "activate"
      ? "Reactivates inactive representative memberships and restores agency_representative role where allowed."
      : confirmAction === "deactivate"
        ? "Deactivates active representative memberships and may remove agency_representative role when the user has no other active representative membership."
        : confirmAction
          ? "Sets the membership inactive and may remove agency_representative when no other active representative memberships remain."
          : "";

  return (
    <>
      <div className="fixed inset-0 z-50" role="presentation">
        <button
          type="button"
          className="absolute inset-0 bg-black/40"
          aria-label="Close agency details"
          onClick={handleClose}
        />
        <aside
          role="dialog"
          aria-modal="true"
          aria-label="Agency details"
          className="absolute inset-y-0 right-0 flex w-full max-w-xl flex-col border-l border-slate-200 bg-white shadow-2xl"
        >
          <div className="flex shrink-0 items-center justify-between border-b border-slate-200 px-4 py-4 sm:px-5">
            <h2 className="text-sm font-semibold text-slate-900">
              {detail?.agency.name ?? "Agency details"}
            </h2>
            <button
              type="button"
              onClick={handleClose}
              className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200 text-slate-600 transition-colors hover:bg-slate-50"
              aria-label="Close agency details"
            >
              <X className="h-5 w-5" aria-hidden />
            </button>
          </div>

          <div className="min-h-0 flex-1 overflow-y-auto overscroll-y-contain px-4 py-4 sm:px-5 sm:py-5">
            {!trimmedUuid ? (
              <p className="text-center text-sm text-slate-600">
                No agency selected.
              </p>
            ) : isLoading ? (
              <LoadingSkeleton lines={8} />
            ) : loadError ? (
              <div className="rounded-lg border border-[#B91C1C]/25 bg-[#FEF2F2] p-4 text-center">
                <p className="text-sm text-[#991B1B]">{loadError}</p>
                <Button
                  type="button"
                  variant="secondary"
                  size="sm"
                  className="mt-3"
                  onClick={() => void loadDetail()}
                >
                  Retry
                </Button>
              </div>
            ) : detail ? (
              <AgencyDetailContent
                detail={detail}
                isMutating={isMutating}
                onEdit={() => setEditOpen(true)}
                onActivate={() => setConfirmAction("activate")}
                onDeactivate={() => setConfirmAction("deactivate")}
                onAddRepresentative={() => setAddRepOpen(true)}
                onDeactivateMembership={(membershipPublicUuid) =>
                  setConfirmAction({ deactivateMembership: membershipPublicUuid })
                }
              />
            ) : null}
          </div>
        </aside>
      </div>

      <EditAgencyDialog
        open={editOpen}
        agency={detail?.agency ?? null}
        onClose={() => setEditOpen(false)}
        onSuccess={() => void handleMutationSuccess()}
      />

      <AddRepresentativeDialog
        open={addRepOpen}
        agencyPublicUuid={trimmedUuid || null}
        agencyName={detail?.agency.name}
        onClose={() => setAddRepOpen(false)}
        onSuccess={() => void handleMutationSuccess()}
      />

      <ConfirmModal
        open={confirmAction !== null}
        title={confirmTitle}
        message={confirmMessage}
        confirmLabel="Confirm"
        isLoading={isMutating}
        onConfirm={() => void runConfirm()}
        onCancel={() => {
          if (!isMutating) setConfirmAction(null);
        }}
      />
    </>
  );
}
