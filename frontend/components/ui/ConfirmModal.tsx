"use client";

import { Button } from "@/components/ui/Button";

export function ConfirmModal({
  open,
  title,
  message,
  confirmLabel = "Confirm",
  isLoading = false,
  onConfirm,
  onCancel,
}: {
  open: boolean;
  title: string;
  message: string;
  confirmLabel?: string;
  isLoading?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4">
      <div className="w-full max-w-md rounded-3xl border border-[#002D62]/10 bg-zinc-200 p-6 shadow-2xl shadow-[#002D62]/15">
        <h2 className="text-lg font-semibold text-[#002D62]">{title}</h2>
        <p className="mt-2 text-sm leading-6 text-gray-600">{message}</p>
        <div className="mt-6 flex justify-end gap-3">
          <Button
            type="button"
            variant="secondary"
            onClick={onCancel}
            disabled={isLoading}
          >
            Cancel
          </Button>
          <Button
            type="button"
            onClick={onConfirm}
            isLoading={isLoading}
            disabled={isLoading}
          >
            {confirmLabel}
          </Button>
        </div>
      </div>
    </div>
  );
}
