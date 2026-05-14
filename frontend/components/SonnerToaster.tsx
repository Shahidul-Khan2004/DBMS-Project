"use client";

import { Toaster } from "sonner";

export function SonnerToaster() {
  return (
    <Toaster
      position="top-center"
      richColors
      closeButton
      toastOptions={{
        classNames: {
          toast: "rounded-2xl border border-[#002D62]/15 font-sans",
        },
      }}
    />
  );
}
