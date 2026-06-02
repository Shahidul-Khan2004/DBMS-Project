"use client";

import { toast } from "sonner";
import { Button } from "@/components/ui/Button";

type CommandPlaceholderActionProps = {
  label: string;
  comingSoonMessage: string;
  disabled?: boolean;
  title?: string;
  variant?: "secondary" | "outline";
};

export function CommandPlaceholderAction({
  label,
  comingSoonMessage,
  disabled = false,
  title,
  variant = "secondary",
}: CommandPlaceholderActionProps) {
  const handleClick = () => {
    toast.message(comingSoonMessage);
  };

  return (
    <Button
      type="button"
      variant={variant}
      size="sm"
      disabled={disabled}
      title={title ?? (disabled ? undefined : comingSoonMessage)}
      onClick={disabled ? undefined : handleClick}
    >
      {label}
    </Button>
  );
}
