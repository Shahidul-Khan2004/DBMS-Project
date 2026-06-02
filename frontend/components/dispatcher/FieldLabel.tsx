import type { ReactNode } from "react";
import { triageLabelClassName } from "@/components/dispatcher/triage/triageFormStyles";

export function RequiredMarker() {
  return (
    <span className="ml-0.5 font-normal text-[#B91C1C]" aria-hidden="true">
      *
    </span>
  );
}

type FieldLabelProps = {
  htmlFor?: string;
  required?: boolean;
  className?: string;
  children: ReactNode;
};

export function FieldLabel({
  htmlFor,
  required = false,
  className = triageLabelClassName,
  children,
}: FieldLabelProps) {
  return (
    <label htmlFor={htmlFor} className={className}>
      {children}
      {required ? <RequiredMarker /> : null}
    </label>
  );
}

type FieldLegendProps = {
  required?: boolean;
  className?: string;
  children: ReactNode;
};

export function FieldLegend({
  required = false,
  className = triageLabelClassName,
  children,
}: FieldLegendProps) {
  return (
    <legend className={className}>
      {children}
      {required ? <RequiredMarker /> : null}
    </legend>
  );
}
