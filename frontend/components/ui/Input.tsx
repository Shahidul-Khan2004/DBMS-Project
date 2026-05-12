import { AlertCircle } from "lucide-react";
import React, { useId } from "react";

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  helpText?: string;
  icon?: React.ReactNode;
  endElement?: React.ReactNode;
}

export const Input = React.forwardRef<HTMLInputElement, InputProps>(
  (
    { label, error, helpText, icon, endElement, className = "", ...props },
    ref,
  ) => {
    const generatedId = useId();
    const inputId = props.id ?? generatedId;
    const errorId = `${inputId}-error`;
    const helpId = `${inputId}-help`;

    return (
      <div className="w-full">
        {label && (
          <label
            htmlFor={inputId}
            className="mb-2 block text-sm font-medium text-gray-700"
          >
            {label}
            {props.required && <span className="ml-1 text-[#DA291C]">*</span>}
          </label>
        )}
        <div className="relative">
          {icon && (
            <div className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400">
              {icon}
            </div>
          )}
          {endElement && (
            <div className="absolute right-2 top-1/2 -translate-y-1/2 text-black">
              {endElement}
            </div>
          )}
          <input
            ref={ref}
            id={inputId}
            aria-invalid={Boolean(error)}
            aria-describedby={error ? errorId : helpText ? helpId : undefined}
            className={`
              w-full rounded-2xl border border-[#002D62]/20 bg-white px-4 py-2.5
              text-gray-900 placeholder-gray-500
              transition-colors duration-200
              focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35
              disabled:cursor-not-allowed disabled:bg-gray-50 disabled:text-gray-500
              ${icon ? "pl-10" : ""}
              ${endElement ? "pr-12" : ""}
              ${error ? "border-[#DA291C] focus:border-[#DA291C] focus:ring-[#DA291C]/30" : ""}
              ${className}
            `}
            {...props}
          />
        </div>
        {error && (
          <p
            id={errorId}
            className="mt-2 flex items-center gap-1.5 text-sm text-[#B71C1C]"
          >
            <AlertCircle className="h-4 w-4 shrink-0" aria-hidden />
            {error}
          </p>
        )}
        {helpText && !error && (
          <p id={helpId} className="mt-2 text-sm text-gray-500">
            {helpText}
          </p>
        )}
      </div>
    );
  },
);

Input.displayName = "Input";
