"use client";

import React, { useState } from "react";
import { useForm } from "react-hook-form";
import { registerSchema, RegisterInput } from "@/lib/validations";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { ApiError, publicPost } from "@/lib/api";
import type { RegisterResponse } from "@/types/auth";

interface RegisterFormProps {
  onSuccess?: (data: RegisterResponse) => void;
}

type RegisterFieldName = keyof RegisterInput;
type RegisterFieldErrors = Partial<Record<RegisterFieldName, string>>;

function getRegisterFieldName(field: unknown): RegisterFieldName | null {
  if (typeof field !== "string") return null;

  const fieldMap: Record<string, RegisterFieldName> = {
    email: "email",
    fullName: "fullName",
    full_name: "fullName",
    phone: "phoneNumber",
    phoneNumber: "phoneNumber",
    phone_number: "phoneNumber",
    password: "password",
    confirmPassword: "rePassword",
    confirm_password: "rePassword",
    rePassword: "rePassword",
  };

  return fieldMap[field] ?? null;
}

function getBackendFieldErrors(details: unknown): RegisterFieldErrors {
  if (!Array.isArray(details)) return {};

  return details.reduce<RegisterFieldErrors>((errors, detail) => {
    if (!detail || typeof detail !== "object") return errors;

    const item = detail as { field?: unknown; path?: unknown; message?: unknown };
    const field = getRegisterFieldName(item.field ?? item.path);
    if (field && typeof item.message === "string" && !errors[field]) {
      errors[field] = item.message;
    }

    return errors;
  }, {});
}

function PasswordToggleIcon({ visible }: { visible: boolean }) {
  if (visible) {
    return (
      <svg
        aria-hidden="true"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
        className="h-5 w-5"
      >
        <path d="M2.5 12s3.5-6.5 9.5-6.5S21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z" />
        <circle cx="12" cy="12" r="3" />
        <path d="M4 4l16 16" />
      </svg>
    );
  }

  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      className="h-5 w-5"
    >
      <path d="M2.5 12s3.5-6.5 9.5-6.5S21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  );
}

export const RegisterForm: React.FC<RegisterFormProps> = ({ onSuccess }) => {
  const [isLoading, setIsLoading] = useState(false);
  const [apiError, setApiError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<RegisterFieldErrors>({});
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const {
    register,
    handleSubmit,
    reset,
  } = useForm<RegisterInput>({
    defaultValues: {
      email: "",
      fullName: "",
      phoneNumber: "",
      password: "",
      rePassword: "",
    },
  });

  async function onSubmit(data: RegisterInput) {
    const validation = registerSchema.safeParse(data);

    if (!validation.success) {
      const nextErrors: RegisterFieldErrors = {};

      for (const issue of validation.error.issues) {
        const field = getRegisterFieldName(issue.path[0]);
        if (field && !nextErrors[field]) {
          nextErrors[field] = issue.message;
        }
      }

      setFieldErrors(nextErrors);
      setApiError(null);
      return;
    }

    setIsLoading(true);
    setApiError(null);
    setFieldErrors({});

    try {
      const result = await publicPost<RegisterResponse, RegisterInput>(
        "/auth/register",
        validation.data,
      );
      reset();
      onSuccess?.(result);
    } catch (err) {
      if (err instanceof ApiError) {
        const backendFieldErrors = getBackendFieldErrors(err.details);

        if (Object.keys(backendFieldErrors).length > 0) {
          setFieldErrors(backendFieldErrors);
          return;
        }
      }

      setApiError(
        err instanceof Error
          ? err.message
          : "Registration failed. Please try again.",
      );
    } finally {
      setIsLoading(false);
    }
  }

  function registerWithErrorReset(field: RegisterFieldName) {
    const fieldRegistration = register(field);

    return {
      ...fieldRegistration,
      onChange: (event: React.ChangeEvent<HTMLInputElement>) => {
        fieldRegistration.onChange(event);
        setFieldErrors((current) => {
          if (!current[field]) return current;
          const next = { ...current };
          delete next[field];
          return next;
        });
      },
    };
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-5" noValidate>
      {apiError && (
        <ErrorAlert message={apiError} />
      )}

      <Input
        label="Email Address"
        type="email"
        placeholder="Enter your email address"
        {...registerWithErrorReset("email")}
        error={fieldErrors.email}
        required
      />

      <Input
        label="Full Name"
        type="text"
        placeholder="Enter your full name"
        {...registerWithErrorReset("fullName")}
        error={fieldErrors.fullName}
        required
      />

      <Input
        label="Phone Number"
        type="tel"
        placeholder="Enter your phone number"
        {...registerWithErrorReset("phoneNumber")}
        error={fieldErrors.phoneNumber}
        helpText="Required. Must be exactly 11 digits."
        required
      />

      <Input
        label="Password"
        type={showPassword ? "text" : "password"}
        placeholder="Create a password"
        {...registerWithErrorReset("password")}
        error={fieldErrors.password}
        helpText="Minimum 8 characters."
        endElement={
          <button
            type="button"
            onClick={() => setShowPassword((current) => !current)}
            aria-pressed={showPassword}
            aria-label={showPassword ? "Hide password" : "Show password"}
            title={showPassword ? "Hide password" : "Show password"}
            className="inline-flex items-center justify-center text-[#002D62] transition-colors hover:text-[#006747]"
          >
            <PasswordToggleIcon visible={showPassword} />
          </button>
        }
        required
      />

      <Input
        label="Confirm Password"
        type={showConfirmPassword ? "text" : "password"}
        placeholder="Confirm your password"
        {...registerWithErrorReset("rePassword")}
        error={fieldErrors.rePassword}
        endElement={
          <button
            type="button"
            onClick={() => setShowConfirmPassword((current) => !current)}
            aria-pressed={showConfirmPassword}
            aria-label={showConfirmPassword ? "Hide password" : "Show password"}
            title={showConfirmPassword ? "Hide password" : "Show password"}
            className="inline-flex items-center justify-center text-[#002D62] transition-colors hover:text-[#006747]"
          >
            <PasswordToggleIcon visible={showConfirmPassword} />
          </button>
        }
        required
      />

      <Button
        type="submit"
        variant="primary"
        fullWidth
        size="lg"
        isLoading={isLoading}
        className="mt-2"
      >
        Create Account
      </Button>
    </form>
  );
};
