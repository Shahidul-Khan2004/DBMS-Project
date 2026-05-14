"use client";

import React, { useState } from "react";
import { useForm } from "react-hook-form";
import { loginSchema, LoginInput } from "@/lib/validations";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { ApiError, publicPost } from "@/lib/api";
import type { LoginResponse } from "@/types/auth";

interface LoginFormProps {
  onSuccess?: (data: LoginResponse) => void;
}

type LoginFieldName = keyof LoginInput;
type LoginFieldErrors = Partial<Record<LoginFieldName, string>>;

function getLoginFieldName(field: unknown): LoginFieldName | null {
  if (field === "email" || field === "password") return field;
  return null;
}

function getBackendFieldErrors(details: unknown): LoginFieldErrors {
  if (!Array.isArray(details)) return {};

  return details.reduce<LoginFieldErrors>((errors, detail) => {
    if (!detail || typeof detail !== "object") return errors;

    const item = detail as { field?: unknown; path?: unknown; message?: unknown };
    const field = getLoginFieldName(item.field ?? item.path);
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

export const LoginForm: React.FC<LoginFormProps> = ({ onSuccess }) => {
  const [isLoading, setIsLoading] = useState(false);
  const [apiError, setApiError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<LoginFieldErrors>({});
  const [showPassword, setShowPassword] = useState(false);

  const {
    register,
    handleSubmit,
    reset,
  } = useForm<LoginInput>({
    defaultValues: {
      email: "",
      password: "",
    },
  });

  async function onSubmit(data: LoginInput) {
    const validation = loginSchema.safeParse(data);

    if (!validation.success) {
      const nextErrors: LoginFieldErrors = {};

      for (const issue of validation.error.issues) {
        const field = getLoginFieldName(issue.path[0]);
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
      const result = await publicPost<LoginResponse, LoginInput>(
        "/auth/login",
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
        err instanceof Error ? err.message : "Login failed. Please try again.",
      );
    } finally {
      setIsLoading(false);
    }
  }

  function registerWithErrorReset(field: LoginFieldName) {
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
        label="Password"
        type={showPassword ? "text" : "password"}
        placeholder="Enter your password"
        {...registerWithErrorReset("password")}
        error={fieldErrors.password}
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

      <Button
        type="submit"
        variant="primary"
        fullWidth
        size="lg"
        isLoading={isLoading}
        className="mt-2"
      >
        Sign In
      </Button>
    </form>
  );
};
