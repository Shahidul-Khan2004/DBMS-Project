"use client";

import { Eye, EyeOff } from "lucide-react";
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

function loginInputClass(hasError: boolean) {
  const base =
    "rounded-2xl border border-[#B8C7D6] bg-[#FDFEFF] px-4 py-3 text-[#0F172A] placeholder:text-[#7A8CA3] shadow-sm focus:border-[#002D62] focus:outline-none focus:ring-4 focus:ring-[#002D62]/10";
  const err =
    "border-[#DA291C] bg-[#FDECEC] focus:border-[#DA291C] focus:ring-4 focus:ring-[#DA291C]/10";
  return [base, hasError && err].filter(Boolean).join(" ");
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
        className={loginInputClass(!!fieldErrors.email)}
        required
      />

      <Input
        label="Password"
        type={showPassword ? "text" : "password"}
        placeholder="Enter your password"
        {...registerWithErrorReset("password")}
        error={fieldErrors.password}
        className={loginInputClass(!!fieldErrors.password)}
        endElement={
          <button
            type="button"
            onClick={() => setShowPassword((current) => !current)}
            aria-pressed={showPassword}
            aria-label={showPassword ? "Hide password" : "Show password"}
            title={showPassword ? "Hide password" : "Show password"}
            className="inline-flex items-center justify-center text-[#002D62] transition-colors hover:text-[#006747]"
          >
            {showPassword ? (
              <EyeOff className="h-5 w-5" aria-hidden />
            ) : (
              <Eye className="h-5 w-5" aria-hidden />
            )}
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
        className="mt-2 bg-[#002D62] text-white shadow-lg shadow-[#002D62]/20 hover:bg-[#001F4A] disabled:cursor-not-allowed disabled:bg-[#7F96B3] disabled:opacity-100 disabled:shadow-none"
      >
        Sign In
      </Button>
    </form>
  );
};
