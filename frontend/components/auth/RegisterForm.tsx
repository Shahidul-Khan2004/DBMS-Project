"use client";

import React, { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { registerSchema, RegisterInput } from "@/lib/validations";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import type { RegisterResponse } from "@/types/auth";

interface RegisterFormProps {
  onSuccess?: (data: RegisterResponse) => void;
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
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const apiBaseUrl =
    process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8080";

  const {
    register,
    handleSubmit,
    formState: { errors },
    reset,
  } = useForm<RegisterInput>({
    resolver: zodResolver(registerSchema),
    defaultValues: {
      email: "",
      fullName: "",
      phoneNumber: "",
      password: "",
      rePassword: "",
    },
  });

  async function onSubmit(data: RegisterInput) {
    setIsLoading(true);
    setApiError(null);

    try {
      const response = await fetch(`${apiBaseUrl}/auth/register`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(data),
      });

      const result = await response.json();

      if (!response.ok) {
        setApiError(
          result?.error?.message ||
            result?.message ||
            "Registration failed. Please try again.",
        );
        return;
      }

      reset();
      onSuccess?.(result as RegisterResponse);
    } catch (error) {
      console.error("Registration error:", error);
      setApiError("An unexpected error occurred. Please try again.");
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-5">
      {apiError && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4">
          <p className="text-sm text-red-800">{apiError}</p>
        </div>
      )}

      <Input
        label="Email Address"
        type="email"
        placeholder="Enter your email address"
        {...register("email")}
        error={errors.email?.message}
        required
      />

      <Input
        label="Full Name"
        type="text"
        placeholder="Enter your full name"
        {...register("fullName")}
        error={errors.fullName?.message}
        required
      />

      <Input
        label="Phone Number"
        type="tel"
        placeholder="Enter your phone number"
        {...register("phoneNumber")}
        error={errors.phoneNumber?.message}
        helpText="Required. Must be exactly 11 digits."
        required
      />

      <Input
        label="Password"
        type={showPassword ? "text" : "password"}
        placeholder="Create a password"
        {...register("password")}
        error={errors.password?.message}
        helpText="Minimum 8 characters."
        endElement={
          <button
            type="button"
            onClick={() => setShowPassword((current) => !current)}
            aria-pressed={showPassword}
            aria-label={showPassword ? "Hide password" : "Show password"}
            title={showPassword ? "Hide password" : "Show password"}
            className="inline-flex items-center justify-center text-black transition-colors hover:text-gray-800"
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
        {...register("rePassword")}
        error={errors.rePassword?.message}
        endElement={
          <button
            type="button"
            onClick={() => setShowConfirmPassword((current) => !current)}
            aria-pressed={showConfirmPassword}
            aria-label={showConfirmPassword ? "Hide password" : "Show password"}
            title={showConfirmPassword ? "Hide password" : "Show password"}
            className="inline-flex items-center justify-center text-black transition-colors hover:text-gray-800"
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
