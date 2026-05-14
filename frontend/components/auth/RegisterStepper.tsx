"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { AnimatePresence, motion } from "framer-motion";
import { Check } from "lucide-react";
import Link from "next/link";
import React, { useCallback, useMemo, useState } from "react";
import { useForm, type FieldErrors } from "react-hook-form";
import { toast } from "sonner";
import { Button } from "@/components/ui/Button";
import { Card, CardContent } from "@/components/ui/Card";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { Input } from "@/components/ui/Input";
import { ApiError, publicPost } from "@/lib/api";
import {
  getBackendFieldErrors,
  registerApiErrorFieldStep,
} from "@/lib/register-api";
import type { RegisterFieldName } from "@/lib/register-api";
import {
  getPasswordStrengthScore,
  registerStepConfirmPasswordStepSchema,
  registerStepCreatePasswordSchema,
  registerStepEmailFieldSchema,
  registerStepFullNameSchema,
  registerStepPhoneSchema,
  registerWizardFormValuesSchema,
  registerWizardSubmitSchema,
  toRegisterPayload,
  type RegisterWizardInput,
} from "@/lib/validations";
import type { RegisterResponse } from "@/types/auth";

const STEP_META = [
  {
    title: "Full name",
    subtitle: "As it appears on your official ID",
  },
  {
    title: "Phone number",
    subtitle: "Bangladesh mobile (01XXXXXXXXX)",
  },
  {
    title: "Email address",
    subtitle: "For account updates and notifications",
  },
  {
    title: "Create password",
    subtitle: "Use a strong, unique password",
  },
  {
    title: "Confirm password",
    subtitle: "Re-enter your password",
  },
  {
    title: "Review and register",
    subtitle: "Confirm your details and accept terms",
  },
] as const;

const TOTAL_STEPS = STEP_META.length;
const REVIEW_STEP_INDEX = TOTAL_STEPS - 1;

interface RegisterStepperProps {
  onSuccess?: (data: RegisterResponse) => void;
}

type RegisterWizardFieldName = keyof RegisterWizardInput;

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

function PasswordStrengthMeter({ password }: { password: string }) {
  const score = getPasswordStrengthScore(password);
  return (
    <div className="space-y-2">
      <div className="flex gap-1.5" aria-hidden>
        {Array.from({ length: 5 }, (_, i) => (
          <div
            key={i}
            className={[
              "h-2 flex-1 rounded-full transition-colors duration-200",
              i < score ? "bg-[#006747]" : "bg-gray-200 ring-1 ring-[#002D62]/10",
            ].join(" ")}
          />
        ))}
      </div>
      <p className="text-xs text-slate-500">
        Strength:{" "}
        <span className="font-medium text-[#002D62]">
          {score === 0
            ? "Too weak"
            : score < 3
              ? "Fair"
              : score < 5
                ? "Good"
                : "Strong"}
        </span>
        {" · "}
        At least 8 characters with upper, lower, number, and symbol.
      </p>
    </div>
  );
}

const WIZARD_FIELD_KEYS = new Set<RegisterWizardFieldName>([
  "email",
  "fullName",
  "phoneNumber",
  "password",
  "rePassword",
  "acceptTerms",
]);

function applyZodIssuesToForm(
  issues: readonly { path: readonly PropertyKey[]; message: string }[],
  setError: ReturnType<typeof useForm<RegisterWizardInput>>["setError"],
) {
  for (const issue of issues) {
    const key = issue.path[0];
    if (
      typeof key === "string" &&
      WIZARD_FIELD_KEYS.has(key as RegisterWizardFieldName)
    ) {
      setError(key as RegisterWizardFieldName, { message: issue.message });
    }
  }
}

function wizardStepForField(name: string): number {
  switch (name) {
    case "fullName":
      return 0;
    case "phoneNumber":
      return 1;
    case "email":
      return 2;
    case "password":
      return 3;
    case "rePassword":
      return 4;
    case "acceptTerms":
      return 5;
    default:
      return 0;
  }
}

function firstWizardStepWithErrors(
  formErrors: FieldErrors<RegisterWizardInput>,
): number {
  const keys = Object.keys(formErrors) as RegisterWizardFieldName[];
  if (keys.length === 0) return 0;
  return Math.min(...keys.map((k) => wizardStepForField(k)));
}

function firstWizardStepFromZodIssues(
  issues: readonly { path: readonly PropertyKey[]; message: string }[],
): number {
  const steps: number[] = [];
  for (const issue of issues) {
    const key = issue.path[0];
    if (typeof key === "string") {
      steps.push(wizardStepForField(key));
    }
  }
  if (steps.length === 0) return 0;
  return Math.min(...steps);
}

export const RegisterStepper: React.FC<RegisterStepperProps> = ({
  onSuccess,
}) => {
  const [currentStep, setCurrentStep] = useState(0);
  const [apiError, setApiError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const {
    register,
    handleSubmit,
    watch,
    setValue,
    setError,
    clearErrors,
    reset,
    formState: { errors },
  } = useForm<RegisterWizardInput>({
    resolver: zodResolver(registerWizardFormValuesSchema),
    mode: "onChange",
    defaultValues: {
      email: "",
      fullName: "",
      phoneNumber: "",
      password: "",
      rePassword: "",
      acceptTerms: false,
    },
  });

  const values = watch();

  const step0Valid = useMemo(
    () =>
      registerStepFullNameSchema.safeParse({ fullName: values.fullName })
        .success,
    [values.fullName],
  );

  const step1Valid = useMemo(
    () =>
      registerStepPhoneSchema.safeParse({ phoneNumber: values.phoneNumber })
        .success,
    [values.phoneNumber],
  );

  const step2Valid = useMemo(
    () => registerStepEmailFieldSchema.safeParse({ email: values.email }).success,
    [values.email],
  );

  const step3Valid = useMemo(
    () =>
      registerStepCreatePasswordSchema.safeParse({
        password: values.password,
      }).success,
    [values.password],
  );

  const step4Valid = useMemo(
    () =>
      registerStepConfirmPasswordStepSchema.safeParse({
        password: values.password,
        rePassword: values.rePassword,
      }).success,
    [values.password, values.rePassword],
  );

  const reviewStepValid = values.acceptTerms === true;

  const currentStepHasFieldErrors = useMemo(() => {
    if (currentStep === 0) return !!errors.fullName;
    if (currentStep === 1) return !!errors.phoneNumber;
    if (currentStep === 2) return !!errors.email;
    if (currentStep === 3) return !!errors.password;
    if (currentStep === 4) return !!errors.rePassword;
    if (currentStep === 5) return !!errors.acceptTerms;
    return false;
  }, [
    currentStep,
    errors.acceptTerms,
    errors.email,
    errors.fullName,
    errors.password,
    errors.phoneNumber,
    errors.rePassword,
  ]);

  const nextDisabled = useMemo(() => {
    switch (currentStep) {
      case 0:
        return !step0Valid;
      case 1:
        return !step1Valid;
      case 2:
        return !step2Valid;
      case 3:
        return !step3Valid;
      case 4:
        return !step4Valid;
      default:
        return true;
    }
  }, [
    currentStep,
    step0Valid,
    step1Valid,
    step2Valid,
    step3Valid,
    step4Valid,
  ]);

  const clearRegisterFieldErrors = useCallback(() => {
    clearErrors([
      "email",
      "fullName",
      "phoneNumber",
      "password",
      "rePassword",
    ]);
  }, [clearErrors]);

  const goNext = useCallback(() => {
    if (currentStep >= REVIEW_STEP_INDEX) return;
    setCurrentStep((s) => s + 1);
  }, [currentStep]);

  const goBack = useCallback(() => {
    if (currentStep <= 0) return;
    setCurrentStep((s) => s - 1);
  }, [currentStep]);

  const validateCurrentStep = useCallback((): boolean => {
    switch (currentStep) {
      case 0: {
        const r = registerStepFullNameSchema.safeParse({
          fullName: values.fullName,
        });
        if (!r.success) applyZodIssuesToForm(r.error.issues, setError);
        return r.success;
      }
      case 1: {
        const r = registerStepPhoneSchema.safeParse({
          phoneNumber: values.phoneNumber,
        });
        if (!r.success) applyZodIssuesToForm(r.error.issues, setError);
        return r.success;
      }
      case 2: {
        const r = registerStepEmailFieldSchema.safeParse({
          email: values.email,
        });
        if (!r.success) applyZodIssuesToForm(r.error.issues, setError);
        return r.success;
      }
      case 3: {
        const r = registerStepCreatePasswordSchema.safeParse({
          password: values.password,
        });
        if (!r.success) applyZodIssuesToForm(r.error.issues, setError);
        return r.success;
      }
      case 4: {
        const r = registerStepConfirmPasswordStepSchema.safeParse({
          password: values.password,
          rePassword: values.rePassword,
        });
        if (!r.success) applyZodIssuesToForm(r.error.issues, setError);
        return r.success;
      }
      default:
        return false;
    }
  }, [
    currentStep,
    setError,
    values.email,
    values.fullName,
    values.password,
    values.phoneNumber,
    values.rePassword,
  ]);

  const handleNext = useCallback(() => {
    setApiError(null);
    clearErrors();
    if (!validateCurrentStep()) return;
    goNext();
  }, [clearErrors, goNext, setApiError, validateCurrentStep]);

  const handleEditEmail = useCallback(() => {
    setValue("acceptTerms", false, { shouldValidate: true });
    setCurrentStep(2);
    clearErrors(["acceptTerms"]);
  }, [clearErrors, setValue]);

  const onRegister = useCallback(
    async (data: RegisterWizardInput) => {
      const parsed = registerWizardSubmitSchema.safeParse(data);
      if (!parsed.success) {
        applyZodIssuesToForm(parsed.error.issues, setError);
        setCurrentStep(firstWizardStepFromZodIssues(parsed.error.issues));
        toast.error("Please fix the issues shown on this step.");
        return;
      }

      setIsSubmitting(true);
      setApiError(null);
      clearRegisterFieldErrors();

      const payload = toRegisterPayload(parsed.data);

      try {
        const result = await publicPost<RegisterResponse, typeof payload>(
          "/auth/register",
          payload,
        );
        reset();
        setCurrentStep(0);
        toast.success("Account created", {
          description: "Welcome to NIERS. Redirecting…",
        });
        onSuccess?.(result);
      } catch (err) {
        if (err instanceof ApiError) {
          const backendFieldErrors = getBackendFieldErrors(err.details);
          if (Object.keys(backendFieldErrors).length > 0) {
            setApiError(null);
            const step = registerApiErrorFieldStep(backendFieldErrors);
            setCurrentStep(step);
            for (const [field, message] of Object.entries(backendFieldErrors)) {
              setError(field as RegisterFieldName, { message });
            }
            return;
          }
        }
        setApiError(
          err instanceof Error
            ? err.message
            : "Registration failed. Please try again.",
        );
      } finally {
        setIsSubmitting(false);
      }
    },
    [clearRegisterFieldErrors, onSuccess, reset, setError],
  );

  const onSubmitInvalid = useCallback(
    (formErrors: FieldErrors<RegisterWizardInput>) => {
      const step = firstWizardStepWithErrors(formErrors);
      setCurrentStep(step);
      toast.error("Please fix the highlighted fields.", {
        description: "Check the messages below each field.",
      });
    },
    [],
  );

  const onFormKeyDown = (e: React.KeyboardEvent<HTMLFormElement>) => {
    if (e.key !== "Enter" || e.shiftKey) return;
    const target = e.target as HTMLElement;
    if (target.tagName === "TEXTAREA") return;
    if (currentStep === REVIEW_STEP_INDEX) return;
    e.preventDefault();
    if (!nextDisabled) handleNext();
  };

  return (
    <div className="min-h-screen bg-gradient-to-b from-emerald-50/40 via-zinc-200 to-zinc-200">
      <header className="fixed top-0 inset-x-0 z-50 border-b border-gray-200 bg-zinc-200/95 backdrop-blur-md">
        <div className="mx-auto flex max-w-screen-2xl items-center justify-between gap-4 px-4 py-4 sm:px-6 md:px-8 lg:px-10">
          <Link
            href="/"
            className="flex shrink-0 items-center rounded-md focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#002D62]"
          >
            <div className="bg-[#002D62] px-6 py-2.5 text-xl font-bold tracking-[-1px] text-white sm:px-7 sm:py-3 sm:text-2xl md:text-3xl">
              NIERS
            </div>
          </Link>
          <Link
            href="/auth/login"
            className="text-sm font-semibold text-[#002D62] transition-colors hover:text-[#006747] sm:text-base"
          >
            Login
          </Link>
        </div>
      </header>

      <div className="mx-auto max-w-screen-2xl px-4 pb-16 pt-28 sm:px-6 md:px-8 lg:px-10">
        <div className="mb-8 lg:mb-10">
          <h1 className="text-2xl font-bold text-[#002D62] sm:text-3xl">
            Create your citizen account
          </h1>
          <p className="mt-2 max-w-2xl text-sm text-gray-600 sm:text-base">
            Join the National Integrated Emergency Response System. Complete each
            step below — your progress is saved as you go.
          </p>
        </div>

        <form
          className="flex flex-col gap-10 lg:flex-row lg:gap-12 xl:gap-16"
          onSubmit={handleSubmit(onRegister, onSubmitInvalid)}
          onKeyDown={onFormKeyDown}
          noValidate
        >
          <aside className="w-full shrink-0 lg:w-[35%] lg:max-w-sm">
            <nav aria-label="Registration steps">
              <ol className="space-y-1">
                {STEP_META.map((step, index) => {
                  const done = index < currentStep;
                  const active = index === currentStep;
                  return (
                    <li key={step.title}>
                      <div
                        className={[
                          "flex gap-3 rounded-2xl border px-4 py-3.5 transition-colors",
                          active
                            ? "border-[#006747]/40 bg-white shadow-md shadow-[#002D62]/5 ring-1 ring-[#006747]/20"
                            : done
                              ? "border-transparent bg-white/60"
                              : "border-transparent bg-transparent opacity-75",
                        ].join(" ")}
                        aria-current={active ? "step" : undefined}
                      >
                        <div
                          className={[
                            "flex h-9 w-9 shrink-0 items-center justify-center rounded-full text-sm font-bold",
                            active
                              ? "bg-[#002D62] text-white"
                              : done
                                ? "bg-[#006747] text-white"
                                : "border border-[#002D62]/20 bg-white text-[#002D62]",
                          ].join(" ")}
                        >
                          {done ? (
                            <Check className="h-4 w-4" aria-hidden />
                          ) : (
                            index + 1
                          )}
                        </div>
                        <div className="min-w-0">
                          <p
                            className={[
                              "text-sm font-semibold sm:text-base",
                              active ? "text-[#002D62]" : "text-slate-800",
                            ].join(" ")}
                          >
                            {step.title}
                          </p>
                          <p className="mt-0.5 text-xs text-slate-500 sm:text-sm">
                            {step.subtitle}
                          </p>
                        </div>
                      </div>
                    </li>
                  );
                })}
              </ol>
            </nav>
            <p className="mt-6 text-center text-xs text-gray-500 lg:text-left">
              Step {currentStep + 1} of {TOTAL_STEPS}
            </p>
          </aside>

          <section className="min-w-0 flex-1 lg:w-[65%]">
            <Card className="shadow-lg shadow-[#002D62]/5">
              <CardContent className="p-6 sm:p-8 md:p-10">
                {apiError && (
                  <div className="mb-6">
                    <ErrorAlert message={apiError} />
                  </div>
                )}
                {currentStepHasFieldErrors && (
                  <div className="mb-6">
                    <ErrorAlert message="Please correct the errors below before continuing." />
                  </div>
                )}

                <AnimatePresence mode="wait">
                  <motion.div
                    key={currentStep}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -6 }}
                    transition={{ duration: 0.2 }}
                    className="mx-auto max-w-md"
                  >
                    <h2 className="text-xl font-bold text-[#002D62] sm:text-2xl">
                      {STEP_META[currentStep].title}
                    </h2>
                    <p className="mt-1 text-sm text-slate-600 sm:text-base">
                      {STEP_META[currentStep].subtitle}
                    </p>

                    <div className="mt-8 space-y-6">
                      <div
                        className={currentStep === 0 ? "space-y-2" : "hidden"}
                        aria-hidden={currentStep !== 0}
                      >
                        <Input
                          label="Full name"
                          type="text"
                          autoComplete="name"
                          placeholder="Enter your full name"
                          {...register("fullName")}
                          error={errors.fullName?.message}
                          required
                        />
                      </div>

                      <div
                        className={currentStep === 1 ? "space-y-2" : "hidden"}
                        aria-hidden={currentStep !== 1}
                      >
                        <Input
                          label="Phone number"
                          type="tel"
                          inputMode="numeric"
                          autoComplete="tel"
                          placeholder="01XXXXXXXXX"
                          {...register("phoneNumber")}
                          error={errors.phoneNumber?.message}
                          helpText="11 digits: 01 followed by 9 digits (Bangladesh mobile)."
                          required
                        />
                      </div>

                      <div
                        className={currentStep === 2 ? "space-y-2" : "hidden"}
                        aria-hidden={currentStep !== 2}
                      >
                        <Input
                          label="Email address"
                          type="email"
                          autoComplete="email"
                          placeholder="you@example.com"
                          {...register("email")}
                          error={errors.email?.message}
                          required
                        />
                      </div>

                      <div
                        className={currentStep === 3 ? "space-y-4" : "hidden"}
                        aria-hidden={currentStep !== 3}
                      >
                        <Input
                          label="Password"
                          type={showPassword ? "text" : "password"}
                          autoComplete="new-password"
                          placeholder="Create a strong password"
                          {...register("password")}
                          error={errors.password?.message}
                          endElement={
                            <button
                              type="button"
                              onClick={() => setShowPassword((v) => !v)}
                              aria-pressed={showPassword}
                              aria-label={
                                showPassword ? "Hide password" : "Show password"
                              }
                              className="inline-flex items-center justify-center text-[#002D62] transition-colors hover:text-[#006747]"
                            >
                              <PasswordToggleIcon visible={showPassword} />
                            </button>
                          }
                          required
                        />
                        <PasswordStrengthMeter password={values.password ?? ""} />
                      </div>

                      <div
                        className={currentStep === 4 ? "space-y-2" : "hidden"}
                        aria-hidden={currentStep !== 4}
                      >
                        <Input
                          label="Confirm password"
                          type={showConfirmPassword ? "text" : "password"}
                          autoComplete="new-password"
                          placeholder="Re-enter your password"
                          {...register("rePassword")}
                          error={errors.rePassword?.message}
                          endElement={
                            <button
                              type="button"
                              onClick={() =>
                                setShowConfirmPassword((v) => !v)
                              }
                              aria-pressed={showConfirmPassword}
                              aria-label={
                                showConfirmPassword
                                  ? "Hide password"
                                  : "Show password"
                              }
                              className="inline-flex items-center justify-center text-[#002D62] transition-colors hover:text-[#006747]"
                            >
                              <PasswordToggleIcon
                                visible={showConfirmPassword}
                              />
                            </button>
                          }
                          required
                        />
                      </div>

                      <div
                        className={
                          currentStep === REVIEW_STEP_INDEX
                            ? "space-y-6"
                            : "hidden"
                        }
                        aria-hidden={currentStep !== REVIEW_STEP_INDEX}
                      >
                        <div className="rounded-2xl border border-[#002D62]/10 bg-white p-5 shadow-sm">
                          <h3 className="text-base font-semibold text-[#002D62]">
                            Summary
                          </h3>
                          <dl className="mt-4 space-y-3 text-sm text-slate-700">
                            <div className="flex justify-between gap-4">
                              <dt className="text-slate-500">Full name</dt>
                              <dd className="max-w-[60%] text-right font-medium text-slate-900">
                                {values.fullName}
                              </dd>
                            </div>
                            <div className="flex justify-between gap-4">
                              <dt className="text-slate-500">Phone</dt>
                              <dd className="font-medium text-slate-900">
                                {values.phoneNumber}
                              </dd>
                            </div>
                            <div className="flex flex-col items-end gap-2 sm:flex-row sm:justify-between sm:gap-4">
                              <dt className="text-slate-500 shrink-0">Email</dt>
                              <dd className="flex max-w-[min(100%,20rem)] flex-col items-end gap-2 text-right">
                                <span className="break-all font-medium text-slate-900">
                                  {values.email}
                                </span>
                                <button
                                  type="button"
                                  onClick={handleEditEmail}
                                  className="text-sm font-semibold text-[#002D62] underline-offset-2 hover:text-[#006747] hover:underline"
                                >
                                  Edit email
                                </button>
                              </dd>
                            </div>
                            <div className="flex justify-between gap-4">
                              <dt className="text-slate-500">Password</dt>
                              <dd className="font-mono tracking-widest text-slate-900">
                                ••••••••
                              </dd>
                            </div>
                          </dl>
                        </div>

                        <label className="flex cursor-pointer items-start gap-3 rounded-2xl border border-[#002D62]/10 bg-[#EFF6FF]/50 p-4">
                          <input
                            type="checkbox"
                            className="mt-1 h-4 w-4 shrink-0 rounded border-[#002D62]/30 text-[#002D62] focus:ring-[#006747]/35"
                            {...register("acceptTerms")}
                          />
                          <span className="text-sm text-slate-700">
                            I agree to the{" "}
                            <span className="font-semibold text-[#002D62]">
                              Terms of Service
                            </span>{" "}
                            and confirm my details are accurate.
                          </span>
                        </label>
                        {errors.acceptTerms?.message && (
                          <p className="text-sm text-[#B71C1C]">
                            {errors.acceptTerms.message}
                          </p>
                        )}
                      </div>
                    </div>

                    <div className="mt-10 flex flex-col-reverse gap-3 sm:flex-row sm:justify-between">
                      <Button
                        type="button"
                        variant="outline"
                        size="lg"
                        className="sm:min-w-[8rem]"
                        disabled={currentStep === 0 || isSubmitting}
                        onClick={goBack}
                      >
                        Back
                      </Button>

                      {currentStep < REVIEW_STEP_INDEX ? (
                        <Button
                          type="button"
                          variant="primary"
                          size="lg"
                          className="sm:min-w-[8rem]"
                          disabled={nextDisabled || isSubmitting}
                          onClick={handleNext}
                        >
                          Next
                        </Button>
                      ) : (
                        <Button
                          type="submit"
                          variant="primary"
                          size="lg"
                          className="sm:min-w-[8rem]"
                          isLoading={isSubmitting}
                          disabled={!reviewStepValid}
                        >
                          Create account
                        </Button>
                      )}
                    </div>
                  </motion.div>
                </AnimatePresence>
              </CardContent>
            </Card>

            <p className="mt-8 text-center text-sm text-slate-600">
              Already have an account?{" "}
              <Link
                href="/auth/login"
                className="font-semibold text-[#002D62] hover:text-[#006747]"
              >
                Login
              </Link>
            </p>
            <p className="mt-4 text-center text-xs text-gray-500">
              Official NIERS registration portal | 2026
            </p>
          </section>
        </form>
      </div>
    </div>
  );
};
