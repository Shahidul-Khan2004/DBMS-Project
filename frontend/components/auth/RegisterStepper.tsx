"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { AnimatePresence, motion } from "framer-motion";
import { Check } from "lucide-react";
import Link from "next/link";
import React, { useCallback, useMemo, useState } from "react";
import { useForm, type FieldErrors } from "react-hook-form";
import { toast } from "sonner";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { ApiError, publicPost } from "@/lib/api";
import {
  getBackendFieldErrors,
  registerApiErrorFieldStep,
} from "@/lib/register-api";
import type { RegisterFieldName } from "@/lib/register-api";
import {
  registerStepConfirmPasswordStepSchema,
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
    subtitle: "Choose a password and confirm it below",
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
      return 3;
    case "acceptTerms":
      return 4;
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

function isStepReachable(
  index: number,
  step0Valid: boolean,
  step1Valid: boolean,
  step2Valid: boolean,
  step3Valid: boolean,
): boolean {
  switch (index) {
    case 0:
      return true;
    case 1:
      return step0Valid;
    case 2:
      return step0Valid && step1Valid;
    case 3:
      return step0Valid && step1Valid && step2Valid;
    case 4:
      return step0Valid && step1Valid && step2Valid && step3Valid;
    default:
      return false;
  }
}

function isStepComplete(
  index: number,
  step0Valid: boolean,
  step1Valid: boolean,
  step2Valid: boolean,
  step3Valid: boolean,
  acceptTerms: boolean,
): boolean {
  switch (index) {
    case 0:
      return step0Valid;
    case 1:
      return step1Valid;
    case 2:
      return step2Valid;
    case 3:
      return step3Valid;
    case 4:
      return (
        step0Valid &&
        step1Valid &&
        step2Valid &&
        step3Valid &&
        acceptTerms
      );
    default:
      return false;
  }
}

function registerInputClass(hasError: boolean) {
  const base =
    "rounded-2xl border border-[#B8C7D6] bg-[#FDFEFF] px-4 py-3 text-[#0F172A] placeholder:text-[#7A8CA3] shadow-sm focus:border-[#002D62] focus:outline-none focus:ring-4 focus:ring-[#002D62]/10";
  const err =
    "border-[#DA291C] bg-[#FDECEC] focus:border-[#DA291C] focus:ring-4 focus:ring-[#DA291C]/10";
  return [base, hasError && err].filter(Boolean).join(" ");
}

function stepButtonClass(active: boolean, done: boolean, navigable: boolean) {
  if (active) {
    return "border-transparent bg-[#002D62] text-white shadow-lg shadow-[#002D62]/20";
  }
  if (done) {
    return "border-transparent bg-[#E1F1EA] text-[#006747] ring-1 ring-[#006747]/20";
  }
  return [
    "border-transparent bg-[#F7F9FC] text-slate-600 ring-1 ring-[#C9D6E3]",
    navigable
      ? "cursor-pointer hover:ring-[#002D62]/20"
      : "cursor-default opacity-75 disabled:cursor-not-allowed",
  ].join(" ");
}

function stepBadgeClass(active: boolean, done: boolean) {
  if (active) return "bg-white/15 text-white";
  if (done) return "bg-[#006747] text-white";
  return "bg-[#F7F9FC] text-slate-500 ring-1 ring-[#C9D6E3]";
}

function stepTitleClass(active: boolean, done: boolean) {
  if (active) return "text-white";
  if (done) return "text-[#006747]";
  return "text-slate-600";
}

function stepSubtitleClass(active: boolean, done: boolean) {
  if (active) return "text-white/80";
  if (done) return "text-[#006747]/80";
  return "text-slate-500";
}

export const RegisterStepper: React.FC<RegisterStepperProps> = ({
  onSuccess,
}) => {
  const [currentStep, setCurrentStep] = useState(0);
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
      registerStepConfirmPasswordStepSchema.safeParse({
        password: values.password,
        rePassword: values.rePassword,
      }).success,
    [values.password, values.rePassword],
  );

  const reviewStepValid = values.acceptTerms === true;

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
      default:
        return true;
    }
  }, [currentStep, step0Valid, step1Valid, step2Valid, step3Valid]);

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
    clearErrors();
    if (!validateCurrentStep()) return;
    goNext();
  }, [clearErrors, goNext, validateCurrentStep]);

  const goToStep = useCallback(
    (index: number) => {
      if (
        index === currentStep ||
        isSubmitting ||
        !isStepReachable(index, step0Valid, step1Valid, step2Valid, step3Valid)
      ) {
        return;
      }
      if (currentStep === REVIEW_STEP_INDEX && index < REVIEW_STEP_INDEX) {
        setValue("acceptTerms", false, { shouldValidate: true });
        clearErrors(["acceptTerms"]);
      }
      clearErrors();
      setCurrentStep(index);
    },
    [
      clearErrors,
      currentStep,
      isSubmitting,
      setValue,
      step0Valid,
      step1Valid,
      step2Valid,
      step3Valid,
    ],
  );

  const handleEditEmail = useCallback(() => {
    goToStep(2);
  }, [goToStep]);

  const onRegister = useCallback(
    async (data: RegisterWizardInput) => {
      const parsed = registerWizardSubmitSchema.safeParse(data);
      if (!parsed.success) {
        applyZodIssuesToForm(parsed.error.issues, setError);
        setCurrentStep(firstWizardStepFromZodIssues(parsed.error.issues));
        return;
      }

      setIsSubmitting(true);
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
            const step = registerApiErrorFieldStep(backendFieldErrors);
            setCurrentStep(step);
            for (const [field, message] of Object.entries(backendFieldErrors)) {
              setError(field as RegisterFieldName, { message });
            }
            return;
          }
        }
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

  const renderStepButton = (
    index: number,
    variant: "compact" | "vertical",
  ) => {
    const step = STEP_META[index];
    const active = index === currentStep;
    const complete = isStepComplete(
      index,
      step0Valid,
      step1Valid,
      step2Valid,
      step3Valid,
      values.acceptTerms,
    );
    const done = complete && !active;
    const reachable = isStepReachable(
      index,
      step0Valid,
      step1Valid,
      step2Valid,
      step3Valid,
    );
    const navigable = !active && !isSubmitting && reachable;

    const badge = (
      <span
        className={[
          "flex shrink-0 items-center justify-center rounded-full text-sm font-bold",
          variant === "compact" ? "h-7 w-7" : "h-9 w-9",
          stepBadgeClass(active, done),
        ].join(" ")}
      >
        {done ? (
          <Check
            className={variant === "compact" ? "h-3.5 w-3.5" : "h-4 w-4"}
            aria-hidden
          />
        ) : (
          index + 1
        )}
      </span>
    );

    if (variant === "compact") {
      return (
        <button
          key={step.title}
          type="button"
          disabled={!navigable}
          onClick={() => goToStep(index)}
          aria-current={active ? "step" : undefined}
          aria-label={navigable ? `Go to ${step.title}` : step.title}
          className={[
            "flex shrink-0 items-center gap-2 rounded-xl border px-3 py-2 text-left transition-colors",
            "focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#002D62]",
            stepButtonClass(active, done, navigable),
          ].join(" ")}
        >
          {badge}
          <span
            className={[
              "whitespace-nowrap text-xs font-semibold sm:text-sm",
              stepTitleClass(active, done),
            ].join(" ")}
          >
            {step.title}
          </span>
        </button>
      );
    }

    return (
      <li key={step.title}>
        <button
          type="button"
          disabled={!navigable}
          onClick={() => goToStep(index)}
          aria-current={active ? "step" : undefined}
          aria-label={navigable ? `Go to ${step.title}` : undefined}
          className={[
            "flex w-full gap-3 rounded-2xl border px-4 py-3.5 text-left transition-colors",
            "focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#002D62]",
            stepButtonClass(active, done, navigable),
          ].join(" ")}
        >
          {badge}
          <span className="min-w-0">
            <span
              className={[
                "block text-sm font-semibold sm:text-base",
                stepTitleClass(active, done),
              ].join(" ")}
            >
              {step.title}
            </span>
            <span
              className={[
                "mt-0.5 block text-xs sm:text-sm",
                stepSubtitleClass(active, done),
              ].join(" ")}
            >
              {step.subtitle}
            </span>
          </span>
        </button>
      </li>
    );
  };

  const isReviewStep = currentStep === REVIEW_STEP_INDEX;

  return (
    <motion.div className="min-h-screen bg-[radial-gradient(circle_at_top_left,rgba(0,103,71,0.10),transparent_30%),linear-gradient(135deg,#EEF6FB_0%,#F3FAF7_48%,#EAF3FB_100%)] lg:min-h-[100svh] lg:overflow-hidden">
      <nav className="fixed top-0 inset-x-0 z-50 w-full border-b border-gray-200 bg-zinc-200/95 backdrop-blur-md">
        <div className="w-full px-4 sm:px-6 md:px-5 lg:px-8 xl:px-10 2xl:px-12">
          <div className="flex min-h-24 items-center justify-between gap-3 py-4 md:min-h-28 md:gap-4 md:py-5 lg:min-h-32 lg:gap-6">
          <Link
            href="/"
            className="flex shrink-0 cursor-pointer items-center rounded-md focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#002D62]"
          >
            <div className="bg-[#002D62] px-7 py-3 text-2xl font-bold tracking-[-1px] text-white md:px-8 md:py-3.5 md:text-3xl lg:px-9 lg:py-4 lg:text-[2.25rem]">
              NIERS
            </div>
          </Link>
          <Link
            href="/auth/login"
            className="cursor-pointer rounded-2xl border-2 border-primary-600 px-7 py-3 text-base font-semibold text-primary-600 transition-colors hover:border-primary-700 hover:bg-gray-50 hover:text-primary-700 md:px-8 md:py-3.5 lg:text-lg"
          >
            Login
          </Link>
          </div>
        </div>
      </nav>

      <div className="mx-auto max-w-[1360px] px-6 pb-6 pt-[calc(96px+3rem)] lg:pt-[calc(128px+3rem)]">
        <div className="mb-7 max-w-xl">
          <h1 className="text-4xl font-extrabold tracking-tight text-[#002D62] lg:text-[2.65rem] lg:leading-[1.05]">
            Create your Citizen Account
          </h1>
          <p className="mt-3 max-w-2xl text-base leading-7 text-slate-600">
            Join the National Integrated Emergency Response System.
          </p>
        </div>

        <form
          className="grid gap-8 lg:grid-cols-[360px_minmax(680px,1fr)] lg:items-start lg:gap-12"
          onSubmit={handleSubmit(onRegister, onSubmitInvalid)}
          onKeyDown={onFormKeyDown}
          noValidate
        >
          <aside className="min-w-0 lg:w-[360px] lg:shrink-0">
            <div className="rounded-3xl border border-[#C9D6E3] bg-[#F7F9FC] p-4 shadow-xl shadow-[#002D62]/10">
              <nav
                aria-label="Registration steps"
                className="flex max-w-full gap-2 overflow-x-auto lg:hidden"
              >
                {STEP_META.map((_, index) =>
                  renderStepButton(index, "compact"),
                )}
              </nav>
              <nav
                aria-label="Registration steps"
                className="hidden lg:block"
              >
                <ol className="flex flex-col gap-2">
                  {STEP_META.map((_, index) =>
                    renderStepButton(index, "vertical"),
                  )}
                </ol>
              </nav>
            </div>
            <p className="mt-4 text-center text-xs text-[#64748B] lg:mt-3 lg:text-left">
              Step {currentStep + 1} of {TOTAL_STEPS}
            </p>
          </aside>

          <section className="min-w-0">
            <motion.div className="flex min-h-[330px] items-center justify-center rounded-[2rem] border border-[#C9D6E3] bg-[#E8EDF3]/70 p-10 shadow-xl shadow-[#002D62]/10 [&_label]:text-[#0F172A] [&_p]:text-[#64748B] [&_[id$='-error']]:text-[#DA291C]">
                <AnimatePresence mode="wait">
                  <motion.div
                    key={currentStep}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -6 }}
                    transition={{ duration: 0.2 }}
                    className="mx-auto w-full max-w-[520px]"
                  >
                    <h2 className="text-xl font-bold text-[#002D62] lg:hidden sm:text-2xl">
                      {STEP_META[currentStep].title}
                    </h2>
                    <p className="mt-1 text-sm text-[#64748B] lg:hidden sm:text-base">
                      {STEP_META[currentStep].subtitle}
                    </p>
                    <div className="mt-6 space-y-6 lg:mt-0">
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
                          className={registerInputClass(!!errors.fullName)}
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
                          className={registerInputClass(!!errors.phoneNumber)}
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
                          className={registerInputClass(!!errors.email)}
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
                          placeholder="Create a password"
                          helpText="Minimum 8 characters."
                          {...register("password")}
                          error={errors.password?.message}
                          className={registerInputClass(!!errors.password)}
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
                        <Input
                          label="Confirm password"
                          type={showConfirmPassword ? "text" : "password"}
                          autoComplete="new-password"
                          placeholder="Re-enter your password"
                          {...register("rePassword")}
                          error={errors.rePassword?.message}
                          className={registerInputClass(!!errors.rePassword)}
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
                            ? "space-y-4"
                            : "hidden"
                        }
                        aria-hidden={currentStep !== REVIEW_STEP_INDEX}
                      >
                        <div className="rounded-3xl border border-[#C9D6E3] bg-[#F7F9FC] p-6 shadow-lg shadow-[#002D62]/10">
                          <h3 className="text-base font-semibold text-[#002D62]">
                            Summary
                          </h3>
                          <dl className="mt-4 space-y-2 text-sm">
                            <div className="flex justify-between gap-4">
                              <dt className="text-[#64748B]">Full name</dt>
                              <dd className="max-w-[60%] text-right font-medium text-[#0F172A]">
                                {values.fullName}
                              </dd>
                            </div>
                            <div className="flex justify-between gap-4">
                              <dt className="text-[#64748B]">Phone</dt>
                              <dd className="font-medium text-[#0F172A]">
                                {values.phoneNumber}
                              </dd>
                            </div>
                            <div className="flex flex-col items-end gap-2 sm:flex-row sm:justify-between sm:gap-4">
                              <dt className="shrink-0 text-[#64748B]">Email</dt>
                              <dd className="flex max-w-[min(100%,20rem)] flex-col items-end gap-2 text-right">
                                <span className="break-all font-medium text-[#0F172A]">
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
                              <dt className="text-[#64748B]">Password</dt>
                              <dd className="font-mono tracking-widest text-[#0F172A]">
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
                          <p className="text-sm text-[#DA291C]">
                            {errors.acceptTerms.message}
                          </p>
                        )}
                      </div>
                    </div>
                    <div className="mt-6 flex flex-col-reverse gap-3 sm:flex-row sm:items-center sm:justify-between sm:gap-6">
                      <Button
                        type="button"
                        variant="outline"
                        size="lg"
                        className="border-2 border-[#002D62] bg-[#F7F9FC] text-[#002D62] hover:bg-[#EFF6FF] sm:min-w-[8rem] disabled:opacity-100 disabled:bg-[#F7F9FC] disabled:text-[#7F96B3] disabled:border-[#C9D6E3]"
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
                          className="bg-[#002D62] text-white shadow-lg shadow-[#002D62]/20 hover:bg-[#001F4A] sm:min-w-[8rem] disabled:opacity-100 disabled:bg-[#7F96B3] disabled:cursor-not-allowed disabled:shadow-none"
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
                          className="bg-[#002D62] text-white shadow-lg shadow-[#002D62]/20 hover:bg-[#001F4A] sm:min-w-[8rem] disabled:opacity-100 disabled:bg-[#7F96B3] disabled:cursor-not-allowed disabled:shadow-none"
                          isLoading={isSubmitting}
                          disabled={!reviewStepValid}
                        >
                          Create account
                        </Button>
                      )}
                    </div>
                  </motion.div>
                </AnimatePresence>
            </motion.div>

            <p className="mt-4 text-center text-sm text-[#64748B]">
              Already have an account?{" "}
              <Link
                href="/auth/login"
                className="font-semibold text-[#002D62] hover:text-[#006747]"
              >
                Login
              </Link>
            </p>
            <p className="mt-2 text-center text-xs text-[#64748B]">
              Official NIERS registration portal | 2026
            </p>
          </section>
        </form>
      </div>
    </motion.div>
  );
};
