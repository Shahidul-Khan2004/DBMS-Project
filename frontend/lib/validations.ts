import { z } from "zod";

const strongPasswordSchema = z
  .string()
  .min(1, "Password is required")
  .min(8, "Password must be at least 8 characters long")
  .regex(/[a-z]/, "Password must include a lowercase letter")
  .regex(/[A-Z]/, "Password must include an uppercase letter")
  .regex(/\d/, "Password must include a number")
  .regex(
    /[^A-Za-z0-9]/,
    "Password must include a special character",
  );

const registerObjectSchema = z.object({
  email: z
    .string()
    .trim()
    .min(1, "Email address is required")
    .pipe(z.email({ message: "Invalid email format" })),
  fullName: z.string().trim().min(1, "Full name is required"),
  phoneNumber: z
    .string()
    .trim()
    .min(1, "Phone number is required")
    .regex(
      /^01\d{9}$/,
      "Use a valid Bangladesh mobile number (01XXXXXXXXX, 11 digits)",
    ),
  password: strongPasswordSchema,
  rePassword: z.string().min(1, "Confirm password is required"),
});

export const registerSchema = registerObjectSchema.refine(
  (data) => data.password === data.rePassword,
  {
    message: "Passwords do not match",
    path: ["rePassword"],
  },
);

/** 0–5 score aligned with strongPasswordSchema checks (length, lower, upper, digit, special). */
export function getPasswordStrengthScore(password: string): 0 | 1 | 2 | 3 | 4 | 5 {
  let score = 0;
  if (password.length >= 8) score += 1;
  if (/[a-z]/.test(password)) score += 1;
  if (/[A-Z]/.test(password)) score += 1;
  if (/\d/.test(password)) score += 1;
  if (/[^A-Za-z0-9]/.test(password)) score += 1;
  return score as 0 | 1 | 2 | 3 | 4 | 5;
}

/** Step 0 — full name only. */
export const registerStepFullNameSchema = registerObjectSchema.pick({
  fullName: true,
});

/** Step 1 — phone only. */
export const registerStepPhoneSchema = registerObjectSchema.pick({
  phoneNumber: true,
});

/** Step 2 — email only. */
export const registerStepEmailFieldSchema = registerObjectSchema.pick({
  email: true,
});

/** Step 3 — create password (password field only). */
export const registerStepCreatePasswordSchema = registerObjectSchema.pick({
  password: true,
});

/** Step 4 — confirm password must match create password (uses both fields). */
export const registerStepConfirmPasswordStepSchema = registerObjectSchema
  .pick({ password: true, rePassword: true })
  .refine((data) => data.password === data.rePassword, {
    message: "Passwords do not match",
    path: ["rePassword"],
  });

/** Strict 6-digit OTP — reserved for when email verification is wired to the backend. */
export const registerStepOtpSchema = z.object({
  otp: z
    .string()
    .regex(/^\d{6}$/, "Enter the complete 6-digit code"),
});

/** @deprecated Multi-field bundle; prefer single-step schemas above. */
export const registerStepPersonalSchema = registerObjectSchema.pick({
  fullName: true,
  phoneNumber: true,
  email: true,
});

/** @deprecated Use registerStepConfirmPasswordStepSchema. */
export const registerStepPasswordSchema = registerObjectSchema
  .pick({ password: true, rePassword: true })
  .refine((data) => data.password === data.rePassword, {
    message: "Passwords do not match",
    path: ["rePassword"],
  });

/**
 * RHF resolver: no password-match refine (avoid rePassword errors on step 3).
 * Match is enforced on step 4 and on submit via registerWizardSubmitSchema.
 */
export const registerWizardFormValuesSchema = registerObjectSchema.extend({
  acceptTerms: z.boolean(),
});

export type RegisterInput = z.infer<typeof registerObjectSchema>;

export type RegisterWizardInput = z.infer<typeof registerWizardFormValuesSchema>;

/** Final POST body to `/auth/register` (strip wizard fields). */
export function toRegisterPayload(
  data: RegisterWizardInput,
): RegisterInput {
  const { acceptTerms: _terms, ...rest } = data;
  return rest;
}

/** Final submit: terms + credentials + password match (OTP disabled until backend exists). */
export const registerWizardSubmitSchema = registerObjectSchema
  .extend({
    acceptTerms: z.literal(true, {
      error: () => ({ message: "You must accept the terms and conditions" }),
    }),
  })
  .refine((data) => data.password === data.rePassword, {
    message: "Passwords do not match",
    path: ["rePassword"],
  });

/** @deprecated Use registerStepEmailFieldSchema. */
export const registerStepEmailSchema = registerObjectSchema.pick({
  email: true,
});

/** @deprecated Use registerStepFullNameSchema / registerStepPhoneSchema. */
export const registerStepProfileSchema = registerObjectSchema.pick({
  fullName: true,
  phoneNumber: true,
});

export const loginSchema = z.object({
  email: z
    .string()
    .trim()
    .min(1, "Email address is required")
    .pipe(z.email({ message: "Invalid email format" })),
  password: z.string().min(1, "Password is required"),
});

export type LoginInput = z.infer<typeof loginSchema>;
