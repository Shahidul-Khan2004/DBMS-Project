import { publicPost } from "@/lib/api";
import type { RegisterInput } from "@/lib/validations";
import type { RegisterResponse } from "@/types/auth";

export type RegisterFieldName = keyof RegisterInput;
export type RegisterFieldErrors = Partial<Record<RegisterFieldName, string>>;

export function getRegisterFieldName(field: unknown): RegisterFieldName | null {
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

export function getBackendFieldErrors(details: unknown): RegisterFieldErrors {
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

export function mapZodRegisterIssues(
  issues: readonly { path: readonly PropertyKey[]; message: string }[],
): RegisterFieldErrors {
  const next: RegisterFieldErrors = {};

  for (const issue of issues) {
    const field = getRegisterFieldName(issue.path[0]);
    if (field && !next[field]) {
      next[field] = issue.message;
    }
  }

  return next;
}

/** Wizard step index for API field errors (5-step citizen registration UI). */
export function registerStepIndex(field: RegisterFieldName): number {
  switch (field) {
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
    default:
      return 0;
  }
}

export function registerApiErrorFieldStep(
  fieldErrors: RegisterFieldErrors,
): number {
  const keys = Object.keys(fieldErrors) as RegisterFieldName[];
  if (keys.length === 0) return 0;
  return Math.max(...keys.map(registerStepIndex));
}

export async function registerCitizen(
  data: RegisterInput,
): Promise<RegisterResponse> {
  return publicPost<RegisterResponse, RegisterInput>("/auth/register", data);
}
