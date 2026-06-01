import { ApiError } from "@/lib/api";

export function formatRoleAssignmentError(error: unknown): string {
  if (error instanceof ApiError) {
    const hints: Record<string, string> = {
      FORBIDDEN:
        "You need the auth.manage_roles permission to assign roles.",
      ROLE_NOT_FOUND:
        "The role code does not exist. Use an existing role such as dispatcher or system_admin.",
      USER_NOT_FOUND: "No user was found for that public UUID.",
      ROLE_ALREADY_ASSIGNED: "That user already has this role.",
      ROLE_ASSIGNMENT_NOT_ALLOWED:
        "Agency representatives must be linked through Agencies, not direct role assignment.",
    };

    const hint = error.code ? hints[error.code] : undefined;
    return `${error.code ? `${error.code}: ` : ""}${error.message}${
      hint ? ` ${hint}` : ""
    }`;
  }

  return error instanceof Error ? error.message : "Failed to assign role.";
}

export const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
