"use client";

import { type FormEvent, useState } from "react";
import { AdminPageHeader } from "@/components/admin/AdminPageHeader";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import { Button } from "@/components/ui/Button";
import { assignUserRole } from "@/lib/admin-user-api";
import {
  formatRoleAssignmentError,
  UUID_PATTERN,
} from "@/lib/admin-role-errors";

const ROLE_OPTIONS = [
  { roleCode: "citizen", name: "Citizen" },
  { roleCode: "dispatcher", name: "Dispatcher" },
  { roleCode: "system_admin", name: "System Admin" },
] as const;

export function RoleAssignmentWorkspace() {
  const [userPublicUuid, setUserPublicUuid] = useState("");
  const [roleCode, setRoleCode] = useState<string>("dispatcher");
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [message, setMessage] = useState<{
    type: "success" | "error";
    text: string;
  } | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const trimmedId = userPublicUuid.trim();
    const normalizedRole = roleCode.trim().toLowerCase();
    const errors: Record<string, string> = {};

    if (!trimmedId) {
      errors.userPublicUuid = "Target user public UUID is required.";
    } else if (!UUID_PATTERN.test(trimmedId)) {
      errors.userPublicUuid = "Enter a valid user public UUID.";
    }

    if (!ROLE_OPTIONS.some((r) => r.roleCode === normalizedRole)) {
      errors.roleCode = "Selected role is not available.";
    }

    if (Object.keys(errors).length > 0) {
      setFieldErrors(errors);
      return;
    }

    setFieldErrors({});
    setMessage(null);
    setIsSubmitting(true);

    try {
      const data = await assignUserRole(trimmedId, normalizedRole);
      const roleName =
        ROLE_OPTIONS.find((r) => r.roleCode === normalizedRole)?.name ??
        normalizedRole;
      setMessage({
        type: "success",
        text:
          typeof data.message === "string"
            ? data.message
            : `Role "${roleName}" assigned successfully.`,
      });
    } catch (err) {
      setMessage({
        type: "error",
        text: formatRoleAssignmentError(err),
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-4">
      <AdminPageHeader
        title="Role Assignment"
        subtitle="Grant supported platform roles to existing users."
      />

      <div className="min-h-0 flex-1">
        <section className="rounded-xl border border-slate-200/80 bg-white p-5 shadow-sm">
          <form className="space-y-5" onSubmit={(event) => void handleSubmit(event)}>
            <div>
              <FieldLabel htmlFor="role-target-uuid" required>
                Target user public UUID
              </FieldLabel>
              <input
                id="role-target-uuid"
                type="text"
                value={userPublicUuid}
                onChange={(e) => {
                  setUserPublicUuid(e.target.value);
                  setMessage(null);
                }}
                className={triageFieldClassName}
                autoComplete="off"
                required
              />
              {fieldErrors.userPublicUuid ? (
                <p className="mt-1 text-xs text-red-600">
                  {fieldErrors.userPublicUuid}
                </p>
              ) : null}
            </div>

            <div>
              <FieldLabel htmlFor="role-code" required>
                Role
              </FieldLabel>
              <select
                id="role-code"
                value={roleCode}
                onChange={(e) => {
                  setRoleCode(e.target.value);
                  setMessage(null);
                }}
                className={triageFieldClassName}
                required
              >
                {ROLE_OPTIONS.map(({ roleCode: code, name }) => (
                  <option key={code} value={code}>
                    {name}
                  </option>
                ))}
              </select>
              {fieldErrors.roleCode ? (
                <p className="mt-1 text-xs text-red-600">{fieldErrors.roleCode}</p>
              ) : null}
            </div>

            <Button type="submit" isLoading={isSubmitting} disabled={isSubmitting}>
              Assign Role
            </Button>

            {message ? (
              <div
                className={`rounded-xl border p-3 text-sm ${
                  message.type === "success"
                    ? "border-emerald-200 bg-emerald-50 text-emerald-800"
                    : "border-red-200 bg-red-50 text-red-700"
                }`}
              >
                {message.text}
              </div>
            ) : null}
          </form>
        </section>
      </div>
    </div>
  );
}
