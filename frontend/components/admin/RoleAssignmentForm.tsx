"use client";

import { type FormEvent, useMemo, useState } from "react";
import { ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Card, CardHeader, CardContent } from "@/components/ui/Card";
import { ApiError, apiPost } from "@/lib/api";
import { getAuthSession } from "@/lib/auth-store";

/** Display names aligned with `roles` seed in schema.sql */
const ROLE_OPTIONS: { roleCode: string; name: string }[] = [
  { roleCode: "citizen", name: "Citizen" },
  { roleCode: "dispatcher", name: "Dispatcher" },
  { roleCode: "agency_representative", name: "Agency Representative" },
  { roleCode: "system_admin", name: "System Admin" },
];

type RoleAssignmentResponse = {
  message?: string;
  userId?: string;
  roleCode?: string;
};

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function formatRoleAssignmentError(error: unknown) {
  if (error instanceof ApiError) {
    const hints: Record<string, string> = {
      FORBIDDEN:
        "You need the auth.manage_roles permission to assign roles.",
      ROLE_NOT_FOUND:
        "The role code does not exist. Use an existing role such as dispatcher or system_admin.",
      USER_NOT_FOUND:
        "No user was found for that public UUID.",
      ROLE_ALREADY_ASSIGNED:
        "That user already has this role.",
    };

    const hint = error.code ? hints[error.code] : undefined;
    return `${error.code ? `${error.code}: ` : ""}${error.message}${
      hint ? ` ${hint}` : ""
    }`;
  }

  return error instanceof Error ? error.message : "Failed to assign role.";
}

export const RoleAssignmentForm: React.FC = () => {
  const assignableRoles = useMemo(() => {
    const { userRole } = getAuthSession();
    const canAssignSystemAdmin = userRole === "system_admin";
    return ROLE_OPTIONS.filter(
      (r) => r.roleCode !== "system_admin" || canAssignSystemAdmin,
    );
  }, []);

  const [userId, setUserId] = useState("");
  const [selectedRoleCode, setSelectedRoleCode] = useState(
    () => assignableRoles[0]?.roleCode ?? "dispatcher",
  );
  const [isAssigning, setIsAssigning] = useState(false);
  const [message, setMessage] = useState<{
    type: "success" | "error";
    text: string;
  } | null>(null);
  const [lastResult, setLastResult] = useState<RoleAssignmentResponse | null>(
    null,
  );

  const handleAssignRole = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    const trimmedId = userId.trim();
    const normalizedRoleCode = selectedRoleCode.trim().toLowerCase();

    if (!trimmedId) {
      setMessage({
        type: "error",
        text: "Enter the target user's public UUID.",
      });
      return;
    }

    if (!UUID_PATTERN.test(trimmedId)) {
      setMessage({
        type: "error",
        text: "Target user public UUID must be a valid UUID.",
      });
      return;
    }

    if (!assignableRoles.some((r) => r.roleCode === normalizedRoleCode)) {
      setMessage({ type: "error", text: "Selected role is not available." });
      return;
    }

    setIsAssigning(true);
    setMessage(null);
    setLastResult(null);

    try {
      const data = await apiPost<RoleAssignmentResponse>(
        `/users/${encodeURIComponent(trimmedId)}/roles`,
        { roleCode: normalizedRoleCode },
      );

      const roleName =
        assignableRoles.find((r) => r.roleCode === normalizedRoleCode)?.name ??
        normalizedRoleCode;

      setLastResult(data);
      setMessage({
        type: "success",
        text:
          typeof data?.message === "string"
            ? data.message
            : `Role "${roleName}" assigned successfully to user ${trimmedId}.`,
      });
    } catch (error) {
      setMessage({
        type: "error",
        text: formatRoleAssignmentError(error),
      });
    } finally {
      setIsAssigning(false);
    }
  };

  return (
    <Card className="overflow-hidden shadow-md">
      <CardHeader>
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-[#002D62] text-white">
            <ShieldCheck className="h-5 w-5" aria-hidden />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-[#002D62]">
              Assign Role
            </h2>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <form className="w-full space-y-5" onSubmit={handleAssignRole}>
          <div className="grid w-full gap-4 sm:grid-cols-2 sm:items-end">
            <div className="min-w-0">
              <Input
                label="Target User Public UUID"
                value={userId}
                onChange={(e) => {
                  setUserId(e.target.value);
                  setMessage(null);
                }}
                placeholder="0d5fd834-a3fc-4180-b8ec-a6e664d130d0"
                autoComplete="off"
                required
              />
            </div>

            <div className="min-w-0">
              <label
                htmlFor="role-assignment-role"
                className="block text-sm font-medium text-gray-700 mb-2"
              >
                Role
              </label>
              <select
                id="role-assignment-role"
                value={selectedRoleCode}
                onChange={(e) => {
                  setSelectedRoleCode(e.target.value.toLowerCase());
                  setMessage(null);
                }}
                className="block h-[46px] w-full rounded-2xl border border-[#002D62]/20 bg-white px-3 py-2 text-sm text-gray-900 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35"
              >
                {assignableRoles.map(({ roleCode, name }) => (
                  <option key={roleCode} value={roleCode}>
                    {name}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <Button
            type="submit"
            isLoading={isAssigning}
            disabled={isAssigning}
          >
            Assign Role
          </Button>

          {message && (
            <div
              className={`rounded-2xl border p-3 text-sm ${
                message.type === "success"
                  ? "border-emerald-200 bg-emerald-50 text-emerald-700"
                  : "border-red-200 bg-red-50 text-red-700"
              }`}
            >
              {message.text}
            </div>
          )}

          {lastResult ? (
            <dl className="grid gap-3 rounded-2xl border border-[#002D62]/10 bg-[#EFF6FF] p-4 text-sm sm:grid-cols-2">
              <div>
                <dt className="font-medium text-gray-600">User ID</dt>
                <dd className="mt-1 break-all text-gray-900">
                  {lastResult.userId ?? userId.trim()}
                </dd>
              </div>
              <div>
                <dt className="font-medium text-gray-600">Role Code</dt>
                <dd className="mt-1 font-semibold text-[#002D62]">
                  {lastResult.roleCode ?? selectedRoleCode}
                </dd>
              </div>
            </dl>
          ) : null}
        </form>
      </CardContent>
    </Card>
  );
};
