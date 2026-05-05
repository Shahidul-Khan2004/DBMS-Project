"use client";

import { useMemo, useState } from "react";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Card, CardHeader, CardContent } from "@/components/ui/Card";
import { getAuthSession } from "@/lib/auth-store";

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8080";

/** Display names aligned with `roles` seed in schema.sql */
const ROLE_OPTIONS: { roleCode: string; name: string }[] = [
  { roleCode: "citizen", name: "Citizen" },
  { roleCode: "dispatcher", name: "Dispatcher" },
  { roleCode: "agency_representative", name: "Agency Representative" },
  { roleCode: "system_admin", name: "System Admin" },
];

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
    () => assignableRoles[0]?.roleCode ?? "citizen",
  );
  const [isAssigning, setIsAssigning] = useState(false);
  const [message, setMessage] = useState<{
    type: "success" | "error";
    text: string;
  } | null>(null);

  const handleAssignRole = async () => {
    const trimmedId = userId.trim();
    if (!trimmedId) {
      setMessage({ type: "error", text: "Please enter a user ID" });
      return;
    }

    if (!assignableRoles.some((r) => r.roleCode === selectedRoleCode)) {
      setMessage({ type: "error", text: "Selected role is not available" });
      return;
    }

    setIsAssigning(true);
    setMessage(null);

    try {
      const accessToken = localStorage.getItem("accessToken");
      const response = await fetch(
        `${API_BASE}/users/${encodeURIComponent(trimmedId)}/roles`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${accessToken}`,
          },
          body: JSON.stringify({
            roleCode: selectedRoleCode,
          }),
        },
      );

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        const errMsg =
          data?.error?.message ?? data?.message ?? "Failed to assign role";
        throw new Error(typeof errMsg === "string" ? errMsg : "Request failed");
      }

      const roleName =
        assignableRoles.find((r) => r.roleCode === selectedRoleCode)?.name ??
        selectedRoleCode;

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
        text: error instanceof Error ? error.message : "Failed to assign role",
      });
    } finally {
      setIsAssigning(false);
    }
  };

  return (
    <Card className="shadow-md">
      <CardHeader>
        <h2 className="text-lg font-semibold text-gray-900">Assign role</h2>
      </CardHeader>
      <CardContent>
        <div className="w-full space-y-4">
          <div className="grid w-full gap-4 sm:grid-cols-2 sm:items-end">
            <div className="min-w-0">
              <Input
                label="User ID"
                value={userId}
                onChange={(e) => setUserId(e.target.value)}
                placeholder="Target user UUID"
                autoComplete="off"
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
                onChange={(e) => setSelectedRoleCode(e.target.value)}
                className="block h-[42px] w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
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
            onClick={handleAssignRole}
            isLoading={isAssigning}
            disabled={isAssigning}
            className="bg-green-600 hover:bg-green-700"
          >
            Assign role
          </Button>

          {message && (
            <div
              className={`rounded-lg p-3 text-sm ${
                message.type === "success"
                  ? "bg-green-50 text-green-700"
                  : "bg-red-50 text-red-700"
              }`}
            >
              {message.text}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
};
