"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardContent, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { ConfirmModal } from "@/components/ui/ConfirmModal";
import { clearAuthSession, getValidAccessToken } from "@/lib/auth-store";

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8080";

const labelClassName = "block text-sm font-medium text-gray-700";
const fieldClassName =
  "mt-1 w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-gray-900 placeholder-gray-400";

export default function ClassifyIntakeAsServiceCasePage() {
  const router = useRouter();
  const params = useParams();
  const reportPublicUuid = params.reportPublicUuid as string;

  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [priorityLevel, setPriorityLevel] = useState("medium");
  const [isLoadingSession, setIsLoadingSession] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [confirmOpen, setConfirmOpen] = useState(false);

  const redirectToLogin = useCallback(() => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/auth/login");
  }, [router]);

  useEffect(() => {
    const sessionUser = sessionStorage.getItem("loggedInUser");
    const token = getValidAccessToken();

    if (!sessionUser || !token) {
      redirectToLogin();
      return;
    }

    setIsLoadingSession(false);
  }, [redirectToLogin]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  async function classifyReport() {
    setLoading(true);
    setError("");

    try {
      const token = getValidAccessToken();

      if (!token) {
        redirectToLogin();
        return;
      }

      const res = await fetch(
        `${API_BASE}/intake/reports/${reportPublicUuid}/classify/service-case`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({
            title: title || undefined,
            description: description || undefined,
            priorityLevel,
          }),
        },
      );

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        throw new Error(
          data?.error?.message ||
            data?.message ||
            data?.code ||
            "Classification failed",
        );
      }

      router.push(`/dashboard/dispatcher/intake-reports/${reportPublicUuid}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong");
    } finally {
      setLoading(false);
      setConfirmOpen(false);
    }
  }

  if (isLoadingSession) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        Loading...
      </div>
    );
  }

  return (
    <DashboardLayout
      title="Classify Intake"
      subtitle={`Create a service case from ${reportPublicUuid}`}
      onLogout={handleLogout}
    >
      <div className="mx-auto max-w-3xl space-y-6">
        <ConfirmModal
          open={confirmOpen}
          title="Classify as service case?"
          message="This will create a non-emergency service case from the intake report."
          confirmLabel="Classify"
          isLoading={loading}
          onConfirm={() => void classifyReport()}
          onCancel={() => setConfirmOpen(false)}
        />
        <Card>
          <CardHeader>
            <h1 className="text-2xl font-bold text-gray-900">
              Classify as Service Case
            </h1>
            <p className="text-sm text-gray-500">
              Create a non-emergency service case from this intake report.
            </p>
          </CardHeader>

          <CardContent>
            {error && (
              <div className="mb-4 rounded-md bg-red-50 p-3 text-sm text-red-700">
                {error}
              </div>
            )}

            <form
              onSubmit={(event) => {
                event.preventDefault();
                setConfirmOpen(true);
              }}
              className="space-y-4"
            >
              <div>
                <label className={labelClassName}>Title</label>
                <input
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  className={fieldClassName}
                  placeholder="Leave blank to use intake summary"
                />
              </div>

              <div>
                <label className={labelClassName}>Description</label>
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  className={fieldClassName}
                  rows={4}
                  placeholder="Optional service case notes"
                />
              </div>

              <div>
                <label className={labelClassName}>Priority</label>
                <select
                  value={priorityLevel}
                  onChange={(e) => setPriorityLevel(e.target.value)}
                  className={fieldClassName}
                >
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="urgent">Urgent</option>
                </select>
              </div>

              <div className="flex gap-3">
                <Button type="submit" disabled={loading}>
                  {loading ? "Classifying..." : "Classify as Service Case"}
                </Button>

                <Button
                  type="button"
                  variant="secondary"
                  onClick={() =>
                    router.push(
                      `/dashboard/dispatcher/intake-reports/${reportPublicUuid}`,
                    )
                  }
                >
                  Cancel
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
}
