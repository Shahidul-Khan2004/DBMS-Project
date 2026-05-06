"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardContent, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { clearAuthSession } from "@/lib/auth-store";
import type {
  CreateIntakeReportRequest,
  CreateIntakeReportResponse,
} from "@/types/intake";

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8080";

const CATEGORY_OPTIONS = [
  { value: "medical", label: "Medical" },
  { value: "crime_public_safety", label: "Crime / Public Safety" },
  { value: "fire", label: "Fire" },
  { value: "natural_disaster", label: "Natural Disaster" },
  { value: "infrastructure_emergency", label: "Infrastructure Emergency" },
  { value: "relief_request", label: "Relief Request" },
  { value: "blood_request", label: "Blood Request" },
] as const;

export default function CitizenNewReportPage() {
  const router = useRouter();
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [message, setMessage] = useState<{
    type: "success" | "error";
    text: string;
  } | null>(null);

  const [form, setForm] = useState<CreateIntakeReportRequest>({
    channelCode: "web_portal",
    categoryCode: "",
    summary: "",
    description: "",
    urgencyType: "unknown",
    location: "",
  });

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  const handleChange = (
    e: React.ChangeEvent<
      HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement
    >,
  ) => {
    const { name, value } = e.target;
    setForm((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!form.summary.trim()) {
      setMessage({ type: "error", text: "Summary is required." });
      return;
    }

    if (!form.categoryCode.trim()) {
      setMessage({ type: "error", text: "Please select a category." });
      return;
    }

    const accessToken = localStorage.getItem("accessToken");
    if (!accessToken) {
      router.push("/auth/login");
      return;
    }

    setIsSubmitting(true);
    setMessage(null);

    try {
      const payload: CreateIntakeReportRequest = {
        channelCode: form.channelCode,
        categoryCode: form.categoryCode,
        summary: form.summary.trim(),
        description: form.description?.trim() || undefined,
        urgencyType: form.urgencyType,
        location: form.location?.trim() || undefined,
      };

      const response = await fetch(`${API_BASE}/intake/reports`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${accessToken}`,
        },
        body: JSON.stringify(payload),
      });

      const data = (await response.json().catch(() => ({}))) as
        | CreateIntakeReportResponse
        | { error?: { message?: string }; message?: string };

      if (!response.ok) {
        const errMsg =
          ("error" in data && data.error?.message) ||
          data.message ||
          "Failed to submit report.";
        setMessage({ type: "error", text: errMsg });
        return;
      }

      setMessage({
        type: "success",
        text: `Report submitted successfully. Reference: ${(data as CreateIntakeReportResponse).intake.report_code}`,
      });

      setForm({
        channelCode: "web_portal",
        categoryCode: "",
        summary: "",
        description: "",
        urgencyType: "unknown",
        location: "",
      });
    } catch {
      setMessage({
        type: "error",
        text: "Unexpected error while submitting report.",
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <DashboardLayout
      title="Report New Incident"
      subtitle="Create an intake report for the NIERS team"
      onLogout={handleLogout}
    >
      <div className="mx-auto max-w-2xl">
        <Card className="shadow-md">
          <CardHeader>
            <h2 className="text-lg font-semibold text-gray-900">
              Incident Report Form
            </h2>
          </CardHeader>
          <CardContent>
            <form className="space-y-4" onSubmit={handleSubmit}>
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

              <div className="grid gap-4 sm:grid-cols-2">
                <div>
                  <label className="mb-2 block text-sm font-medium text-gray-700">
                    Channel
                  </label>
                  <select
                    name="channelCode"
                    value={form.channelCode}
                    onChange={handleChange}
                    className="block h-[42px] w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="web_portal">Web Portal</option>
                  </select>
                </div>

                <div>
                  <label className="mb-2 block text-sm font-medium text-gray-700">
                    Category
                  </label>
                  <select
                    name="categoryCode"
                    value={form.categoryCode}
                    onChange={handleChange}
                    required
                    className="block h-[42px] w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="" disabled>
                      Select category
                    </option>
                    {CATEGORY_OPTIONS.map((option) => (
                      <option key={option.value} value={option.value}>
                        {option.label}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <Input
                name="summary"
                label="Summary"
                value={form.summary}
                onChange={handleChange}
                placeholder="Briefly describe what happened"
                required
              />

              <div>
                <label className="mb-2 block text-sm font-medium text-gray-700">
                  Description
                </label>
                <textarea
                  name="description"
                  value={form.description ?? ""}
                  onChange={handleChange}
                  rows={4}
                  placeholder="Optional details"
                  className="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm text-gray-900 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>

              <div className="grid gap-4 sm:grid-cols-2">
                <div>
                  <label className="mb-2 block text-sm font-medium text-gray-700">
                    Urgency
                  </label>
                  <select
                    name="urgencyType"
                    value={form.urgencyType}
                    onChange={handleChange}
                    className="block h-[42px] w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="unknown">Unknown</option>
                    <option value="non_emergency">Non-Emergency</option>
                  </select>
                </div>

                <Input
                  name="location"
                  label="Location"
                  value={form.location ?? ""}
                  onChange={handleChange}
                  placeholder="Address or location details"
                />
              </div>

              <div className="flex flex-col gap-3 sm:flex-row">
                <Button
                  type="submit"
                  isLoading={isSubmitting}
                  className="sm:w-auto"
                >
                  Submit Report
                </Button>
                <Button
                  type="button"
                  variant="secondary"
                  onClick={() => router.push("/dashboard/citizen/reports")}
                  className="sm:w-auto"
                >
                  View My Reports
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
}
