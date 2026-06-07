"use client";

import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import { ArrowLeft, Pencil, Save, XCircle } from "lucide-react";
import { SystemAdminShell } from "@/components/admin/SystemAdminShell";
import { AgencyOpsShell } from "@/components/agency/AgencyOpsShell";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { DispatcherOpsShell } from "@/components/dispatcher/DispatcherOpsShell";
import { Button } from "@/components/ui/Button";
import { Card, CardContent, CardHeader } from "@/components/ui/Card";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import { MessageBanner, PageLoading } from "@/components/ui/StatusState";
import { apiJson } from "@/lib/api";
import { getAgencyMe } from "@/lib/agency-api";
import { AGENCY_WORKSPACE_TITLE_FALLBACK } from "@/lib/agency-dashboard";
import { formatBangladeshTime } from "@/lib/datetime";
import {
  clearAuthSession,
  determineRole,
  getAuthSession,
} from "@/lib/auth-store";
import {
  ADMIN_DASHBOARD_SUBTITLE,
  ADMIN_DASHBOARD_TITLE,
} from "@/lib/admin-dashboard";
import {
  formatPhoneOrNotAdded,
  getSecondaryPhoneNumberFromUser,
  updateMyProfile,
  type UpdateMyProfilePayload,
} from "@/lib/profile-api";
import {
  DISPATCHER_DASHBOARD_SUBTITLE,
  DISPATCHER_DASHBOARD_TITLE,
} from "@/lib/dispatcher-dashboard";
import { useAuthGuard } from "@/lib/use-auth-guard";
import type { AgencyMeResponse } from "@/types/agency";
import type { AuthzInfo, LoginResponse } from "@/types/auth";

type MeResponse = {
  user: LoginResponse["user"];
  authz?: AuthzInfo;
};

type ProfileFormValues = {
  fullName: string;
  phoneNumber: string;
  secondaryPhoneNumber: string;
};

const PHONE_NUMBER_PATTERN = /^\d{11}$/;

function formatRoleLabel(value: string) {
  return value
    .replace(/_/g, " ")
    .split(" ")
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

function getRoleLabels(authz: AuthzInfo | null) {
  const roleCodes = authz?.roleCodes?.length
    ? authz.roleCodes
    : [getAuthSession().userRole];

  return roleCodes.map(formatRoleLabel);
}

function getDashboardHref(role: ReturnType<typeof determineRole>) {
  if (role === "dispatcher") return "/dashboard/dispatcher";
  if (role === "system_admin") return "/dashboard/admin";
  if (role === "agency_representative") return "/dashboard/agency";
  return "/dashboard/citizen";
}

function getBackLabel(role: ReturnType<typeof determineRole>) {
  if (role === "dispatcher" || role === "system_admin") {
    return "Back to Command Center";
  }

  return "Back to Dashboard";
}

function formatDateTime(value?: string | null) {
  if (!value) return null;
  return formatBangladeshTime(value);
}

function formatBoolean(value?: boolean | null) {
  if (value == null) return null;
  return value ? "Yes" : "No";
}

function getProfileFormValues(user: LoginResponse["user"]): ProfileFormValues {
  return {
    fullName: user.full_name ?? "",
    phoneNumber: user.phone_number ?? "",
    secondaryPhoneNumber: getSecondaryPhoneNumberFromUser(user),
  };
}

function buildProfileUpdatePayload(
  user: LoginResponse["user"],
  formValues: ProfileFormValues,
) {
  const original = getProfileFormValues(user);
  const payload: UpdateMyProfilePayload = {};
  const fullName = formValues.fullName.trim();
  const phoneNumber = formValues.phoneNumber.trim();
  const secondaryPhoneNumber = formValues.secondaryPhoneNumber.trim();

  if (fullName !== original.fullName) {
    payload.fullName = fullName;
  }

  if (phoneNumber !== original.phoneNumber) {
    payload.phoneNumber = phoneNumber;
  }

  if (secondaryPhoneNumber !== original.secondaryPhoneNumber) {
    payload.secondaryPhoneNumber = secondaryPhoneNumber || null;
  }

  return payload;
}

function validateProfileUpdate(
  user: LoginResponse["user"],
  payload: UpdateMyProfilePayload,
) {
  if (payload.fullName !== undefined && !payload.fullName) {
    return "Full name is required.";
  }
  if (payload.fullName && payload.fullName.length > 150) {
    return "Full name must be at most 150 characters.";
  }
  if (
    payload.phoneNumber !== undefined &&
    !PHONE_NUMBER_PATTERN.test(payload.phoneNumber)
  ) {
    return "Primary phone number must be exactly 11 digits.";
  }
  if (
    typeof payload.secondaryPhoneNumber === "string" &&
    !PHONE_NUMBER_PATTERN.test(payload.secondaryPhoneNumber)
  ) {
    return "Secondary phone must be exactly 11 digits.";
  }

  const finalPhoneNumber = payload.phoneNumber ?? user.phone_number;
  const finalSecondaryPhoneNumber =
    payload.secondaryPhoneNumber !== undefined
      ? payload.secondaryPhoneNumber
      : getSecondaryPhoneNumberFromUser(user) || null;

  if (
    finalPhoneNumber &&
    finalSecondaryPhoneNumber &&
    finalSecondaryPhoneNumber === finalPhoneNumber
  ) {
    return "Secondary phone number must differ from the primary phone number.";
  }

  return "";
}

function DetailItem({
  label,
  value,
  children,
}: {
  label: string;
  value?: string | null;
  children?: ReactNode;
}) {
  if (!children && !value) return null;

  return (
    <div className="min-w-0 rounded-xl border border-[#002D62]/10 bg-white px-4 py-3">
      <dt className="text-xs font-semibold uppercase text-[#42547A]">{label}</dt>
      <dd className="mt-1 break-words text-sm font-semibold text-slate-900">
        {children ?? value}
      </dd>
    </div>
  );
}

function ReadOnlyField({
  label,
  value,
}: {
  label: string;
  value?: string | null;
}) {
  if (!value) return null;

  return (
    <div className="min-w-0 rounded-xl border border-[#002D62]/10 bg-white px-4 py-3">
      <p className="text-xs font-semibold uppercase text-[#42547A]">{label}</p>
      <p className="mt-1 break-words text-sm font-semibold text-slate-900">
        {value}
      </p>
    </div>
  );
}

function EditableField({
  id,
  label,
  value,
  onChange,
  disabled,
  autoComplete,
  inputMode,
  maxLength,
  helperText,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
  autoComplete?: string;
  inputMode?: "text" | "tel";
  maxLength?: number;
  helperText?: string;
}) {
  return (
    <div className="min-w-0">
      <label
        htmlFor={id}
        className="text-xs font-semibold uppercase text-[#42547A]"
      >
        {label}
      </label>
      <input
        id={id}
        type="text"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        onKeyDown={(event) => {
          if (event.key !== "Enter") return;
          event.preventDefault();
          event.currentTarget.form?.requestSubmit();
        }}
        disabled={disabled}
        autoComplete={autoComplete}
        inputMode={inputMode}
        maxLength={maxLength}
        className="mt-1 w-full rounded-xl border border-[#002D62]/20 bg-white px-3 py-2.5 text-sm font-semibold text-slate-900 shadow-sm transition-colors placeholder:text-slate-400 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/25 disabled:cursor-not-allowed disabled:bg-slate-100 disabled:text-slate-500"
      />
      {helperText ? (
        <p className="mt-1 text-xs leading-5 text-slate-500">{helperText}</p>
      ) : null}
    </div>
  );
}

export default function ProfilePage() {
  const router = useRouter();
  const isChecking = useAuthGuard();
  const [user, setUser] = useState<LoginResponse["user"] | null>(null);
  const [authz, setAuthz] = useState<AuthzInfo | null>(null);
  const [agencyMe, setAgencyMe] = useState<AgencyMeResponse | null>(null);
  const [error, setError] = useState("");
  const [formValues, setFormValues] = useState<ProfileFormValues>({
    fullName: "",
    phoneNumber: "",
    secondaryPhoneNumber: "",
  });
  const [isEditing, setIsEditing] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [saveError, setSaveError] = useState("");
  const [successMessage, setSuccessMessage] = useState("");

  useEffect(() => {
    if (isChecking) return;

    async function loadProfile() {
      try {
        const data = await apiJson<MeResponse>("/users/me");
        setUser(data.user);
        setFormValues(getProfileFormValues(data.user));
        setAuthz(data.authz ?? null);
        sessionStorage.setItem("loggedInUser", JSON.stringify(data.user));

        if (data.authz?.roleCodes?.includes("agency_representative")) {
          const agencyData = await getAgencyMe().catch(() => null);
          setAgencyMe(agencyData);
        } else {
          setAgencyMe(null);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : "Could not load profile.");
      }
    }

    void loadProfile();
  }, [isChecking]);

  const updateFormValue = (field: keyof ProfileFormValues, value: string) => {
    setFormValues((current) => ({ ...current, [field]: value }));
    setSaveError("");
    setSuccessMessage("");
  };

  const handleStartEdit = () => {
    if (!user) return;
    setFormValues(getProfileFormValues(user));
    setIsEditing(true);
    setSaveError("");
    setSuccessMessage("");
  };

  const handleCancelEdit = () => {
    if (user) {
      setFormValues(getProfileFormValues(user));
    }
    setIsEditing(false);
    setSaveError("");
    setSuccessMessage("");
  };

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!user || isSaving) return;

    const payload = buildProfileUpdatePayload(user, formValues);
    const validationMessage = validateProfileUpdate(user, payload);
    if (validationMessage) {
      setSaveError(validationMessage);
      setSuccessMessage("");
      return;
    }

    if (Object.keys(payload).length === 0) {
      setIsEditing(false);
      setSaveError("");
      setSuccessMessage("Profile is already up to date.");
      return;
    }

    setIsSaving(true);
    setSaveError("");
    setSuccessMessage("");

    try {
      const data = await updateMyProfile(payload);
      setUser(data.user);
      setFormValues(getProfileFormValues(data.user));
      sessionStorage.setItem("loggedInUser", JSON.stringify(data.user));
      setIsEditing(false);
      setSuccessMessage(data.message || "Profile updated successfully.");
    } catch (err) {
      setSaveError(
        err instanceof Error
          ? err.message
          : "Could not save your profile. Please try again.",
      );
    } finally {
      setIsSaving(false);
    }
  };

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  if (isChecking || (!user && !error)) {
    return <PageLoading label="Loading profile" />;
  }

  const resolvedRole = authz?.roleCodes?.length
    ? determineRole(authz.roleCodes)
    : getAuthSession().userRole;
  const roleLabels = getRoleLabels(authz);
  const roleLabel = roleLabels.join(", ");
  const agencyName = agencyMe?.agency.name ?? null;
  const dashboardHref = getDashboardHref(resolvedRole);

  const pageBody = (
    <div className="mx-auto w-full max-w-5xl space-y-5">
      {resolvedRole !== "citizen" ? (
        <div className="flex justify-start">
          <Button
            type="button"
            variant="secondary"
            size="sm"
            className="h-9 !rounded-full border border-[#002D62]/15 bg-white px-3 text-[#002D62] shadow-sm shadow-[#002D62]/5"
            onClick={() => router.push(dashboardHref)}
          >
            <ArrowLeft className="h-4 w-4" aria-hidden />
            {getBackLabel(resolvedRole)}
          </Button>
        </div>
      ) : null}

      {error && <ErrorAlert message={error} />}

      {!user && !error ? (
        <Card className="!rounded-2xl !border-[#002D62]/10 !bg-white shadow-sm shadow-[#002D62]/5">
          <CardContent>
            <LoadingSkeleton lines={5} />
          </CardContent>
        </Card>
      ) : user ? (
        <Card className="!rounded-2xl !border-[#002D62]/10 !bg-white shadow-sm shadow-[#002D62]/5">
          <form onSubmit={handleSubmit}>
            <CardHeader className="flex flex-col gap-3 !px-5 !py-4 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <h2 className="text-lg font-semibold text-[#002D62]">
                  Full Details
                </h2>
                <p className="mt-1 text-sm text-slate-600">
                  Personal contact details and read-only account information.
                </p>
              </div>
              <div className="flex flex-col gap-2 sm:flex-row sm:justify-end">
                {isEditing ? (
                  <>
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={handleCancelEdit}
                      disabled={isSaving}
                    >
                      <XCircle className="h-4 w-4" aria-hidden />
                      Cancel
                    </Button>
                    <Button type="submit" size="sm" isLoading={isSaving}>
                      {isSaving ? null : (
                        <Save className="h-4 w-4" aria-hidden />
                      )}
                      {isSaving ? "Saving" : "Save"}
                    </Button>
                  </>
                ) : (
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={handleStartEdit}
                  >
                    <Pencil className="h-4 w-4" aria-hidden />
                    Edit
                  </Button>
                )}
              </div>
            </CardHeader>
            <CardContent className="space-y-5 !px-5 !py-5">
              {successMessage ? (
                <MessageBanner tone="success" title="Profile saved">
                  {successMessage}
                </MessageBanner>
              ) : null}

              {saveError ? <ErrorAlert message={saveError} /> : null}

              <section className="space-y-3" aria-labelledby="profile-identity">
                <h3
                  id="profile-identity"
                  className="text-sm font-semibold text-[#002D62]"
                >
                  Identity
                </h3>
                {isEditing ? (
                  <div className="grid gap-4 rounded-xl border border-[#002D62]/10 bg-[#F8FBFF] p-4 sm:grid-cols-2">
                    <ReadOnlyField label="User ID" value={user.id} />
                    <ReadOnlyField label="Email" value={user.email} />
                    <EditableField
                      id="profile-full-name"
                      label="Full Name"
                      value={formValues.fullName}
                      onChange={(value) => updateFormValue("fullName", value)}
                      disabled={isSaving}
                      autoComplete="name"
                      maxLength={150}
                    />
                    <EditableField
                      id="profile-phone-number"
                      label="Phone Number"
                      value={formValues.phoneNumber}
                      onChange={(value) =>
                        updateFormValue("phoneNumber", value)
                      }
                      disabled={isSaving}
                      autoComplete="tel"
                      inputMode="tel"
                      maxLength={11}
                      helperText="Use 11 digits."
                    />
                    <EditableField
                      id="profile-secondary-phone-number"
                      label="Secondary Phone"
                      value={formValues.secondaryPhoneNumber}
                      onChange={(value) =>
                        updateFormValue("secondaryPhoneNumber", value)
                      }
                      disabled={isSaving}
                      autoComplete="tel"
                      inputMode="tel"
                      maxLength={11}
                      helperText="Optional. Leave blank to clear it."
                    />
                  </div>
                ) : (
                  <dl className="grid gap-3 sm:grid-cols-2">
                    <DetailItem label="User ID" value={user.id} />
                    <DetailItem label="Full Name" value={user.full_name} />
                    <DetailItem label="Email" value={user.email} />
                    <DetailItem
                      label="Phone Number"
                      value={user.phone_number}
                    />
                    <DetailItem
                      label="SECONDARY PHONE"
                      value={formatPhoneOrNotAdded(
                        getSecondaryPhoneNumberFromUser(user),
                      )}
                    />
                  </dl>
                )}
              </section>

            <section className="space-y-3" aria-labelledby="profile-access">
              <h3
                id="profile-access"
                className="text-sm font-semibold text-[#002D62]"
              >
                Account and Access
              </h3>
              <dl className="grid gap-3 sm:grid-cols-2">
                <DetailItem label="Role" value={roleLabel} />
                {user.account_status ? (
                  <DetailItem label="Account Status">
                    <Badge tone={user.account_status}>
                      {formatBadgeLabel(user.account_status)}
                    </Badge>
                  </DetailItem>
                ) : null}
              </dl>
            </section>

            <section className="space-y-3" aria-labelledby="profile-timeline">
              <h3
                id="profile-timeline"
                className="text-sm font-semibold text-[#002D62]"
              >
                Account Timeline
              </h3>
              <dl className="grid gap-3 sm:grid-cols-2">
                <DetailItem
                  label="Created"
                  value={formatDateTime(user.created_at)}
                />
                <DetailItem
                  label="Last Updated"
                  value={formatDateTime(user.updated_at)}
                />
              </dl>
            </section>

            {agencyMe ? (
              <section className="space-y-3" aria-labelledby="profile-agency">
                <h3
                  id="profile-agency"
                  className="text-sm font-semibold text-[#002D62]"
                >
                  Agency Representation
                </h3>
                <dl className="grid gap-3 sm:grid-cols-2">
                  <DetailItem label="Agency" value={agencyMe.agency.name} />
                  <DetailItem
                    label="Agency Code"
                    value={agencyMe.agency.agency_code}
                  />
                  <DetailItem
                    label="Agency Type"
                    value={formatRoleLabel(agencyMe.agency.agency_type_code)}
                  />
                  <DetailItem
                    label="Agency Active"
                    value={formatBoolean(agencyMe.agency.is_active)}
                  />
                  <DetailItem
                    label="Membership Role"
                    value={formatRoleLabel(agencyMe.membership.membership_role)}
                  />
                  <DetailItem label="Membership Status">
                    <Badge tone={agencyMe.membership.membership_status}>
                      {formatBadgeLabel(agencyMe.membership.membership_status)}
                    </Badge>
                  </DetailItem>
                  <DetailItem
                    label="Joined"
                    value={formatDateTime(agencyMe.membership.joined_at)}
                  />
                </dl>
              </section>
            ) : null}
            </CardContent>
          </form>
        </Card>
      ) : null}
    </div>
  );

  if (resolvedRole === "dispatcher") {
    return (
      <DashboardLayout
        title={DISPATCHER_DASHBOARD_TITLE}
        subtitle={DISPATCHER_DASHBOARD_SUBTITLE}
        onLogout={handleLogout}
        hideSidebar
        showHealthBadge={false}
      >
        <DispatcherOpsShell>{pageBody}</DispatcherOpsShell>
      </DashboardLayout>
    );
  }

  if (resolvedRole === "system_admin") {
    return (
      <DashboardLayout
        title={ADMIN_DASHBOARD_TITLE}
        subtitle={ADMIN_DASHBOARD_SUBTITLE}
        onLogout={handleLogout}
        hideSidebar
        showHealthBadge={false}
      >
        <SystemAdminShell>{pageBody}</SystemAdminShell>
      </DashboardLayout>
    );
  }

  if (resolvedRole === "agency_representative") {
    return (
      <DashboardLayout
        title={agencyName ? `${agencyName} Workspace` : AGENCY_WORKSPACE_TITLE_FALLBACK}
        subtitle="Agency response operations"
        onLogout={handleLogout}
        hideSidebar
        showHealthBadge={false}
      >
        <AgencyOpsShell>{pageBody}</AgencyOpsShell>
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout
      title="Profile"
      subtitle="Account details"
      onLogout={handleLogout}
      showHealthBadge={false}
    >
      {pageBody}
    </DashboardLayout>
  );
}
