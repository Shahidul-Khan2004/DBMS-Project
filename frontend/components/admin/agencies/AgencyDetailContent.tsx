"use client";

import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { formatAdminAgencyTypeLabel } from "@/lib/admin-agency-types";
import { formatBangladeshTime } from "@/lib/datetime";
import type {
  AdminAgencyContact,
  AdminAgencyDetailResponse,
  AdminAgencyRepresentative,
  AdminAgencyUnitSummary,
} from "@/types/admin-agency";

type AgencyDetailContentProps = {
  detail: AdminAgencyDetailResponse;
  isMutating: boolean;
  onEdit: () => void;
  onActivate: () => void;
  onDeactivate: () => void;
  onAddRepresentative: () => void;
  onDeactivateMembership: (membershipPublicUuid: string) => void;
};

function RepresentativesTable({
  representatives,
  isMutating,
  onDeactivateMembership,
}: {
  representatives: AdminAgencyRepresentative[];
  isMutating: boolean;
  onDeactivateMembership: (membershipPublicUuid: string) => void;
}) {
  if (representatives.length === 0) {
    return <p className="text-sm text-slate-600">No representatives on record.</p>;
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[32rem] text-left text-sm">
        <thead>
          <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-500">
            <th className="py-2 pr-3 font-medium">Name</th>
            <th className="py-2 pr-3 font-medium">Email</th>
            <th className="py-2 pr-3 font-medium">Status</th>
            <th className="py-2 font-medium">Actions</th>
          </tr>
        </thead>
        <tbody>
          {representatives.map((rep) => (
            <tr key={rep.public_uuid} className="border-b border-slate-100">
              <td className="py-2.5 pr-3 text-slate-900">
                {rep.full_name ?? "—"}
              </td>
              <td className="py-2.5 pr-3 text-slate-700">{rep.email ?? "—"}</td>
              <td className="py-2.5 pr-3">
                <Badge
                  size="compact"
                  tone={rep.membership_status === "active" ? "success" : "neutral"}
                >
                  {formatBadgeLabel(rep.membership_status)}
                </Badge>
              </td>
              <td className="py-2.5">
                {rep.membership_status === "active" ? (
                  <Button
                    type="button"
                    variant="secondary"
                    size="sm"
                    disabled={isMutating}
                    onClick={() => onDeactivateMembership(rep.public_uuid)}
                  >
                    Deactivate
                  </Button>
                ) : (
                  <span className="text-xs text-slate-500">—</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function UnitsList({ units }: { units: AdminAgencyUnitSummary[] }) {
  if (units.length === 0) {
    return <p className="text-sm text-slate-600">No units returned for this agency.</p>;
  }

  return (
    <ul className="space-y-2">
      {units.map((unit) => (
        <li
          key={unit.public_uuid}
          className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-100 px-3 py-2 text-sm"
        >
          <span className="font-medium text-slate-900">
            {unit.unit_name}{" "}
            <span className="font-normal text-slate-500">({unit.unit_code})</span>
          </span>
          <div className="flex gap-1.5">
            <Badge size="compact" tone="neutral">
              {formatBadgeLabel(unit.unit_type_code)}
            </Badge>
            <Badge size="compact" tone="neutral">
              {formatBadgeLabel(unit.status_code)}
            </Badge>
          </div>
        </li>
      ))}
    </ul>
  );
}

function ContactsList({ contacts }: { contacts: AdminAgencyContact[] }) {
  if (contacts.length === 0) {
    return <p className="text-sm text-slate-600">No contacts on record.</p>;
  }

  return (
    <ul className="space-y-2">
      {contacts.map((contact) => (
        <li
          key={contact.id}
          className="rounded-lg border border-slate-100 px-3 py-2 text-sm"
        >
          <p className="font-medium text-slate-900">
            {contact.label ?? formatBadgeLabel(contact.contact_type)}
          </p>
          <p className="text-slate-700">{contact.contact_value}</p>
        </li>
      ))}
    </ul>
  );
}

export function AgencyDetailContent({
  detail,
  isMutating,
  onEdit,
  onActivate,
  onDeactivate,
  onAddRepresentative,
  onDeactivateMembership,
}: AgencyDetailContentProps) {
  const { agency } = detail;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap gap-2">
        <Button
          type="button"
          variant="secondary"
          size="sm"
          onClick={onEdit}
          disabled={isMutating}
        >
          Edit agency
        </Button>
        {agency.is_active ? (
          <Button
            type="button"
            variant="secondary"
            size="sm"
            onClick={onDeactivate}
            disabled={isMutating}
          >
            Deactivate agency
          </Button>
        ) : (
          <Button
            type="button"
            size="sm"
            onClick={onActivate}
            disabled={isMutating}
          >
            Activate agency
          </Button>
        )}
        <Button
          type="button"
          size="sm"
          onClick={onAddRepresentative}
          disabled={isMutating}
        >
          Add representative
        </Button>
      </div>

      <section>
        <h3 className="text-sm font-semibold text-slate-900">Agency overview</h3>
        <dl className="mt-3 grid gap-3 text-sm sm:grid-cols-2">
          <div>
            <dt className="text-slate-500">Name</dt>
            <dd className="mt-0.5 font-medium text-slate-900">{agency.name}</dd>
          </div>
          <div>
            <dt className="text-slate-500">Agency code</dt>
            <dd className="mt-0.5 font-medium text-slate-900">
              {agency.agency_code}
            </dd>
          </div>
          <div>
            <dt className="text-slate-500">Type</dt>
            <dd className="mt-0.5">
              <Badge size="compact" tone="neutral">
                {formatBadgeLabel(
                  formatAdminAgencyTypeLabel(agency.agency_type_code),
                )}
              </Badge>
            </dd>
          </div>
          <div>
            <dt className="text-slate-500">Status</dt>
            <dd className="mt-0.5">
              <Badge
                size="compact"
                tone={agency.is_active ? "success" : "neutral"}
              >
                {agency.is_active ? "Active" : "Inactive"}
              </Badge>
            </dd>
          </div>
          <div className="sm:col-span-2">
            <dt className="text-slate-500">Description</dt>
            <dd className="mt-0.5 text-slate-900">
              {agency.description?.trim() || "—"}
            </dd>
          </div>
          <div>
            <dt className="text-slate-500">Created</dt>
            <dd className="mt-0.5 text-slate-900">
              {formatBangladeshTime(agency.created_at)}
            </dd>
          </div>
          <div>
            <dt className="text-slate-500">Updated</dt>
            <dd className="mt-0.5 text-slate-900">
              {formatBangladeshTime(agency.updated_at)}
            </dd>
          </div>
        </dl>
      </section>

      <section>
        <h3 className="text-sm font-semibold text-slate-900">Representatives</h3>
        <div className="mt-3">
          <RepresentativesTable
            representatives={detail.representatives}
            isMutating={isMutating}
            onDeactivateMembership={onDeactivateMembership}
          />
        </div>
      </section>

      <section>
        <h3 className="text-sm font-semibold text-slate-900">Units</h3>
        <p className="mt-0.5 text-xs text-slate-500">Read-only in admin v1</p>
        <div className="mt-3">
          <UnitsList units={detail.units} />
        </div>
      </section>

      <section>
        <h3 className="text-sm font-semibold text-slate-900">Contacts</h3>
        <p className="mt-0.5 text-xs text-slate-500">Read-only</p>
        <div className="mt-3">
          <ContactsList contacts={detail.contacts} />
        </div>
      </section>
    </div>
  );
}
