export type AdminAgencyListItem = {
  public_uuid: string;
  agency_code: string;
  name: string;
  agency_type_code: string;
  description: string | null;
  is_active: boolean;
  created_at: string;
  updated_at: string;
};

export type AdminAgenciesListResponse = {
  total: number;
  limit: number;
  offset: number;
  agencies: AdminAgencyListItem[];
};

export type AdminAgencyRepresentative = {
  public_uuid: string;
  user_public_uuid: string;
  full_name: string | null;
  email: string | null;
  membership_role: string;
  membership_status: string;
  joined_at: string;
  left_at: string | null;
};

export type AdminAgencyUnitSummary = {
  public_uuid: string;
  unit_code: string;
  unit_name: string;
  unit_type_code: string;
  status_code: string;
  is_active: boolean;
};

export type AdminAgencyContact = {
  id: number;
  contact_type: string;
  contact_value: string;
  label: string | null;
  is_primary: boolean;
  is_active: boolean;
};

export type AdminAgencyDetailResponse = {
  agency: AdminAgencyListItem;
  representatives: AdminAgencyRepresentative[];
  units: AdminAgencyUnitSummary[];
  contacts: AdminAgencyContact[];
};

export type AdminAgencyRepresentativesResponse = {
  agency_public_uuid: string;
  representatives: AdminAgencyRepresentative[];
};

export type AdminAgencyHeadOfficeLocation = {
  latitude: number;
  longitude: number;
  source: "manual_entry";
  place_name?: string;
  address_text?: string;
};

export type AdminOnboardAgencyFields = {
  agency_code: string;
  name: string;
  agency_type_code: string;
  description?: string;
  head_office_location?: AdminAgencyHeadOfficeLocation;
};

export type AdminOnboardAgencyOnlyPayload = {
  agency: AdminOnboardAgencyFields;
};

export type AdminOnboardAgencyWithRepresentativePayload = {
  user_public_uuid: string;
  agency: AdminOnboardAgencyFields;
};

export type AdminOnboardAgencyExistingOnlyPayload = {
  agency_public_uuid: string;
};

export type AdminOnboardAgencyExistingWithRepresentativePayload = {
  user_public_uuid: string;
  agency_public_uuid: string;
};

export type AdminOnboardAgencyPayload =
  | AdminOnboardAgencyOnlyPayload
  | AdminOnboardAgencyWithRepresentativePayload
  | AdminOnboardAgencyExistingOnlyPayload
  | AdminOnboardAgencyExistingWithRepresentativePayload;

export type AdminOnboardAgencyResponse = {
  message: string;
  agency: AdminAgencyListItem;
  membership_public_uuid?: string;
  user_public_uuid?: string;
};

export type AdminPatchAgencyPayload = {
  agency_code?: string;
  name?: string;
  description?: string;
};

export type AdminPatchAgencyResponse = {
  agency: AdminAgencyListItem;
};

export type AdminActivateAgencyResponse = AdminAgencyDetailResponse & {
  message?: string;
};

export type AdminDeactivateAgencyResponse = AdminAgencyDetailResponse & {
  message?: string;
};

export type AdminAddRepresentativeResponse = {
  message: string;
  representative: AdminAgencyRepresentative;
};

export type AdminDeactivateMembershipResponse = {
  message: string;
  membership: {
    public_uuid: string;
    membership_status: string;
    left_at: string | null;
  };
};

export type AssignUserRoleResponse = {
  message?: string;
  userId?: string;
  roleCode?: string;
};
