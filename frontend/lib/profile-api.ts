import { apiPatch } from "@/lib/api";
import type { LoginResponse } from "@/types/auth";

type UserWithSecondaryPhone = LoginResponse["user"] & {
  secondaryPhoneNumber?: string | null;
};

export function getSecondaryPhoneNumberFromUser(
  user: UserWithSecondaryPhone,
): string {
  const value = user.secondary_phone_number ?? user.secondaryPhoneNumber;
  if (value == null) return "";
  return String(value).trim();
}

export function formatPhoneOrNotAdded(value?: string | null): string {
  const trimmed = value?.trim();
  return trimmed ? trimmed : "Not added";
}

export type UpdateMyProfilePayload = {
  fullName?: string;
  phoneNumber?: string;
  secondaryPhoneNumber?: string | null;
};

export type UpdateMyProfileResponse = {
  message: string;
  user: LoginResponse["user"];
};

export function updateMyProfile(payload: UpdateMyProfilePayload) {
  return apiPatch<UpdateMyProfileResponse, UpdateMyProfilePayload>(
    "/users/me/profile",
    payload,
  );
}
