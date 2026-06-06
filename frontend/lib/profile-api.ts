import { apiPatch } from "@/lib/api";
import type { LoginResponse } from "@/types/auth";

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
