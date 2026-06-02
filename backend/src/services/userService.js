import BackendError from "../lib/BackendError.js";
import { findUserById, updateUserProfile } from "../repositories/userRepo.js";
import { toPublicUser } from "./authService.js";

/**
 * Update the logged-in user's own profile fields.
 * @param {number} actorUserId  - internal DB id from auth middleware
 * @param {{ fullName?: string, phoneNumber?: string, secondaryPhoneNumber?: string|null }} fields
 */
export async function updateMyProfile(actorUserId, { fullName, phoneNumber, secondaryPhoneNumber }) {
  // Load current profile to resolve final primary phone for cross-field validation
  const current = await findUserById(actorUserId);
  if (!current) {
    throw new BackendError(404, "USER_NOT_FOUND", "User not found");
  }

  // Resolve final values — request wins, otherwise keep current DB value
  const finalPhoneNumber =
    phoneNumber !== undefined ? phoneNumber : current.phone_number;
  const finalSecondaryPhoneNumber =
    secondaryPhoneNumber !== undefined ? secondaryPhoneNumber : current.secondary_phone_number;

  // Cross-field: secondary phone must differ from final primary phone
  if (finalSecondaryPhoneNumber !== null && finalSecondaryPhoneNumber === finalPhoneNumber) {
    throw new BackendError(
      422,
      "DUPLICATE_PHONE",
      "Secondary phone number must differ from the primary phone number",
    );
  }

  const updated = await updateUserProfile(actorUserId, {
    fullName,
    phoneNumber,
    secondaryPhoneNumber,
  });

  if (!updated) {
    throw new BackendError(
      500,
      "PROFILE_UPDATE_FAILED",
      "User profile row not found; profile may be missing",
    );
  }

  return toPublicUser(updated);
}