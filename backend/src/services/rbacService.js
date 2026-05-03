import BackendError from "../lib/BackendError.js";
import { findUserByPublicUuid } from "../repositories/userRepo.js";
import {
  assignRoleToUser,
  findPermissionCodesByUserId,
  findRoleByCode,
  findRolesByUserId,
  hasRoleAssignment,
} from "../repositories/rbacRepo.js";

export const ROLE_CODES = {
  SYSTEM_ADMIN: "system_admin",
  CITIZEN: "citizen",
  DISPATCHER: "dispatcher",
};

export async function resolveAuthorizationContext(userId) {
  const roles = await findRolesByUserId(userId);
  const permissions = await findPermissionCodesByUserId(userId);

  return {
    roleCodes: roles.map((role) => role.role_code),
    permissions,
  };
}

export async function assignRoleToUserByPublicId({
  targetUserPublicId,
  roleCode,
  assignedByUserId,
}) {
  const targetUser = await findUserByPublicUuid(targetUserPublicId);

  if (!targetUser) {
    throw new BackendError(404, "USER_NOT_FOUND", "User not found");
  }

  const role = await findRoleByCode(roleCode);

  if (!role) {
    throw new BackendError(404, "ROLE_NOT_FOUND", "Role not found");
  }

  const alreadyAssigned = await hasRoleAssignment({
    userId: targetUser.id,
    roleCode: role.role_code,
  });

  if (alreadyAssigned) {
    throw new BackendError(409, "ROLE_ALREADY_ASSIGNED", "Role already assigned");
  }

  await assignRoleToUser({
    userId: targetUser.id,
    roleId: role.id,
    assignedByUserId,
  });

  return {
    userPublicId: targetUser.public_uuid,
    roleCode: role.role_code,
  };
}

