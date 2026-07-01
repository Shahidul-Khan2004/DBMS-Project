import { randomUUID } from "node:crypto";
import bcrypt from "bcrypt";
import BackendError from "../lib/BackendError.js";
import {
  findUserByEmail,
  findUserByPublicUuid,
  createUser,
} from "../repositories/userRepo.js";
import { assignRoleToUser, findRoleByCode } from "../repositories/rbacRepo.js";
import { resolveAuthorizationContext, ROLE_CODES } from "./rbacService.js";
import {
  signAccessToken,
  signRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
} from "./tokenService.js";
import { resolveUserAccountForAuth } from "./userAccountStatusService.js";
import { assertUserCanLogin } from "../lib/accountStatusLoginErrors.js";

export function toPublicUser(user) {
  return {
    id: user.public_uuid,
    email: user.email,
    full_name: user.full_name,
    phone_number: user.phone_number,
    secondary_phone_number: user.secondary_phone_number ?? null,
    account_status: user.account_status,
    is_active: user.account_status === "active",
    account_status_reason: user.account_status_reason ?? null,
    account_status_expires_at: user.account_status_expires_at ?? null,
    created_at: user.created_at,
    updated_at: user.updated_at,
  };
}

export async function registerUser({ email, fullName, phoneNumber, password }) {
  const existingUser = await findUserByEmail(email);

  if (existingUser) {
    throw new BackendError(409, "EXISTING_EMAIL", "Email already in use");
  }

  const publicUuid = randomUUID();
  const passwordHash = await bcrypt.hash(password, 10);

  try {
    await createUser({
      publicUuid,
      email,
      fullName,
      phoneNumber,
      passwordHash,
    });
  } catch (error) {
    const isDuplicateEmail =
      (error.code === "ER_DUP_ENTRY" &&
        error.message.includes("uq_users_email")) ||
      (error.code === "23505" &&
        (error.constraint === "uq_users_email" ||
          error.message?.includes("uq_users_email")));

    if (isDuplicateEmail) {
      throw new BackendError(409, "EXISTING_EMAIL", "Email already in use");
    }

    throw error;
  }

  const user = await findUserByPublicUuid(publicUuid);
  const defaultRole = await findRoleByCode(ROLE_CODES.CITIZEN);

  if (defaultRole) {
    try {
      await assignRoleToUser({
        userId: user.id,
        roleId: defaultRole.id,
        assignedByUserId: null,
      });
    } catch (error) {
      if (error.code !== "ER_DUP_ENTRY" && error.code !== "23505") {
        throw error;
      }
    }
  }

  const authz = await resolveAuthorizationContext(user.id);

  return {
    user: toPublicUser(user),
    accessToken: signAccessToken(user),
    refreshToken: signRefreshToken(user),
    authz,
  };
}

export async function loginUser({ email, password }) {
  const user = await findUserByEmail(email);

  if (!user) {
    throw new BackendError(
      401,
      "INVALID_CREDENTIALS",
      "Invalid email or password",
    );
  }

  const isPasswordValid = await bcrypt.compare(password, user.password_hash);

  if (!isPasswordValid) {
    throw new BackendError(
      401,
      "INVALID_CREDENTIALS",
      "Invalid email or password",
    );
  }

  let resolvedUser = await resolveUserAccountForAuth(user);
  assertUserCanLogin(resolvedUser);

  const authz = await resolveAuthorizationContext(resolvedUser.id);

  return {
    user: toPublicUser(resolvedUser),
    accessToken: signAccessToken(resolvedUser),
    refreshToken: signRefreshToken(resolvedUser),
    authz,
  };
}

export async function refreshAccessToken({ refreshToken }) {
  try {
    const payload = verifyRefreshToken(refreshToken);

    if (payload.type !== "refresh") {
      throw new BackendError(
        401,
        "INVALID_REFRESH_TOKEN",
        "Provided token is not a refresh token",
      );
    }

    let user = await findUserByPublicUuid(payload.sub);

    user = user ? await resolveUserAccountForAuth(user) : user;

    if (!user || user.account_status !== "active") {
      throw new BackendError(
        401,
        "INVALID_REFRESH_TOKEN",
        "Invalid refresh token",
      );
    }

    const authz = await resolveAuthorizationContext(user.id);

    return {
      user: toPublicUser(user),
      accessToken: signAccessToken(user),
      refreshToken: signRefreshToken(user),
      authz,
    };
  } catch (error) {
    if (
      error.name === "TokenExpiredError" ||
      error.name === "JsonWebTokenError"
    ) {
      throw new BackendError(
        401,
        "INVALID_REFRESH_TOKEN",
        "Invalid or expired refresh token",
      );
    }

    throw error;
  }
}

export async function authenticateAccessToken(accessToken) {
  try {
    const payload = verifyAccessToken(accessToken);

    if (payload.type !== "access") {
      throw new BackendError(
        401,
        "INVALID_ACCESS_TOKEN",
        "Invalid access token",
      );
    }

    let user = await findUserByPublicUuid(payload.sub);

    user = user ? await resolveUserAccountForAuth(user) : user;

    if (!user || user.account_status !== "active") {
      throw new BackendError(
        401,
        "INVALID_ACCESS_TOKEN",
        "Invalid access token",
      );
    }

    const authz = await resolveAuthorizationContext(user.id);

    return {
      auth: payload,
      user: toPublicUser(user),
      authz,
      actorUserId: user.id,
    };
  } catch (error) {
    if (
      error.name === "TokenExpiredError" ||
      error.name === "JsonWebTokenError"
    ) {
      throw new BackendError(
        401,
        "INVALID_ACCESS_TOKEN",
        "Invalid or expired access token",
      );
    }

    throw error;
  }
}