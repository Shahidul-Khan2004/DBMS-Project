import { randomUUID } from "node:crypto";
import bcrypt from "bcrypt";
import BackendError from "../lib/BackendError.js";
import {
  findUserByEmail,
  findUserByPublicUuid,
  createUser,
} from "../repositories/userRepo.js";
import {
  signAccessToken,
  signRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
} from "./tokenService.js";

export function toPublicUser(user) {
  return {
    id: user.public_uuid,
    email: user.email,
    full_name: user.full_name,
    phone_number: user.phone_number,
    is_active: user.is_active,
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

  await createUser({
    publicUuid,
    email,
    fullName,
    phoneNumber,
    passwordHash,
  });

  const user = await findUserByPublicUuid(publicUuid);

  return {
    user: toPublicUser(user),
    accessToken: signAccessToken(user),
    refreshToken: signRefreshToken(user),
  };
}

export async function loginUser({ email, password }) {
  const user = await findUserByEmail(email);

  if (!user) {
    throw new BackendError(401, "INVALID_CREDENTIALS", "Invalid email or password");
  }

  if (!user.is_active) {
    throw new BackendError(403, "USER_INACTIVE", "User account is inactive");
  }

  const isPasswordValid = await bcrypt.compare(password, user.password_hash);

  if (!isPasswordValid) {
    throw new BackendError(401, "INVALID_CREDENTIALS", "Invalid email or password");
  }

  return {
    user: toPublicUser(user),
    accessToken: signAccessToken(user),
    refreshToken: signRefreshToken(user),
  };
}

export async function refreshAccessToken({ refreshToken }) {
  try {
    const payload = verifyRefreshToken(refreshToken);

    if (payload.type !== "refresh") {
      throw new BackendError(401, "INVALID_REFRESH_TOKEN", "Provided token is not a refresh token");
    }

    const user = await findUserByPublicUuid(payload.sub);

    if (!user || !user.is_active) {
      throw new BackendError(401, "INVALID_REFRESH_TOKEN", "Invalid refresh token");
    }

    return {
      user: toPublicUser(user),
      accessToken: signAccessToken(user),
      refreshToken: signRefreshToken(user),
    };
  } catch (error) {
    if (
      error.name === "TokenExpiredError" ||
      error.name === "JsonWebTokenError"
    ) {
      throw new BackendError(401, "INVALID_REFRESH_TOKEN", "Invalid or expired refresh token");
    }

    throw error;
  }
}


export async function authenticateAccessToken(accessToken) {
  try {
    const payload = verifyAccessToken(accessToken);

    if (payload.type !== "access") {
      throw new BackendError(401, "INVALID_ACCESS_TOKEN", "Invalid access token");
    }

    const user = await findUserByPublicUuid(payload.sub);

    if (!user || !user.is_active) {
      throw new BackendError(401, "INVALID_ACCESS_TOKEN", "Invalid access token");
    }

    return {
      auth: payload,
      user: toPublicUser(user),
    };
  } catch (error) {
    if (
      error.name === "TokenExpiredError" ||
      error.name === "JsonWebTokenError"
    ) {
      throw new BackendError(401, "INVALID_ACCESS_TOKEN", "Invalid or expired access token");
    }

    throw error;
  }
}
