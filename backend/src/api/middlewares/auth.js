import { randomUUID } from "node:crypto";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { query } from "../../config/db.js";
import BackendError from "../../lib/BackendError.js";

const ACCESS_TOKEN_EXPIRES_IN = process.env.JWT_ACCESS_EXPIRES_IN || "1h";
const REFRESH_TOKEN_EXPIRES_IN = process.env.JWT_REFRESH_EXPIRES_IN || "7d";

function getAccessTokenSecret() {
  return process.env.JWT_ACCESS_SECRET;
}

function getRefreshTokenSecret() {
  return process.env.JWT_REFRESH_SECRET;
}

function ensureJwtSecrets() {
  const accessSecret = getAccessTokenSecret();
  const refreshSecret = getRefreshTokenSecret();

  if (!accessSecret) {
    throw new Error("JWT_ACCESS_SECRET is not configured");
  }

  if (!refreshSecret) {
    throw new Error("JWT_REFRESH_SECRET is not configured");
  }

  return {
    accessSecret,
    refreshSecret,
  };
}

function toPublicUser(user) {
  return {
    id: user.public_uuid,
    email: user.email,
    full_name: user.full_name,
    created_at: user.created_at,
  };
}

async function getUserByPublicUuid(publicUuid) {
  const result = await query(
    `
      SELECT public_uuid, email, full_name, created_at
      FROM users
      WHERE public_uuid = ?
    `,
    [publicUuid]
  );

  return result.rows[0] || null;
}

function signAccessToken(user) {
  const { accessSecret } = ensureJwtSecrets();

  return jwt.sign(
    {
      sub: user.public_uuid,
      email: user.email,
      type: "access",
    },
    accessSecret,
    { expiresIn: ACCESS_TOKEN_EXPIRES_IN }
  );
}

function signRefreshToken(user) {
  const { refreshSecret } = ensureJwtSecrets();

  return jwt.sign(
    {
      sub: user.public_uuid,
      type: "refresh",
    },
    refreshSecret,
    { expiresIn: REFRESH_TOKEN_EXPIRES_IN }
  );
}

function extractBearerToken(req) {
  const authorization = req.get("authorization");

  if (!authorization) {
    return null;
  }

  const [scheme, token] = authorization.trim().split(/\s+/);

  if (scheme?.toLowerCase() !== "bearer" || !token) {
    return null;
  }

  return token;
}

export async function registerUser(req, res) {
  const { email, fullName, password } = req.body;
  const publicUuid = randomUUID();

  const userExists = await query("SELECT id FROM users WHERE email = ?", [
    email,
  ]);
  if (userExists.rows.length > 0) {
    throw new BackendError(409, "EXISTING_EMAIL", "Email already in use");
  }

  const saltRounds = 10;
  const passwordHash = await bcrypt.hash(password, saltRounds);

  const insertQuery = `
    INSERT INTO users (public_uuid, email, full_name, password_hash) 
    VALUES (?, ?, ?, ?)
  `;
  await query(insertQuery, [
    publicUuid,
    email,
    fullName,
    passwordHash,
  ]);
  const user = await getUserByPublicUuid(publicUuid);
  const accessToken = signAccessToken(user);
  const refreshToken = signRefreshToken(user);

  res.status(201).json({
    message: "User registered successfully",
    accessToken,
    refreshToken,
    user: toPublicUser(user),
  });
}

export async function loginUser(req, res) {
  const { email, password } = req.body;

  const result = await query(
    `
      SELECT public_uuid, email, full_name, password_hash, created_at
      FROM users
      WHERE email = ?
    `,
    [email]
  );

  const user = result.rows[0];

  if (!user) {
    throw new BackendError(403, "INVALID_CREDENTIALS", "User with this email does not exist");
  }

  const isPasswordValid = await bcrypt.compare(password, user.password_hash);

  if (!isPasswordValid) {
    throw new BackendError(401, "INVALID_CREDENTIALS", "Password is incorrect");
  }
  const accessToken = signAccessToken(user);
  const refreshToken = signRefreshToken(user);

  res.status(200).json({
    message: "Login successful",
    accessToken,
    refreshToken,
    user: toPublicUser(user),
  });
}

export async function refreshAccessToken(req, res) {
  const { refreshToken } = req.body;
  const { refreshSecret } = ensureJwtSecrets();
  const payload = jwt.verify(refreshToken, refreshSecret);

  if (payload.type !== "refresh") {
    throw new BackendError(401, "INVALID_REFRESH_TOKEN", "Provided token is not a refresh token");
  }

  const user = await getUserByPublicUuid(payload.sub);

  if (!user) {
    throw new BackendError(401, "INVALID_REFRESH_TOKEN", "Invalid refresh token");
  }

  const nextAccessToken = signAccessToken(user);
  const nextRefreshToken = signRefreshToken(user);

  res.status(200).json({
    message: "Token refreshed successfully",
    accessToken: nextAccessToken,
    refreshToken: nextRefreshToken,
    user: toPublicUser(user),
  });
}

export async function requireAuth(req, res, next) {
  try {
    const accessToken = extractBearerToken(req);

    if (!accessToken) {
      return next(
        new BackendError(401, "AUTH_HEADER_INVALID", "Missing or invalid Authorization header")
      );
    }

    const { accessSecret } = ensureJwtSecrets();
    const payload = jwt.verify(accessToken, accessSecret);

    if (payload.type !== "access") {
      return next(new BackendError(401, "INVALID_ACCESS_TOKEN", "Invalid access token"));
    }

    const user = await getUserByPublicUuid(payload.sub);

    if (!user) {
      return next(new BackendError(401, "INVALID_ACCESS_TOKEN", "Not user's access token"));
    }

    req.auth = payload;
    req.user = toPublicUser(user);
    next();
  } catch (error) {
    if (
      error.name === "TokenExpiredError" || error.name === "JsonWebTokenError"
    ) {
      return next(new BackendError(401, "INVALID_ACCESS_TOKEN", "Invalid or expired access token"));
    }

    next(error);
  }
}

export function getCurrentUser(req, res) {
  res.status(200).json({
    user: req.user,
  });
}
