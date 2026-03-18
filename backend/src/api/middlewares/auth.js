import { randomUUID } from "node:crypto";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { query } from "../../config/db.js";

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
  try {
    const { email, fullName, password } = req.body;
    const publicUuid = randomUUID();

    const userExists = await query("SELECT id FROM users WHERE email = ?", [
      email,
    ]);
    if (userExists.rows.length > 0) {
      return res.status(409).json({ error: "Email already in use" });
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
  } catch (error) {
    console.error("Registration Error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
}

export async function loginUser(req, res) {
  try {
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
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password_hash);

    if (!isPasswordValid) {
      return res.status(401).json({ error: "Invalid email or password" });
    }
    const accessToken = signAccessToken(user);
    const refreshToken = signRefreshToken(user);

    res.status(200).json({
      message: "Login successful",
      accessToken,
      refreshToken,
      user: toPublicUser(user),
    });
  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
}

export async function refreshAccessToken(req, res) {
  try {
    const { refreshToken } = req.body;
    const { refreshSecret } = ensureJwtSecrets();
    const payload = jwt.verify(refreshToken, refreshSecret);

    if (payload.type !== "refresh") {
      return res.status(401).json({ error: "Invalid refresh token" });
    }

    const user = await getUserByPublicUuid(payload.sub);

    if (!user) {
      return res.status(401).json({ error: "Invalid refresh token" });
    }

    const nextAccessToken = signAccessToken(user);
    const nextRefreshToken = signRefreshToken(user);

    res.status(200).json({
      message: "Token refreshed successfully",
      accessToken: nextAccessToken,
      refreshToken: nextRefreshToken,
      user: toPublicUser(user),
    });
  } catch (error) {
    console.error("Refresh Token Error:", error);
    res.status(401).json({ error: "Invalid or expired refresh token" });
  }
}

export async function requireAuth(req, res, next) {
  try {
    const accessToken = extractBearerToken(req);

    if (!accessToken) {
      return res.status(401).json({ error: "Missing or invalid Authorization header" });
    }

    const { accessSecret } = ensureJwtSecrets();
    const payload = jwt.verify(accessToken, accessSecret);

    if (payload.type !== "access") {
      return res.status(401).json({ error: "Invalid access token" });
    }

    const user = await getUserByPublicUuid(payload.sub);

    if (!user) {
      return res.status(401).json({ error: "Invalid access token" });
    }

    req.auth = payload;
    req.user = toPublicUser(user);
    next();
  } catch (error) {
    console.error("Authorization Error:", error);
    res.status(401).json({ error: "Invalid or expired access token" });
  }
}

export function getCurrentUser(req, res) {
  res.status(200).json({
    user: req.user,
  });
}
