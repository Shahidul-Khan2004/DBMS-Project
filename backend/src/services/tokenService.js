import jwt from "jsonwebtoken";

const ACCESS_TOKEN_EXPIRES_IN = process.env.JWT_ACCESS_EXPIRES_IN || "1h";
const REFRESH_TOKEN_EXPIRES_IN = process.env.JWT_REFRESH_EXPIRES_IN || "7d";

function ensureJwtSecrets() {
  const accessSecret = process.env.JWT_ACCESS_SECRET;
  const refreshSecret = process.env.JWT_REFRESH_SECRET;

  if (!accessSecret || !refreshSecret) {
    throw new Error("JWT secrets are not configured");
  }

  return { accessSecret, refreshSecret };
}

export function signAccessToken(user) {
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

export function signRefreshToken(user) {
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

export function verifyAccessToken(accessToken) {
  const { accessSecret } = ensureJwtSecrets();
  return jwt.verify(accessToken, accessSecret);
}

export function verifyRefreshToken(refreshToken) {
  const { refreshSecret } = ensureJwtSecrets();
  return jwt.verify(refreshToken, refreshSecret);
}
