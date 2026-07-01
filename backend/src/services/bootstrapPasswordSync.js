import bcrypt from "bcrypt";
import { findUserByEmail, updateUserPasswordHash } from "../repositories/userRepo.js";

export function readBootstrapPassword(envValue, envName) {
  const password = envValue?.trim();
  if (!password) {
    return null;
  }
  if (password.length < 8) {
    console.warn(
      `Skipping bootstrap using ${envName}: password must be at least 8 characters.`,
    );
    return null;
  }
  return password;
}

export async function hashBootstrapPassword(plainPassword) {
  return bcrypt.hash(plainPassword.trim(), 10);
}

export async function syncBootstrapPassword(email, plainPassword, passwordHash) {
  const normalizedEmail = email.trim().toLowerCase();
  let user = await findUserByEmail(normalizedEmail);

  if (!user) {
    return null;
  }

  await updateUserPasswordHash(user.id, passwordHash);

  user = await findUserByEmail(normalizedEmail);
  if (!user) {
    throw new Error(`Bootstrap password sync lost user ${normalizedEmail}`);
  }

  const verified = await bcrypt.compare(plainPassword.trim(), user.password_hash);
  if (!verified) {
    throw new Error(
      `Bootstrap password verification failed for ${normalizedEmail}`,
    );
  }

  return user;
}
