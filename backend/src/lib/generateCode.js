import { randomBytes } from "node:crypto";

export function generateCode(prefix, maxLen = 60) {
  const t = Date.now().toString(36).toUpperCase();
  const r = randomBytes(4).toString("hex").toUpperCase();
  const raw = `${prefix}-${t}-${r}`;
  return raw.length <= maxLen ? raw : raw.slice(0, maxLen);
}
