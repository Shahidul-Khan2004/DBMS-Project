"use client";

import {
  clearAuthSession,
  determineRole,
  getAuthSession,
  saveAuthSession,
} from "@/lib/auth-store";

export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8080";

type ErrorPayload = {
  error?: {
    code?: string;
    message?: string;
    details?: unknown;
  };
  code?: string;
  message?: string;
};

type RefreshResponse = {
  accessToken: string;
  refreshToken: string;
  authz?: {
    roleCodes?: string[];
  };
  user?: unknown;
};

export function getApiErrorMessage(data: unknown, fallback: string) {
  if (!data || typeof data !== "object") return fallback;

  const payload = data as ErrorPayload;
  const code = payload.error?.code ?? payload.code;
  const message = payload.error?.message ?? payload.message;

  if (code && message) return `${message} (${code})`;
  return message ?? code ?? fallback;
}

async function refreshSession() {
  const { refreshToken, userRole } = getAuthSession();

  if (!refreshToken) return null;

  const response = await fetch(`${API_BASE}/auth/refresh`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ refreshToken }),
  });

  const data = (await response.json().catch(() => ({}))) as RefreshResponse;

  if (!response.ok || !data.accessToken || !data.refreshToken) {
    clearAuthSession();
    return null;
  }

  const nextRole = determineRole(data.authz?.roleCodes ?? [userRole]);
  saveAuthSession(data.accessToken, data.refreshToken, nextRole);

  if (data.user) {
    sessionStorage.setItem("loggedInUser", JSON.stringify(data.user));
  }

  return data.accessToken;
}

export async function apiFetch(path: string, init: RequestInit = {}) {
  const { accessToken } = getAuthSession();
  const headers = new Headers(init.headers);

  if (!headers.has("Content-Type") && init.body) {
    headers.set("Content-Type", "application/json");
  }

  if (accessToken && !headers.has("Authorization")) {
    headers.set("Authorization", `Bearer ${accessToken}`);
  }

  let response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers,
  });

  if (response.status !== 401) {
    return response;
  }

  const nextAccessToken = await refreshSession();
  if (!nextAccessToken) return response;

  headers.set("Authorization", `Bearer ${nextAccessToken}`);
  response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers,
  });

  return response;
}

export async function apiJson<T>(path: string, init: RequestInit = {}) {
  const response = await apiFetch(path, init);
  const data = (await response.json().catch(() => ({}))) as T;

  if (!response.ok) {
    throw new Error(getApiErrorMessage(data, "Request failed."));
  }

  return data;
}
