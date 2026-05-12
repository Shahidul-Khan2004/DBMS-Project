"use client";

import {
  clearAuthSession,
  determineRole,
  getAuthSession,
  getValidAccessToken,
  saveAuthSession,
} from "@/lib/auth-store";

export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8080";

export type BackendErrorPayload = {
  error?: {
    code?: string;
    message?: string;
    details?: unknown;
  };
  code?: string;
  message?: string;
};

export class ApiError extends Error {
  status: number;
  code?: string;
  details?: unknown;

  constructor({
    status,
    code,
    message,
    details,
  }: {
    status: number;
    code?: string;
    message: string;
    details?: unknown;
  }) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

type RefreshResponse = {
  accessToken: string;
  refreshToken: string;
  authz?: {
    roleCodes?: string[];
  };
  user?: unknown;
};

type ApiRequestOptions = Omit<RequestInit, "body" | "method"> & {
  body?: unknown;
  method?: "GET" | "POST" | "PATCH";
};

let refreshSessionPromise: Promise<string | null> | null = null;

function buildHeaders(initHeaders?: HeadersInit, body?: unknown) {
  const headers = new Headers(initHeaders);

  if (!headers.has("Content-Type") && body !== undefined) {
    headers.set("Content-Type", "application/json");
  }

  return headers;
}

function serializeBody(body: unknown) {
  if (body === undefined) return undefined;
  if (
    typeof body === "string" ||
    body instanceof FormData ||
    body instanceof Blob ||
    body instanceof URLSearchParams
  ) {
    return body;
  }
  return JSON.stringify(body);
}

async function readJson(response: Response) {
  return (await response.json().catch(() => ({}))) as unknown;
}

export function getApiErrorMessage(data: unknown, fallback: string) {
  if (!data || typeof data !== "object") return fallback;

  const payload = data as BackendErrorPayload;
  const code = payload.error?.code ?? payload.code;
  const message = payload.error?.message ?? payload.message;

  return message ?? code ?? fallback;
}

function toApiError(response: Response, data: unknown, fallback: string) {
  const payload =
    data && typeof data === "object" ? (data as BackendErrorPayload) : {};
  const code = payload.error?.code ?? payload.code;
  const details = payload.error?.details;

  return new ApiError({
    status: response.status,
    code,
    message: getApiErrorMessage(data, fallback),
    details,
  });
}

function missingAuthError() {
  return new ApiError({
    status: 401,
    code: "AUTH_REQUIRED",
    message: "Please sign in to continue.",
  });
}

async function refreshSessionRequest() {
  const { refreshToken, userRole } = getAuthSession();

  if (!refreshToken) return null;

  let data: RefreshResponse;

  try {
    data = await publicJson<RefreshResponse>("/auth/refresh", {
      method: "POST",
      body: { refreshToken },
    });
  } catch {
    clearAuthSession();
    return null;
  }

  if (!data.accessToken || !data.refreshToken) {
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

export async function refreshSession() {
  refreshSessionPromise ??= refreshSessionRequest().finally(() => {
    refreshSessionPromise = null;
  });

  return refreshSessionPromise;
}

export async function ensureAuthSession() {
  const validAccessToken = getValidAccessToken();
  const sessionUser = sessionStorage.getItem("loggedInUser");

  if (validAccessToken && sessionUser) {
    return validAccessToken;
  }

  return refreshSession();
}

export async function apiFetch(path: string, init: RequestInit = {}) {
  const { accessToken } = getAuthSession();
  const headers = buildHeaders(init.headers, init.body);

  if (!accessToken && !headers.has("Authorization")) {
    throw missingAuthError();
  }

  if (!headers.has("Authorization")) {
    headers.set("Authorization", `Bearer ${accessToken}`);
  }

  let response: Response;

  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers,
    });
  } catch {
    throw new ApiError({
      status: 0,
      code: "NETWORK_ERROR",
      message: "Could not reach the server. Please try again.",
    });
  }

  if (response.status !== 401) {
    return response;
  }

  const nextAccessToken = await refreshSession();
  if (!nextAccessToken) return response;

  headers.set("Authorization", `Bearer ${nextAccessToken}`);

  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers,
    });
  } catch {
    throw new ApiError({
      status: 0,
      code: "NETWORK_ERROR",
      message: "Could not reach the server. Please try again.",
    });
  }

  return response;
}

export async function apiJson<T>(path: string, init: RequestInit = {}) {
  const response = await apiFetch(path, init);
  const data = await readJson(response);

  if (!response.ok) {
    throw toApiError(response, data, "Request failed.");
  }

  return data as T;
}

async function protectedJson<T>(
  path: string,
  { method = "GET", body, headers, ...init }: ApiRequestOptions = {},
) {
  return apiJson<T>(path, {
    ...init,
    method,
    headers,
    body: serializeBody(body),
  });
}

async function publicJson<T>(
  path: string,
  { method = "GET", body, headers, ...init }: ApiRequestOptions = {},
) {
  const requestHeaders = buildHeaders(headers, body);
  let response: Response;

  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...init,
      method,
      headers: requestHeaders,
      body: serializeBody(body),
    });
  } catch {
    throw new ApiError({
      status: 0,
      code: "NETWORK_ERROR",
      message: "Could not reach the server. Please try again.",
    });
  }

  const data = await readJson(response);

  if (!response.ok) {
    throw toApiError(response, data, "Request failed.");
  }

  return data as T;
}

export function apiGet<T>(path: string, init?: Omit<ApiRequestOptions, "method" | "body">) {
  return protectedJson<T>(path, { ...init, method: "GET" });
}

export function apiPost<TResponse, TBody = unknown>(
  path: string,
  body?: TBody,
  init?: Omit<ApiRequestOptions, "method" | "body">,
) {
  return protectedJson<TResponse>(path, { ...init, method: "POST", body });
}

export function apiPatch<TResponse, TBody = unknown>(
  path: string,
  body?: TBody,
  init?: Omit<ApiRequestOptions, "method" | "body">,
) {
  return protectedJson<TResponse>(path, { ...init, method: "PATCH", body });
}

export function publicPost<TResponse, TBody = unknown>(
  path: string,
  body?: TBody,
  init?: Omit<ApiRequestOptions, "method" | "body">,
) {
  return publicJson<TResponse>(path, { ...init, method: "POST", body });
}

export function publicGet<T>(path: string, init?: Omit<ApiRequestOptions, "method" | "body">) {
  return publicJson<T>(path, { ...init, method: "GET" });
}
