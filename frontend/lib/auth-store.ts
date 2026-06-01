import type { AuthzInfo } from '@/types/auth';

// Role determination from backend authz.roleCodes
export type UserRole = 'citizen' | 'dispatcher' | 'system_admin';

const AUTHZ_STORAGE_KEY = 'authz';

interface StoredAuthSession {
  accessToken: string;
  refreshToken?: string;
  userRole?: UserRole;
}

export function determineRole(roleCodes: string[] = []): UserRole {
  if (roleCodes.includes('system_admin')) {
    return 'system_admin';
  }

  if (roleCodes.includes('dispatcher')) {
    return 'dispatcher';
  }

  return 'citizen';
}

export function saveAuthSession(accessToken: string, refreshToken: string, role: UserRole) {
  localStorage.setItem(
    'auth_session',
    JSON.stringify({ accessToken, refreshToken, userRole: role }),
  );
  localStorage.setItem('accessToken', accessToken);
  localStorage.setItem('refreshToken', refreshToken);
  localStorage.setItem('userRole', role);
}

export function getAuthSession() {
  const storedSession = readStoredAuthSession();
  const accessToken = storedSession?.accessToken ?? localStorage.getItem('accessToken');
  const refreshToken = storedSession?.refreshToken ?? localStorage.getItem('refreshToken');
  const userRole =
    storedSession?.userRole ?? (localStorage.getItem('userRole') as UserRole) ?? 'citizen';
  
  return { accessToken, refreshToken, userRole };
}

export function clearAuthSession() {
  localStorage.removeItem('auth_session');
  localStorage.removeItem('accessToken');
  localStorage.removeItem('refreshToken');
  localStorage.removeItem('userRole');
  clearAuthz();
}

export function saveAuthz(authz: AuthzInfo) {
  localStorage.setItem(AUTHZ_STORAGE_KEY, JSON.stringify(authz));
}

export function getAuthz(): AuthzInfo | null {
  const raw = localStorage.getItem(AUTHZ_STORAGE_KEY);
  if (!raw) return null;

  try {
    return JSON.parse(raw) as AuthzInfo;
  } catch {
    return null;
  }
}

export function clearAuthz() {
  localStorage.removeItem(AUTHZ_STORAGE_KEY);
}

export function getValidAccessToken() {
  const { accessToken } = getAuthSession();

  if (!accessToken || isJwtExpired(accessToken)) {
    return null;
  }

  return accessToken;
}

function readStoredAuthSession(): StoredAuthSession | null {
  const raw = localStorage.getItem('auth_session');

  if (!raw) return null;

  try {
    const parsed = JSON.parse(raw) as Partial<StoredAuthSession>;
    if (!parsed.accessToken || typeof parsed.accessToken !== 'string') {
      return null;
    }

    return parsed as StoredAuthSession;
  } catch {
    return null;
  }
}

function isJwtExpired(token: string) {
  try {
    const payloadPart = token.split('.')[1];
    if (!payloadPart) return true;

    const normalized = payloadPart.replace(/-/g, '+').replace(/_/g, '/');
    const payload = JSON.parse(atob(normalized)) as { exp?: number };

    if (!payload.exp) return false;

    return payload.exp * 1000 <= Date.now();
  } catch {
    return true;
  }
}

export function getDashboardUrl(role: UserRole): string {
  if (role === 'system_admin') {
    return '/dashboard/admin';
  }

  if (role === 'dispatcher') {
    return '/dashboard/dispatcher';
  }

  return '/dashboard/citizen';
}

export function getDashboardUrlFromRoleCodes(roleCodes: string[] = []): string {
  return getDashboardUrl(determineRole(roleCodes));
}
