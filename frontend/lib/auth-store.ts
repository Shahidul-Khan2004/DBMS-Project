// Role determination from backend authz.roleCodes
export type UserRole = 'citizen' | 'dispatcher' | 'system_admin';

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
  localStorage.setItem('accessToken', accessToken);
  localStorage.setItem('refreshToken', refreshToken);
  localStorage.setItem('userRole', role);
}

export function getAuthSession() {
  const accessToken = localStorage.getItem('accessToken');
  const refreshToken = localStorage.getItem('refreshToken');
  const userRole = (localStorage.getItem('userRole') as UserRole) || 'citizen';
  
  return { accessToken, refreshToken, userRole };
}

export function clearAuthSession() {
  localStorage.removeItem('accessToken');
  localStorage.removeItem('refreshToken');
  localStorage.removeItem('userRole');
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
