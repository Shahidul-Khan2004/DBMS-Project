export interface RegisterFormData {
  email: string;
  fullName: string;
  phoneNumber: string;
  password: string;
  rePassword: string;
}

export interface AuthzInfo {
  roleCodes: string[];
  permissions?: string[];
}

export interface AuthUser {
  id: string;
  email?: string;
  full_name: string;
  phone_number: string;
  account_status: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface RegisterResponse {
  message: string;
  accessToken: string;
  refreshToken: string;
  authz: AuthzInfo;
  user: AuthUser;
}

export interface LoginFormData {
  email: string;
  password: string;
}

export interface LoginResponse {
  message: string;
  accessToken: string;
  refreshToken: string;
  authz: AuthzInfo;
  user: AuthUser;
}
