export type DemoAccount = {
  email: string;
  role: string;
  password: string;
  label?: string;
};

export type DemoAccountGroup = {
  role: string;
  roleLabel: string;
  password: string;
  accounts: DemoAccount[];
};

export type DemoAccountsResponse = {
  groups: DemoAccountGroup[];
};
