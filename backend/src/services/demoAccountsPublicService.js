import { readBootstrapPassword } from "./bootstrapPasswordSync.js";

const DEMO_CITIZENS = [
  { email: "citizen.rahima@niers.test", label: "Rahima Begum" },
  { email: "citizen.karim@niers.test", label: "Abdul Karim" },
  { email: "citizen.farhana@niers.test", label: "Farhana Akter" },
  { email: "citizen.rubel@niers.test", label: "Rubel Hossain" },
  { email: "citizen.shamim@niers.test", label: "Shamim Ahmed" },
];

const DEMO_AGENCY_REPS = [
  { email: "fire.rep@niers.test", label: "Fire Agency Representative" },
  { email: "police.rep@niers.test", label: "Police Agency Representative" },
  { email: "medical.rep@niers.test", label: "Medical Agency Representative" },
  { email: "relief.rep@niers.test", label: "Relief Agency Representative" },
  { email: "shelter.rep@niers.test", label: "Shelter Agency Representative" },
];

function account(email, role, password, label) {
  if (!password) return null;
  return {
    email,
    role,
    password,
    ...(label ? { label } : {}),
  };
}

function group(role, roleLabel, password, accounts) {
  const items = accounts
    .map((item) => account(item.email, role, password, item.label))
    .filter(Boolean);

  if (items.length === 0) return null;

  return { role, roleLabel, password, accounts: items };
}

export function listPublicDemoAccounts() {
  const systemAdminEmail = process.env.SYSTEM_ADMIN__EMAIL?.trim().toLowerCase();
  const systemAdminPassword = readBootstrapPassword(
    process.env.SYSTEM_ADMIN_PASSWORD,
    "SYSTEM_ADMIN_PASSWORD",
  );
  const dispatcherPassword = readBootstrapPassword(
    process.env.DEMO_DISPATCHER_PASSWORD,
    "DEMO_DISPATCHER_PASSWORD",
  );
  const citizenPassword = readBootstrapPassword(
    process.env.DEMO_CITIZEN_PASSWORD,
    "DEMO_CITIZEN_PASSWORD",
  );
  const repPassword = readBootstrapPassword(
    process.env.DEMO_REP_PASSWORD,
    "DEMO_REP_PASSWORD",
  );

  const groups = [];

  const systemAdmin = account(
    systemAdminEmail,
    "system_admin",
    systemAdminPassword,
    process.env.SYSTEM_ADMIN_NAME?.trim() || "System Administrator",
  );
  if (systemAdmin) {
    groups.push({
      role: "system_admin",
      roleLabel: "System Admin",
      password: systemAdmin.password,
      accounts: [systemAdmin],
    });
  }

  const dispatcher = account(
    "dispatcher@niers.test",
    "dispatcher",
    dispatcherPassword,
    "Demo Dispatcher",
  );
  if (dispatcher) {
    groups.push({
      role: "dispatcher",
      roleLabel: "Dispatcher",
      password: dispatcher.password,
      accounts: [dispatcher],
    });
  }

  const citizenGroup = group("citizen", "Citizens", citizenPassword, DEMO_CITIZENS);
  if (citizenGroup) groups.push(citizenGroup);

  const repGroup = group(
    "agency_representative",
    "Agency Representatives",
    repPassword,
    DEMO_AGENCY_REPS,
  );
  if (repGroup) groups.push(repGroup);

  return { groups };
}
