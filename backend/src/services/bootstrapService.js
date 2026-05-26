import { randomUUID } from "node:crypto";
import bcrypt from "bcrypt";
import { createUser, findUserByEmail } from "../repositories/userRepo.js";
import {
  assignRoleToUser,
  ensurePermission,
  ensureRole,
  findRoleByCode,
  grantPermissionToRole,
  hasAnyUserWithRole,
  hasRoleAssignment,
} from "../repositories/rbacRepo.js";
import { ROLE_CODES } from "./rbacService.js";
import { bootstrapDemoAgencyRepresentatives } from "./demoRepBootstrapService.js";
import { ensureAgencyMembershipsPublicUuid } from "./schemaMigrations.js";

const DEFAULT_PERMISSIONS = [
  {
    permissionCode: "auth.manage_roles",
    moduleName: "auth",
    description: "Assign and manage user roles",
  },
  {
    permissionCode: "incident.create",
    moduleName: "incident",
    description: "Create emergency incidents",
  },
  {
    permissionCode: "incident.classify",
    moduleName: "incident",
    description: "Classify reports into emergency or service tracks",
  },
  {
    permissionCode: "incident.assign_agency",
    moduleName: "incident",
    description: "Assign agencies to incidents",
  },
  {
    permissionCode: "incident.update_status",
    moduleName: "incident",
    description: "Update incident lifecycle status",
  },
  {
    permissionCode: "dispatch.create",
    moduleName: "dispatch",
    description: "Dispatch units to incidents",
  },
  {
    permissionCode: "dispatch.update_status",
    moduleName: "dispatch",
    description: "Update dispatch progress",
  },
  {
    permissionCode: "case.create",
    moduleName: "case",
    description: "Create service cases",
  },
  {
    permissionCode: "case.respond",
    moduleName: "case",
    description: "Respond to service cases",
  },
  {
    permissionCode: "case.assign",
    moduleName: "case",
    description: "Assign service cases",
  },
  {
    permissionCode: "case.escalate",
    moduleName: "case",
    description: "Escalate service case to emergency incident",
  },
  {
    permissionCode: "agency.manage",
    moduleName: "agency",
    description: "Manage agencies and onboard representatives",
  },
  {
    permissionCode: "agency.view_own",
    moduleName: "agency",
    description: "View own agency profile and resources",
  },
  {
    permissionCode: "agency.manage_own_units",
    moduleName: "agency",
    description: "Manage units for own agency",
  },
  {
    permissionCode: "dispatch.view_own_agency",
    moduleName: "dispatch",
    description: "View dispatches for own agency",
  },
  {
    permissionCode: "dispatch.update_own_agency",
    moduleName: "dispatch",
    description: "Update dispatch status for own agency",
  },
  {
    permissionCode: "response_log.create_own_agency",
    moduleName: "response",
    description: "Create field response logs for own agency incidents",
  },
];

const ROLE_DEFINITIONS = [
  {
    roleCode: ROLE_CODES.SYSTEM_ADMIN,
    name: "System Administrator",
    description: "Full administrative role",
    isSystemRole: true,
  },
  {
    roleCode: ROLE_CODES.CITIZEN,
    name: "Citizen",
    description: "Default role for user registration",
    isSystemRole: true,
  },
  {
    roleCode: ROLE_CODES.DISPATCHER,
    name: "Dispatcher",
    description:
      "Handles emergency call intake and triage, incidents, agency assignment, and dispatch progress",
    isSystemRole: true,
  },
  {
    roleCode: ROLE_CODES.AGENCY_REPRESENTATIVE,
    name: "Agency Representative",
    description: "Agency-side field operations for own agency units and dispatches",
    isSystemRole: true,
  },
];

const AGENCY_REPRESENTATIVE_PERMISSION_CODES = [
  "agency.view_own",
  "agency.manage_own_units",
  "dispatch.view_own_agency",
  "dispatch.update_own_agency",
  "response_log.create_own_agency",
];

async function ensureRolesAndPermissions() {
  for (const role of ROLE_DEFINITIONS) {
    await ensureRole(role);
  }

  for (const permission of DEFAULT_PERMISSIONS) {
    await ensurePermission(permission);
  }

  for (const permission of DEFAULT_PERMISSIONS) {
    await grantPermissionToRole({
      roleCode: ROLE_CODES.SYSTEM_ADMIN,
      permissionCode: permission.permissionCode,
    });
  }

  const dispatcherPermissionCodes = [
    "incident.create",
    "incident.classify",
    "incident.assign_agency",
    "incident.update_status",
    "dispatch.create",
    "dispatch.update_status",
    "case.create",
    "case.respond",
    "case.assign",
    "case.escalate",
  ];

  for (const permissionCode of dispatcherPermissionCodes) {
    await grantPermissionToRole({
      roleCode: ROLE_CODES.DISPATCHER,
      permissionCode,
    });
  }

  for (const permissionCode of AGENCY_REPRESENTATIVE_PERMISSION_CODES) {
    await grantPermissionToRole({
      roleCode: ROLE_CODES.AGENCY_REPRESENTATIVE,
      permissionCode,
    });
  }
}

export async function bootstrapDevelopmentSystemAdmin() {
  await ensureRolesAndPermissions();
  await ensureAgencyMembershipsPublicUuid();
  await bootstrapDemoAgencyRepresentatives();

  const adminExists = await hasAnyUserWithRole(ROLE_CODES.SYSTEM_ADMIN);

  if (adminExists) {
    return;
  }

  const email = process.env.SYSTEM_ADMIN__EMAIL;
  const password = process.env.SYSTEM_ADMIN_PASSWORD;
  const fullName = process.env.SYSTEM_ADMIN_NAME;
  const phoneNumber = process.env.SYSTEM_ADMIN_PHONE;

  if (!email || !password || !fullName || !phoneNumber) {
    console.warn(
      "Skipping system admin bootstrap. Please set SYSTEM_ADMIN__EMAIL, SYSTEM_ADMIN_PASSWORD, SYSTEM_ADMIN_NAME, and SYSTEM_ADMIN_PHONE."
    );
    return;
  }

  if (!/^\d{11}$/.test(phoneNumber)) {
    console.warn(
      "Skipping system admin bootstrap. SYSTEM_ADMIN_PHONE must be exactly 11 digits."
    );
    return;
  }

  let adminUser = await findUserByEmail(email);

  if (!adminUser) {
    const publicUuid = randomUUID();
    const passwordHash = await bcrypt.hash(password, 10);

    await createUser({
      publicUuid,
      email,
      fullName,
      phoneNumber,
      passwordHash,
    });

    adminUser = await findUserByEmail(email);
  }

  const systemAdminRole = await findRoleByCode(ROLE_CODES.SYSTEM_ADMIN);

  if (!systemAdminRole) {
    throw new Error("Failed to load system_admin role during bootstrap.");
  }

  const assigned = await hasRoleAssignment({
    userId: adminUser.id,
    roleCode: ROLE_CODES.SYSTEM_ADMIN,
  });

  if (!assigned) {
    await assignRoleToUser({
      userId: adminUser.id,
      roleId: systemAdminRole.id,
      assignedByUserId: null,
    });
  }

  console.log(`Bootstrapped system admin: ${fullName}`);
}

