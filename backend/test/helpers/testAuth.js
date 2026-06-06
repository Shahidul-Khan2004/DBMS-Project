import { ROLE_CODES } from "../../src/services/rbacService.js";

const TEST_USER_ID = 9001;
const TEST_USER_PUBLIC_UUID = "a0000001-0000-4000-8000-000000000099";

const ALL_PERMISSION_CODES = [
  "auth.manage_roles",
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
  "agency.manage",
  "agency.view_own",
  "agency.manage_own_units",
  "dispatch.view_own_agency",
  "dispatch.update_own_agency",
  "response_log.create_own_agency",
  "disaster.create",
  "disaster.read",
  "disaster.update_status",
  "disaster.declare",
  "disaster.manage_affected_areas",
  "disaster.manage_responsibilities",
  "disaster.link_incidents",
  "facility.manage",
  "facility.read",
  "shelter.manage",
  "shelter.record_occupancy",
  "shelter.record_occupancy_own",
  "relief.manage_inventory",
  "relief.manage_inventory_own",
  "relief.manage_requests",
  "relief.request_own_shelter",
  "relief.distribute",
];

const DISPATCHER_PERMISSION_CODES = [
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
  "disaster.read",
  "disaster.manage_affected_areas",
  "disaster.link_incidents",
  "facility.read",
];

const AGENCY_REP_PERMISSION_CODES = [
  "agency.view_own",
  "agency.manage_own_units",
  "dispatch.view_own_agency",
  "dispatch.update_own_agency",
  "response_log.create_own_agency",
  "disaster.read",
  "shelter.record_occupancy_own",
  "relief.request_own_shelter",
  "relief.manage_inventory_own",
];

function baseUser() {
  return {
    id: TEST_USER_PUBLIC_UUID,
    email: "test.user@niers.test",
    full_name: "Test User",
    phone_number: "01700000000",
    secondary_phone_number: null,
    account_status: "active",
    is_active: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };
}

export const PERSONAS = {
  citizen: {
    user: baseUser(),
    actorUserId: TEST_USER_ID,
    auth: { sub: TEST_USER_PUBLIC_UUID, type: "access" },
    authz: {
      roleCodes: [ROLE_CODES.CITIZEN],
      permissions: [],
    },
    agencyContext: null,
  },
  dispatcher: {
    user: baseUser(),
    actorUserId: TEST_USER_ID,
    auth: { sub: TEST_USER_PUBLIC_UUID, type: "access" },
    authz: {
      roleCodes: [ROLE_CODES.DISPATCHER],
      permissions: DISPATCHER_PERMISSION_CODES,
    },
    agencyContext: null,
  },
  systemAdmin: {
    user: baseUser(),
    actorUserId: TEST_USER_ID,
    auth: { sub: TEST_USER_PUBLIC_UUID, type: "access" },
    authz: {
      roleCodes: [ROLE_CODES.SYSTEM_ADMIN],
      permissions: ALL_PERMISSION_CODES,
    },
    agencyContext: null,
  },
  agencyRep: {
    user: baseUser(),
    actorUserId: TEST_USER_ID,
    auth: { sub: TEST_USER_PUBLIC_UUID, type: "access" },
    authz: {
      roleCodes: [ROLE_CODES.AGENCY_REPRESENTATIVE],
      permissions: AGENCY_REP_PERMISSION_CODES,
    },
    agencyContext: {
      agency_id: 1,
      agency_public_uuid: "b2000001-0000-4000-8000-000000000001",
      agency_code: "DHK-FIRE-01",
      agency_name: "Dhaka Fire Demo",
      membership_role: "representative",
      membership_status: "active",
    },
  },
};

/**
 * @param {keyof PERSONAS} personaKey
 */
export function createTestAuth(personaKey) {
  const persona = PERSONAS[personaKey];
  if (!persona) {
    throw new Error(`Unknown test persona: ${personaKey}`);
  }

  return (req, res, next) => {
    req.user = persona.user;
    req.authz = persona.authz;
    req.actorUserId = persona.actorUserId;
    req.auth = persona.auth;
    next();
  };
}

/** Injects agency context without hitting the database. */
export function createTestAgencyContext(personaKey = "agencyRep") {
  const persona = PERSONAS[personaKey];
  return (req, res, next) => {
    req.agencyContext = persona.agencyContext ?? PERSONAS.agencyRep.agencyContext;
    next();
  };
}