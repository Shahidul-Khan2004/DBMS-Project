import { randomUUID } from "node:crypto";
import bcrypt from "bcrypt";
import pool from "../config/db.js";
import {
  createUser,
  findUserByEmail,
  updateUserPasswordHash,
} from "../repositories/userRepo.js";
import {
  assignRoleToUser,
  findRoleByCode,
  grantPermissionToRole,
  hasRoleAssignment,
} from "../repositories/rbacRepo.js";
import { ROLE_CODES } from "./rbacService.js";

const DEMO_REPS = [
  {
    email: "fire.rep@niers.test",
    fullName: "Fire Agency Representative",
    phoneNumber: "01700000001",
    agencyPublicUuid: "b2000001-0000-4000-8000-000000000001",
    membershipPublicUuid: "d4000001-0000-4000-8000-000000000001",
  },
  {
    email: "police.rep@niers.test",
    fullName: "Police Agency Representative",
    phoneNumber: "01700000002",
    agencyPublicUuid: "b2000001-0000-4000-8000-000000000002",
    membershipPublicUuid: "d4000001-0000-4000-8000-000000000002",
  },
  {
    email: "medical.rep@niers.test",
    fullName: "Medical Agency Representative",
    phoneNumber: "01700000003",
    agencyPublicUuid: "b2000001-0000-4000-8000-000000000003",
    membershipPublicUuid: "d4000001-0000-4000-8000-000000000003",
  },
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

const KURIGRAM_DEMO_REPS = [
  {
    email: "relief.rep@niers.test",
    fullName: "Relief Agency Representative",
    phoneNumber: "01700000011",
    agencyPublicUuid: "b3000001-0000-4000-8000-000000000001",
    membershipPublicUuid: "d4000001-0000-4000-8000-000000000011",
  },
  {
    email: "shelter.rep@niers.test",
    fullName: "Shelter Agency Representative",
    phoneNumber: "01700000012",
    agencyPublicUuid: "b3000001-0000-4000-8000-000000000002",
    membershipPublicUuid: "d4000001-0000-4000-8000-000000000012",
  },
];

async function ensureAgencyRepRoleAndPermissions() {
  for (const permissionCode of AGENCY_REP_PERMISSION_CODES) {
    await grantPermissionToRole({
      roleCode: ROLE_CODES.AGENCY_REPRESENTATIVE,
      permissionCode,
    });
  }
}

async function upsertMembership(conn, { userId, agencyId, membershipPublicUuid }) {
  const [existing] = await conn.execute(
    `
      SELECT id, membership_status
      FROM agency_memberships
      WHERE user_id = ? AND agency_id = ?
      LIMIT 1
    `,
    [userId, agencyId],
  );

  if (existing[0]) {
    await conn.execute(
      `
        UPDATE agency_memberships
        SET membership_status = 'active',
            membership_role = 'representative',
            left_at = NULL
        WHERE id = ?
      `,
      [existing[0].id],
    );
    return;
  }

  await conn.execute(
    `
      INSERT INTO agency_memberships (
        public_uuid,
        user_id,
        agency_id,
        membership_role,
        membership_status
      )
      VALUES (?, ?, ?, 'representative', 'active')
    `,
    [membershipPublicUuid, userId, agencyId],
  );
}

export async function bootstrapDemoAgencyRepresentatives() {
  const password = process.env.DEMO_REP_PASSWORD;
  if (!password) {
    return;
  }

  if (password.length < 8) {
    console.warn("Skipping demo rep bootstrap. DEMO_REP_PASSWORD must be at least 8 characters.");
    return;
  }

  await ensureAgencyRepRoleAndPermissions();

  const repRole = await findRoleByCode(ROLE_CODES.AGENCY_REPRESENTATIVE);
  if (!repRole) {
    console.warn("Skipping demo rep bootstrap. agency_representative role not found.");
    return;
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const conn = await pool.getConnection();

  try {
    for (const rep of [...DEMO_REPS, ...KURIGRAM_DEMO_REPS]) {
      let user = await findUserByEmail(rep.email);

      if (!user) {
        await createUser({
          publicUuid: randomUUID(),
          email: rep.email,
          fullName: rep.fullName,
          phoneNumber: rep.phoneNumber,
          passwordHash,
        });
        user = await findUserByEmail(rep.email);
      } else {
        await updateUserPasswordHash(user.id, passwordHash);
      }

      if (!user) {
        continue;
      }

      const assigned = await hasRoleAssignment({
        userId: user.id,
        roleCode: ROLE_CODES.AGENCY_REPRESENTATIVE,
      });
      if (!assigned) {
        await assignRoleToUser({
          userId: user.id,
          roleId: repRole.id,
          assignedByUserId: null,
        });
      }

      const [agencyRows] = await conn.execute(
        `SELECT id FROM agencies WHERE public_uuid = ? LIMIT 1`,
        [rep.agencyPublicUuid],
      );
      const agency = agencyRows[0];
      if (!agency) {
        console.warn(`Skipping demo rep ${rep.email}: agency ${rep.agencyPublicUuid} not found.`);
        continue;
      }

      const [otherActive] = await conn.execute(
        `
          SELECT am.id
          FROM agency_memberships am
          WHERE am.user_id = ?
            AND am.agency_id <> ?
            AND am.membership_role = 'representative'
            AND am.membership_status = 'active'
          LIMIT 1
        `,
        [user.id, agency.id],
      );
      if (otherActive[0]) {
        console.warn(`Skipping membership for ${rep.email}: active representative membership exists elsewhere.`);
        continue;
      }

      await upsertMembership(conn, {
        userId: user.id,
        agencyId: agency.id,
        membershipPublicUuid: rep.membershipPublicUuid,
      });
    }

    console.log(
      "Bootstrapped demo agency representatives (Dhaka + relief/shelter.rep@niers.test).",
    );
  } finally {
    conn.release();
  }
}
