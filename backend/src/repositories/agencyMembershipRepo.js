import { randomUUID } from "node:crypto";
import BackendError from "../lib/BackendError.js";
import {
  assignRoleToUser,
  findRoleByCode,
  hasRoleAssignment,
  removeRoleFromUser,
} from "./rbacRepo.js";
import { ROLE_CODES } from "../services/rbacService.js";

export async function assertNoOtherActiveRepresentativeMembership(conn, userId, agencyId) {
  const [rows] = await conn.execute(
    `
      SELECT am.public_uuid
      FROM agency_memberships am
      WHERE am.user_id = ?
        AND am.agency_id <> ?
        AND am.membership_role = 'representative'
        AND am.membership_status = 'active'
      LIMIT 1
    `,
    [userId, agencyId],
  );
  if (rows[0]) {
    throw new BackendError(
      409,
      "USER_ALREADY_REPRESENTATIVE",
      "User already has an active representative membership for another agency",
    );
  }
}

export async function deactivateActiveRepresentativeMembershipsForAgency(conn, agencyId) {
  const [userRows] = await conn.execute(
    `
      SELECT DISTINCT user_id
      FROM agency_memberships
      WHERE agency_id = ?
        AND membership_role = 'representative'
        AND membership_status = 'active'
    `,
    [agencyId],
  );

  if (userRows.length === 0) {
    return;
  }

  await conn.execute(
    `
      UPDATE agency_memberships
      SET membership_status = 'inactive',
          left_at = CURRENT_TIMESTAMP
      WHERE agency_id = ?
        AND membership_role = 'representative'
        AND membership_status = 'active'
    `,
    [agencyId],
  );

  for (const row of userRows) {
    await revokeAgencyRepresentativeRoleIfNoActiveMembership(conn, row.user_id);
  }
}

export async function revokeAgencyRepresentativeRoleIfNoActiveMembership(conn, userId) {
  const [rows] = await conn.execute(
    `
      SELECT 1
      FROM agency_memberships am
      WHERE am.user_id = ?
        AND am.membership_role = 'representative'
        AND am.membership_status = 'active'
      LIMIT 1
    `,
    [userId],
  );
  if (rows[0]) {
    return;
  }

  await removeRoleFromUser({
    userId,
    roleCode: ROLE_CODES.AGENCY_REPRESENTATIVE,
    conn,
  });
}

export async function ensureAgencyRepresentativeRole(conn, userId, assignedByUserId) {
  const role = await findRoleByCode(ROLE_CODES.AGENCY_REPRESENTATIVE);
  if (!role) {
    throw new BackendError(500, "INTERNAL_SERVER_ERROR", "agency_representative role is not configured");
  }

  const assigned = await hasRoleAssignment({
    userId,
    roleCode: ROLE_CODES.AGENCY_REPRESENTATIVE,
  });
  if (!assigned) {
    await assignRoleToUser({
      userId,
      roleId: role.id,
      assignedByUserId: assignedByUserId ?? null,
      conn,
    });
  }
}

export async function reactivateInactiveRepresentativeMembershipsForAgency(
  conn,
  agencyId,
  actorUserId,
) {
  const [userRows] = await conn.execute(
    `
      SELECT DISTINCT user_id
      FROM agency_memberships
      WHERE agency_id = ?
        AND membership_role = 'representative'
        AND membership_status = 'inactive'
    `,
    [agencyId],
  );

  if (userRows.length === 0) {
    return;
  }

  for (const row of userRows) {
    await assertNoOtherActiveRepresentativeMembership(conn, row.user_id, agencyId);
  }

  await conn.execute(
    `
      UPDATE agency_memberships
      SET membership_status = 'active',
          left_at = NULL,
          joined_at = CURRENT_TIMESTAMP
      WHERE agency_id = ?
        AND membership_role = 'representative'
        AND membership_status = 'inactive'
    `,
    [agencyId],
  );

  for (const row of userRows) {
    await ensureAgencyRepresentativeRole(conn, row.user_id, actorUserId);
  }
}

export async function upsertRepresentativeMembership(conn, {
  userId,
  agencyId,
  membershipPublicUuid,
}) {
  await assertNoOtherActiveRepresentativeMembership(conn, userId, agencyId);

  const [existing] = await conn.execute(
    `
      SELECT id, public_uuid, membership_status
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
        SET membership_role = 'representative',
            membership_status = 'active',
            left_at = NULL,
            joined_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `,
      [existing[0].id],
    );
    return existing[0].public_uuid;
  }

  const publicUuid = membershipPublicUuid ?? randomUUID();
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
    [publicUuid, userId, agencyId],
  );
  return publicUuid;
}

export function mapMembershipRow(row) {
  return {
    public_uuid: row.public_uuid,
    user_public_uuid: row.user_public_uuid,
    full_name: row.full_name,
    email: row.email,
    membership_role: row.membership_role,
    membership_status: row.membership_status,
    joined_at: row.joined_at,
    left_at: row.left_at,
  };
}
