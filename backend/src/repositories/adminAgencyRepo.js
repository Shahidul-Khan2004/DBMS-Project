import { randomUUID } from "node:crypto";
import BackendError from "../lib/BackendError.js";
import pool from "../config/db.js";
import { buildDistanceSortClause } from "../lib/geoListSql.js";
import { mapRowWithOptionalDistance } from "../lib/geoSortMap.js";
import { findUserByPublicUuid } from "./userRepo.js";
import { insertLocationInTransaction } from "./locationRepo.js";
import { deriveAddressAndSourceForLocation } from "../services/locationAddressService.js";
import { resolveAdminAreaIdForLocationPayload } from "../services/adminAreaFromGpsService.js";
import { requireAdministrativeAreaInTransaction } from "../domain/locationAccess.js";
import {
  deactivateActiveRepresentativeMembershipsForAgency,
  ensureAgencyRepresentativeRole,
  mapMembershipRow,
  reactivateInactiveRepresentativeMembershipsForAgency,
  revokeAgencyRepresentativeRoleIfNoActiveMembership,
  upsertRepresentativeMembership,
} from "./agencyMembershipRepo.js";

function mapAgencyRow(row) {
  return {
    public_uuid: row.public_uuid,
    agency_code: row.agency_code,
    name: row.name,
    description: row.description,
    agency_type_code: row.agency_type_code,
    is_active: Boolean(row.is_active),
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

function mapContactRow(row) {
  return {
    id: Number(row.id),
    contact_type: row.contact_type,
    contact_value: row.contact_value,
    label: row.label,
    is_primary: Boolean(row.is_primary),
    is_active: Boolean(row.is_active),
  };
}

function mapUnitSummaryRow(row) {
  return {
    public_uuid: row.public_uuid,
    unit_code: row.unit_code,
    unit_name: row.unit_name,
    unit_type_code: row.unit_type_code,
    status_code: row.status_code,
    is_active: Boolean(row.is_active),
  };
}

async function loadAgencyTypeId(conn, typeCode) {
  const [rows] = await conn.execute(
    `SELECT id FROM agency_types WHERE type_code = ? AND is_active = TRUE LIMIT 1`,
    [typeCode],
  );
  if (!rows[0]) {
    throw new BackendError(422, "VALIDATION_ERROR", "Invalid agency_type_code", [
      { field: "agency.agency_type_code", message: "Unknown agency type" },
    ]);
  }
  return rows[0].id;
}

async function loadAgencyByPublicUuid(conn, agencyPublicUuid, { activeOnly = false } = {}) {
  const [rows] = await conn.execute(
    `
      SELECT
        a.id,
        a.public_uuid,
        a.agency_code,
        a.name,
        a.description,
        a.is_active,
        a.created_at,
        a.updated_at,
        at.type_code AS agency_type_code
      FROM agencies a
      INNER JOIN agency_types at ON at.id = a.agency_type_id
      WHERE a.public_uuid = ?
      ${activeOnly ? "AND a.is_active = TRUE" : ""}
      LIMIT 1
    `,
    [agencyPublicUuid],
  );
  return rows[0] ?? null;
}

async function insertHeadOfficeLocation(conn, locationPayload, actorUserId) {
  if (!locationPayload) {
    return null;
  }

  let gpsResolvedAdminAreaId = null;
  if (locationPayload.admin_area_id == null) {
    const r = await resolveAdminAreaIdForLocationPayload({
      explicitAdminAreaId: null,
      latitude: locationPayload.latitude,
      longitude: locationPayload.longitude,
      pool,
    });
    gpsResolvedAdminAreaId = r.adminAreaId;
  }
  const derived = await deriveAddressAndSourceForLocation({
    latitude: locationPayload.latitude,
    longitude: locationPayload.longitude,
    addressText: locationPayload.address_text ?? null,
    source: locationPayload.source ?? "manual_entry",
  });
  const adminAreaId = locationPayload.admin_area_id ?? gpsResolvedAdminAreaId ?? null;
  if (adminAreaId != null) {
    await requireAdministrativeAreaInTransaction(conn, adminAreaId);
  }

  const inserted = await insertLocationInTransaction(conn, {
    admin_area_id: adminAreaId,
    latitude: locationPayload.latitude,
    longitude: locationPayload.longitude,
    address_text: derived.addressText,
    place_name: locationPayload.place_name ?? null,
    source: derived.source ?? locationPayload.source ?? "manual_entry",
    created_by_user_id: actorUserId ?? null,
  });
  return Number(inserted.id);
}

export async function listAgencies({ limit = 20, offset = 0, geoSort = null } = {}) {
  const safeLimit = Math.min(Math.max(limit, 1), 100);
  const safeOffset = Math.max(offset, 0);
  const useDistance = Boolean(geoSort?.ref);
  const distance = useDistance ? buildDistanceSortClause(geoSort.ref, "entity_loc.id") : null;

  const refJoinSql = useDistance
    ? `
      LEFT JOIN locations entity_loc ON entity_loc.id = a.head_office_location_id
      ${distance.joinSql}
    `
    : "";
  const distanceSelect = useDistance ? `, ${distance.selectDistanceSql}` : "";
  const orderSql = useDistance ? distance.orderBySql : "a.name";
  const joinParams = useDistance ? distance.joinParams : [];

  const [countRows] = await pool.execute(`SELECT COUNT(*) AS total FROM agencies`);
  const [rows] = await pool.execute(
    `
      SELECT
        a.public_uuid,
        a.agency_code,
        a.name,
        a.description,
        a.is_active,
        a.created_at,
        a.updated_at,
        at.type_code AS agency_type_code
        ${distanceSelect}
      FROM agencies a
      INNER JOIN agency_types at ON at.id = a.agency_type_id
      ${refJoinSql}
      ORDER BY ${orderSql}
      LIMIT ${safeLimit} OFFSET ${safeOffset}
    `,
    joinParams,
  );

  return {
    total: Number(countRows[0].total),
    limit: safeLimit,
    offset: safeOffset,
    agencies: rows.map((row) =>
      mapRowWithOptionalDistance(mapAgencyRow(row), row, geoSort),
    ),
  };
}

export async function getAgencyDetail(agencyPublicUuid) {
  const conn = await pool.getConnection();
  try {
    const agency = await loadAgencyByPublicUuid(conn, agencyPublicUuid);
    if (!agency) {
      throw new BackendError(404, "AGENCY_NOT_FOUND", "Agency not found");
    }

    const [repRows] = await conn.execute(
      `
        SELECT
          am.public_uuid,
          u.public_uuid AS user_public_uuid,
          up.full_name,
          u.email,
          am.membership_role,
          am.membership_status,
          am.joined_at,
          am.left_at
        FROM agency_memberships am
        INNER JOIN users u ON u.id = am.user_id
        LEFT JOIN user_profiles up ON up.user_id = u.id
        WHERE am.agency_id = ?
          AND am.membership_role = 'representative'
        ORDER BY am.joined_at DESC
      `,
      [agency.id],
    );

    const [unitRows] = await conn.execute(
      `
        SELECT
          eu.public_uuid,
          eu.unit_code,
          eu.unit_name,
          eut.type_code AS unit_type_code,
          us.status_code,
          eu.is_active
        FROM emergency_units eu
        INNER JOIN emergency_unit_types eut ON eut.id = eu.unit_type_id
        INNER JOIN unit_statuses us ON us.id = eu.current_status_id
        WHERE eu.agency_id = ?
        ORDER BY eu.unit_code
      `,
      [agency.id],
    );

    const [contactRows] = await conn.execute(
      `
        SELECT id, contact_type, contact_value, label, is_primary, is_active
        FROM agency_contacts
        WHERE agency_id = ?
        ORDER BY is_primary DESC, contact_type
      `,
      [agency.id],
    );

    return {
      agency: mapAgencyRow(agency),
      representatives: repRows.map(mapMembershipRow),
      units: unitRows.map(mapUnitSummaryRow),
      contacts: contactRows.map(mapContactRow),
    };
  } finally {
    conn.release();
  }
}

export async function patchAgency(agencyPublicUuid, patch) {
  const conn = await pool.getConnection();
  try {
    const agency = await loadAgencyByPublicUuid(conn, agencyPublicUuid);
    if (!agency) {
      throw new BackendError(404, "AGENCY_NOT_FOUND", "Agency not found");
    }

    if (patch.agency_code && patch.agency_code !== agency.agency_code) {
      const [conflict] = await conn.execute(
        `SELECT id FROM agencies WHERE agency_code = ? AND id <> ? LIMIT 1`,
        [patch.agency_code, agency.id],
      );
      if (conflict[0]) {
        throw new BackendError(409, "AGENCY_CODE_CONFLICT", "Agency code already exists");
      }
    }

    let headOfficeLocationId = null;
    if (patch.head_office_location) {
      headOfficeLocationId = await insertHeadOfficeLocation(
        conn,
        patch.head_office_location,
        patch.actorUserId,
      );
    }

    await conn.execute(
      `
        UPDATE agencies
        SET
          agency_code = COALESCE(?, agency_code),
          name = COALESCE(?, name),
          description = COALESCE(?, description),
          head_office_location_id = COALESCE(?, head_office_location_id)
        WHERE id = ?
      `,
      [
        patch.agency_code ?? null,
        patch.name ?? null,
        patch.description ?? null,
        headOfficeLocationId,
        agency.id,
      ],
    );

    const updated = await loadAgencyByPublicUuid(conn, agencyPublicUuid);
    return mapAgencyRow(updated);
  } finally {
    conn.release();
  }
}

export async function deactivateAgency(agencyPublicUuid) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const agency = await loadAgencyByPublicUuid(conn, agencyPublicUuid);
    if (!agency) {
      throw new BackendError(404, "AGENCY_NOT_FOUND", "Agency not found");
    }

    await conn.execute(
      `
        UPDATE agencies
        SET is_active = FALSE
        WHERE id = ?
      `,
      [agency.id],
    );

    await deactivateActiveRepresentativeMembershipsForAgency(conn, agency.id);

    await conn.commit();
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }

  return getAgencyDetail(agencyPublicUuid);
}

export async function activateAgency(agencyPublicUuid, actorUserId) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const agency = await loadAgencyByPublicUuid(conn, agencyPublicUuid);
    if (!agency) {
      throw new BackendError(404, "AGENCY_NOT_FOUND", "Agency not found");
    }

    await conn.execute(
      `
        UPDATE agencies
        SET is_active = TRUE
        WHERE id = ?
      `,
      [agency.id],
    );

    await reactivateInactiveRepresentativeMembershipsForAgency(conn, agency.id, actorUserId);

    await conn.commit();
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }

  return getAgencyDetail(agencyPublicUuid);
}

export async function onboardAgency(params) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    let agency;
    if (params.agencyPublicUuid) {
      agency = await loadAgencyByPublicUuid(conn, params.agencyPublicUuid);
      if (!agency) {
        throw new BackendError(404, "AGENCY_NOT_FOUND", "Agency not found");
      }
    } else {
      const agencyPayload = params.agency;
      const [codeConflict] = await conn.execute(
        `SELECT id FROM agencies WHERE agency_code = ? LIMIT 1`,
        [agencyPayload.agency_code],
      );
      if (codeConflict[0]) {
        throw new BackendError(409, "AGENCY_CODE_CONFLICT", "Agency code already exists");
      }

      const agencyTypeId = await loadAgencyTypeId(conn, agencyPayload.agency_type_code);
      const headOfficeLocationId = await insertHeadOfficeLocation(
        conn,
        agencyPayload.head_office_location,
        params.actorUserId,
      );

      const agencyPublicUuid = randomUUID();
      await conn.execute(
        `
          INSERT INTO agencies (
            public_uuid,
            agency_type_id,
            agency_code,
            name,
            description,
            head_office_location_id,
            is_active
          )
          VALUES (?, ?, ?, ?, ?, ?, TRUE)
        `,
        [
          agencyPublicUuid,
          agencyTypeId,
          agencyPayload.agency_code,
          agencyPayload.name,
          agencyPayload.description ?? null,
          headOfficeLocationId,
        ],
      );
      agency = await loadAgencyByPublicUuid(conn, agencyPublicUuid);
    }

    if (!params.userPublicUuid) {
      await conn.commit();
      return { agency: mapAgencyRow(agency) };
    }

    const user = await findUserByPublicUuid(params.userPublicUuid);
    if (!user) {
      throw new BackendError(404, "USER_NOT_FOUND", "User not found");
    }

    const membershipPublicUuid = await upsertRepresentativeMembership(conn, {
      userId: user.id,
      agencyId: agency.id,
    });
    await ensureAgencyRepresentativeRole(conn, user.id, params.actorUserId);

    await conn.commit();

    return {
      agency: mapAgencyRow(agency),
      membership_public_uuid: membershipPublicUuid,
      user_public_uuid: user.public_uuid,
    };
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

export async function linkAgencyRepresentative(agencyPublicUuid, userPublicUuid, actorUserId) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const agency = await loadAgencyByPublicUuid(conn, agencyPublicUuid, { activeOnly: true });
    if (!agency) {
      throw new BackendError(404, "AGENCY_NOT_FOUND", "Agency not found");
    }

    const user = await findUserByPublicUuid(userPublicUuid);
    if (!user) {
      throw new BackendError(404, "USER_NOT_FOUND", "User not found");
    }

    const membershipPublicUuid = await upsertRepresentativeMembership(conn, {
      userId: user.id,
      agencyId: agency.id,
    });
    await ensureAgencyRepresentativeRole(conn, user.id, actorUserId);

    await conn.commit();

    const [membershipRow] = await pool.execute(
      `
        SELECT
          am.public_uuid,
          u.public_uuid AS user_public_uuid,
          up.full_name,
          u.email,
          am.membership_role,
          am.membership_status,
          am.joined_at,
          am.left_at
        FROM agency_memberships am
        INNER JOIN users u ON u.id = am.user_id
        LEFT JOIN user_profiles up ON up.user_id = u.id
        WHERE am.public_uuid = ?
        LIMIT 1
      `,
      [membershipPublicUuid],
    );

    return mapMembershipRow(membershipRow[0]);
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }
}

export async function listAgencyRepresentatives(agencyPublicUuid) {
  const conn = await pool.getConnection();
  try {
    const agency = await loadAgencyByPublicUuid(conn, agencyPublicUuid);
    if (!agency) {
      throw new BackendError(404, "AGENCY_NOT_FOUND", "Agency not found");
    }

    const [rows] = await conn.execute(
      `
        SELECT
          am.public_uuid,
          u.public_uuid AS user_public_uuid,
          up.full_name,
          u.email,
          am.membership_role,
          am.membership_status,
          am.joined_at,
          am.left_at
        FROM agency_memberships am
        INNER JOIN users u ON u.id = am.user_id
        LEFT JOIN user_profiles up ON up.user_id = u.id
        WHERE am.agency_id = ?
          AND am.membership_role = 'representative'
        ORDER BY am.joined_at DESC
      `,
      [agency.id],
    );

    return {
      agency_public_uuid: agency.public_uuid,
      representatives: rows.map(mapMembershipRow),
    };
  } finally {
    conn.release();
  }
}

export async function deactivateMembership(membershipPublicUuid) {
  const conn = await pool.getConnection();
  let membershipId;
  try {
    await conn.beginTransaction();

    const [rows] = await conn.execute(
      `
        SELECT id, user_id, membership_status
        FROM agency_memberships
        WHERE public_uuid = ?
        LIMIT 1
      `,
      [membershipPublicUuid],
    );
    const membership = rows[0];
    if (!membership) {
      throw new BackendError(404, "MEMBERSHIP_NOT_FOUND", "Agency membership not found");
    }
    if (["inactive", "left", "suspended"].includes(membership.membership_status)) {
      throw new BackendError(409, "MEMBERSHIP_ALREADY_INACTIVE", "Membership is already inactive");
    }

    await conn.execute(
      `
        UPDATE agency_memberships
        SET membership_status = 'inactive',
            left_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `,
      [membership.id],
    );

    await revokeAgencyRepresentativeRoleIfNoActiveMembership(conn, membership.user_id);

    await conn.commit();
    membershipId = membership.id;
  } catch (error) {
    await conn.rollback();
    throw error;
  } finally {
    conn.release();
  }

  const [updated] = await pool.execute(
    `
      SELECT
        am.public_uuid,
        u.public_uuid AS user_public_uuid,
        up.full_name,
        u.email,
        am.membership_role,
        am.membership_status,
        am.joined_at,
        am.left_at
      FROM agency_memberships am
      INNER JOIN users u ON u.id = am.user_id
      LEFT JOIN user_profiles up ON up.user_id = u.id
      WHERE am.id = ?
      LIMIT 1
    `,
    [membershipId],
  );

  return mapMembershipRow(updated[0]);
}
