import { randomUUID } from "node:crypto";
import BackendError from "../lib/BackendError.js";
import { generateCode } from "../lib/generateCode.js";
import pool from "../config/db.js";
import { requireAdministrativeAreaInTransaction } from "../domain/locationAccess.js";
import { insertLocationInTransaction } from "./locationRepo.js";

export async function listFacilities({ activeOnly = false } = {}) {
  const [rows] = await pool.execute(
    `
      SELECT
        f.id,
        f.public_uuid AS publicUuid,
        f.facility_code AS facilityCode,
        f.name,
        ft.type_code AS facilityTypeCode,
        ft.name AS facilityTypeName,
        f.is_active AS isActive,
        l.public_uuid AS locationPublicUuid,
        l.latitude,
        l.longitude,
        l.address_text AS addressText,
        l.place_name AS placeName
      FROM facilities f
      JOIN facility_types ft ON ft.id = f.facility_type_id
      JOIN locations l ON l.id = f.location_id
      ${activeOnly ? "WHERE f.is_active = TRUE" : ""}
      ORDER BY f.name
    `,
  );
  return rows.map((r) => ({
    id: Number(r.id),
    publicUuid: r.publicUuid,
    facilityCode: r.facilityCode,
    name: r.name,
    facilityTypeCode: r.facilityTypeCode,
    facilityTypeName: r.facilityTypeName,
    isActive: Boolean(r.isActive),
    location: {
      publicUuid: r.locationPublicUuid,
      latitude: Number(r.latitude),
      longitude: Number(r.longitude),
      addressText: r.addressText,
      placeName: r.placeName ?? null,
    },
  }));
}

export async function getFacilityByPublicUuid(publicUuid) {
  const [rows] = await pool.execute(
    `
      SELECT
        f.id,
        f.public_uuid AS publicUuid,
        f.facility_code AS facilityCode,
        f.name,
        ft.type_code AS facilityTypeCode,
        f.is_active AS isActive,
        l.id AS locationId,
        l.public_uuid AS locationPublicUuid,
        l.admin_area_id AS adminAreaId,
        l.latitude,
        l.longitude,
        l.address_text AS addressText
      FROM facilities f
      JOIN facility_types ft ON ft.id = f.facility_type_id
      JOIN locations l ON l.id = f.location_id
      WHERE f.public_uuid = ?
      LIMIT 1
    `,
    [publicUuid],
  );
  if (!rows[0]) return null;
  const f = rows[0];
  const [caps] = await pool.execute(
    `
      SELECT c.capability_code AS capabilityCode, c.name
      FROM facility_capabilities fc
      JOIN capabilities c ON c.id = fc.capability_id
      WHERE fc.facility_id = ? AND fc.is_active = TRUE
    `,
    [f.id],
  );
  const [defaults] = await pool.execute(
    `
      SELECT capacity_type AS capacityType, total_capacity AS totalCapacity
      FROM facility_default_capacities
      WHERE facility_id = ?
    `,
    [f.id],
  );
  return {
    id: Number(f.id),
    publicUuid: f.publicUuid,
    facilityCode: f.facilityCode,
    name: f.name,
    facilityTypeCode: f.facilityTypeCode,
    isActive: Boolean(f.isActive),
    location: {
      publicUuid: f.locationPublicUuid,
      adminAreaId: f.adminAreaId != null ? Number(f.adminAreaId) : null,
      latitude: Number(f.latitude),
      longitude: Number(f.longitude),
      addressText: f.addressText,
    },
    capabilities: caps.map((c) => ({ capabilityCode: c.capabilityCode, name: c.name })),
    defaultCapacities: defaults.map((d) => ({
      capacityType: d.capacityType,
      totalCapacity: Number(d.totalCapacity),
    })),
  };
}

export async function createFacility(params) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [ft] = await conn.execute(
      `SELECT id FROM facility_types WHERE type_code = ? AND is_active = TRUE LIMIT 1`,
      [params.facilityTypeCode],
    );
    if (!ft[0]) {
      throw new BackendError(422, "FACILITY_TYPE_NOT_FOUND", "Invalid facility type");
    }
    if (params.location.admin_area_id != null) {
      await requireAdministrativeAreaInTransaction(conn, params.location.admin_area_id);
    }
    const loc = await insertLocationInTransaction(conn, {
      admin_area_id: params.location.admin_area_id ?? null,
      latitude: params.location.latitude,
      longitude: params.location.longitude,
      address_text: params.location.address_text,
      place_name: params.location.place_name ?? null,
      source: "manual_entry",
      created_by_user_id: params.actorUserId,
    });
    const publicUuid = randomUUID();
    const facilityCode = params.facilityCode ?? generateCode("FAC");
    const [result] = await conn.execute(
      `
        INSERT INTO facilities (
          public_uuid, facility_type_id, facility_code, name, location_id, is_active
        ) VALUES (?, ?, ?, ?, ?, TRUE)
      `,
      [publicUuid, ft[0].id, facilityCode, params.name, loc.id],
    );
    await conn.commit();
    return getFacilityByPublicUuid(publicUuid);
  } catch (e) {
    await conn.rollback();
    throw e;
  } finally {
    conn.release();
  }
}

export async function setFacilityCapabilities(facilityPublicUuid, capabilityCodes) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const facility = await loadFacilityId(conn, facilityPublicUuid);
    for (const code of capabilityCodes) {
      const [cap] = await conn.execute(
        `SELECT id FROM capabilities WHERE capability_code = ? LIMIT 1`,
        [code],
      );
      if (!cap[0]) {
        throw new BackendError(422, "CAPABILITY_NOT_FOUND", `Unknown capability: ${code}`);
      }
      await conn.execute(
        `
          INSERT INTO facility_capabilities (facility_id, capability_id, is_active)
          VALUES (?, ?, TRUE)
          ON DUPLICATE KEY UPDATE is_active = TRUE
        `,
        [facility.id, cap[0].id],
      );
    }
    await conn.commit();
    return getFacilityByPublicUuid(facilityPublicUuid);
  } catch (e) {
    await conn.rollback();
    throw e;
  } finally {
    conn.release();
  }
}

export async function setFacilityDefaultCapacities(facilityPublicUuid, capacities) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const facility = await loadFacilityId(conn, facilityPublicUuid);
    for (const cap of capacities) {
      await conn.execute(
        `
          INSERT INTO facility_default_capacities (facility_id, capacity_type, total_capacity)
          VALUES (?, ?, ?)
          ON DUPLICATE KEY UPDATE total_capacity = VALUES(total_capacity)
        `,
        [facility.id, cap.capacityType, cap.totalCapacity],
      );
    }
    await conn.commit();
    return getFacilityByPublicUuid(facilityPublicUuid);
  } catch (e) {
    await conn.rollback();
    throw e;
  } finally {
    conn.release();
  }
}

async function loadFacilityId(conn, publicUuid) {
  const [rows] = await conn.execute(
    `SELECT id FROM facilities WHERE public_uuid = ? LIMIT 1`,
    [publicUuid],
  );
  if (!rows[0]) {
    throw new BackendError(404, "FACILITY_NOT_FOUND", "Facility not found");
  }
  return { id: rows[0].id };
}
