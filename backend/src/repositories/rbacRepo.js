import { query } from "../config/db.js";

export async function findRoleByCode(roleCode) {
  const result = await query(
    `
      SELECT id, role_code, name, description, is_system_role, created_at
      FROM roles
      WHERE role_code = ?
    `,
    [roleCode]
  );

  return result.rows[0] || null;
}

export async function findRolesByUserId(userId) {
  const result = await query(
    `
      SELECT r.id, r.role_code, r.name
      FROM user_roles ur
      INNER JOIN roles r ON r.id = ur.role_id
      WHERE ur.user_id = ?
      ORDER BY r.role_code ASC
    `,
    [userId]
  );

  return result.rows;
}

export async function findPermissionCodesByUserId(userId) {
  const result = await query(
    `
      SELECT DISTINCT p.permission_code
      FROM user_roles ur
      INNER JOIN role_permissions rp ON rp.role_id = ur.role_id
      INNER JOIN permissions p ON p.id = rp.permission_id
      WHERE ur.user_id = ?
      ORDER BY p.permission_code ASC
    `,
    [userId]
  );

  return result.rows.map((row) => row.permission_code);
}

export async function assignRoleToUser({ userId, roleId, assignedByUserId = null, conn = null }) {
  const sql = `
    INSERT INTO user_roles (user_id, role_id, assigned_by_user_id)
    VALUES (?, ?, ?)
  `;
  const params = [userId, roleId, assignedByUserId];
  if (conn) {
    await conn.execute(sql, params);
  } else {
    await query(sql, params);
  }
}

export async function removeRoleFromUser({ userId, roleCode, conn = null }) {
  const sql = `
    DELETE ur FROM user_roles ur
    INNER JOIN roles r ON r.id = ur.role_id
    WHERE ur.user_id = ? AND r.role_code = ?
  `;
  const params = [userId, roleCode];
  if (conn) {
    await conn.execute(sql, params);
  } else {
    await query(sql, params);
  }
}

export async function ensureRole({
  roleCode,
  name,
  description = null,
  isSystemRole = false,
}) {
  await query(
    `
      INSERT INTO roles (role_code, name, description, is_system_role)
      VALUES (?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        name = VALUES(name),
        description = VALUES(description),
        is_system_role = VALUES(is_system_role)
    `,
    [roleCode, name, description, isSystemRole]
  );
}

export async function ensurePermission({
  permissionCode,
  moduleName,
  description = null,
}) {
  await query(
    `
      INSERT INTO permissions (permission_code, module_name, description)
      VALUES (?, ?, ?)
      ON DUPLICATE KEY UPDATE
        module_name = VALUES(module_name),
        description = VALUES(description)
    `,
    [permissionCode, moduleName, description]
  );
}

export async function grantPermissionToRole({ roleCode, permissionCode }) {
  await query(
    `
      INSERT INTO role_permissions (role_id, permission_id)
      SELECT r.id, p.id
      FROM roles r
      INNER JOIN permissions p ON p.permission_code = ?
      WHERE r.role_code = ?
      ON DUPLICATE KEY UPDATE role_id = VALUES(role_id)
    `,
    [permissionCode, roleCode]
  );
}

export async function hasRoleAssignment({ userId, roleCode }) {
  const result = await query(
    `
      SELECT 1
      FROM user_roles ur
      INNER JOIN roles r ON r.id = ur.role_id
      WHERE ur.user_id = ? AND r.role_code = ?
      LIMIT 1
    `,
    [userId, roleCode]
  );

  return Boolean(result.rows[0]);
}

export async function hasAnyUserWithRole(roleCode) {
  const result = await query(
    `
      SELECT 1
      FROM user_roles ur
      INNER JOIN roles r ON r.id = ur.role_id
      WHERE r.role_code = ?
      LIMIT 1
    `,
    [roleCode]
  );

  return Boolean(result.rows[0]);
}

