-- Run on existing databases created before agency_memberships.public_uuid was added.
-- Fresh docker-init from 09_agencies_and_units.sql already includes the column.

SET @has_col = (
  SELECT COUNT(*)
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'agency_memberships'
    AND COLUMN_NAME = 'public_uuid'
);

SET @sql = IF(
  @has_col = 0,
  'ALTER TABLE agency_memberships ADD COLUMN public_uuid CHAR(36) NULL AFTER id',
  'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

UPDATE agency_memberships
SET public_uuid = UUID()
WHERE public_uuid IS NULL;

SET @sql2 = IF(
  @has_col = 0,
  'ALTER TABLE agency_memberships MODIFY public_uuid CHAR(36) NOT NULL, ADD UNIQUE KEY uq_agency_memberships_public_uuid (public_uuid)',
  'SELECT 1'
);
PREPARE stmt2 FROM @sql2;
EXECUTE stmt2;
DEALLOCATE PREPARE stmt2;
