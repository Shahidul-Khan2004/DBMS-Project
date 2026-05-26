-- ============================================================
-- Demo incident with agency participation and assigned dispatches
-- for agency representative field-demo (requires demo agencies/units)
-- ============================================================

SET @dhaka_area_id = (
  SELECT id FROM administrative_areas WHERE code = 'BD-DIV-6' LIMIT 1
);

SET @creator_user_id = (
  SELECT id FROM users ORDER BY id ASC LIMIT 1
);

SET @fire_category_id = (SELECT id FROM report_categories WHERE category_code = 'fire' LIMIT 1);
SET @severity_id = (SELECT id FROM incident_severity_levels WHERE severity_code = 'high' LIMIT 1);
SET @incident_status_id = (SELECT id FROM incident_statuses WHERE status_code = 'unit_assigned' LIMIT 1);
SET @assigned_dispatch_status_id = (SELECT id FROM dispatch_statuses WHERE status_code = 'assigned' LIMIT 1);

INSERT INTO locations (
  public_uuid,
  admin_area_id,
  latitude,
  longitude,
  geo_point,
  address_text,
  place_name,
  source
) VALUES (
  'a1000001-0000-4000-8000-000000000099',
  @dhaka_area_id,
  23.780800,
  90.400200,
  ST_SRID(POINT(90.400200, 23.780800), 4326),
  'Demo Multi-Agency Response Site, Dhaka',
  'Agency Rep Demo Site',
  'manual_entry'
)
ON DUPLICATE KEY UPDATE address_text = VALUES(address_text);

SET @demo_location_id = (SELECT id FROM locations WHERE public_uuid = 'a1000001-0000-4000-8000-000000000099' LIMIT 1);

INSERT INTO emergency_incidents (
  public_uuid,
  incident_code,
  category_id,
  severity_level_id,
  current_status_id,
  current_location_id,
  origin_type,
  title,
  description,
  created_by_user_id,
  reported_at
)
SELECT
  'e5000001-0000-4000-8000-000000000001',
  'EMI-DEMO-AGENCY-REP',
  @fire_category_id,
  @severity_id,
  @incident_status_id,
  @demo_location_id,
  'admin_created',
  'Agency representative demo incident',
  'Seeded incident for fire, police, and medical agency rep dispatch demos.',
  @creator_user_id,
  CURRENT_TIMESTAMP
FROM DUAL
WHERE @creator_user_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM emergency_incidents WHERE public_uuid = 'e5000001-0000-4000-8000-000000000001'
  );

SET @demo_incident_id = (
  SELECT id FROM emergency_incidents WHERE public_uuid = 'e5000001-0000-4000-8000-000000000001' LIMIT 1
);

INSERT INTO incident_agency_participation (
  incident_id,
  agency_id,
  is_lead_agency,
  participation_status,
  assigned_by_user_id
)
SELECT
  @demo_incident_id,
  a.id,
  CASE WHEN a.agency_code = 'DHK-FIRE-01' THEN 1 ELSE 0 END,
  'active',
  @creator_user_id
FROM agencies a
WHERE a.agency_code IN ('DHK-FIRE-01', 'DHK-POL-01', 'DHK-MED-01')
  AND @demo_incident_id IS NOT NULL
ON DUPLICATE KEY UPDATE participation_status = 'active';

INSERT INTO dispatches (
  public_uuid,
  incident_id,
  unit_id,
  assigned_by_user_id,
  current_status_id,
  priority_level
)
SELECT
  v.dispatch_uuid,
  @demo_incident_id,
  eu.id,
  @creator_user_id,
  @assigned_dispatch_status_id,
  'high'
FROM (
  SELECT 'f5000001-0000-4000-8000-000000000001' AS dispatch_uuid, 'c3000001-0000-4000-8000-000000000001' AS unit_uuid UNION ALL
  SELECT 'f5000001-0000-4000-8000-000000000002', 'c3000001-0000-4000-8000-000000000003' UNION ALL
  SELECT 'f5000001-0000-4000-8000-000000000003', 'c3000001-0000-4000-8000-000000000005'
) AS v
INNER JOIN emergency_units eu ON eu.public_uuid = v.unit_uuid
WHERE @demo_incident_id IS NOT NULL
  AND @creator_user_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM dispatches d
    INNER JOIN emergency_units eu2 ON eu2.id = d.unit_id
    WHERE d.incident_id = @demo_incident_id AND eu2.public_uuid = v.unit_uuid
  );

INSERT INTO dispatch_status_history (
  dispatch_id,
  status_id,
  changed_by_user_id,
  note
)
SELECT
  d.id,
  d.current_status_id,
  @creator_user_id,
  'Demo seed assigned dispatch'
FROM dispatches d
WHERE d.public_uuid IN (
  'f5000001-0000-4000-8000-000000000001',
  'f5000001-0000-4000-8000-000000000002',
  'f5000001-0000-4000-8000-000000000003'
)
AND NOT EXISTS (
  SELECT 1 FROM dispatch_status_history h WHERE h.dispatch_id = d.id
);

INSERT INTO incident_status_history (
  incident_id,
  status_id,
  changed_by_user_id,
  note
)
SELECT
  @demo_incident_id,
  @incident_status_id,
  @creator_user_id,
  'Demo seed incident at unit_assigned'
FROM DUAL
WHERE @demo_incident_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM incident_status_history h
    WHERE h.incident_id = @demo_incident_id AND h.status_id = @incident_status_id
  );

INSERT INTO unit_status_history (
  unit_id,
  status_id,
  changed_by_user_id,
  note
)
SELECT
  eu.id,
  us_busy.id,
  @creator_user_id,
  'Demo seed dispatch assignment'
FROM emergency_units eu
INNER JOIN unit_statuses us_busy ON us_busy.status_code = 'busy'
WHERE eu.public_uuid IN (
  'c3000001-0000-4000-8000-000000000001',
  'c3000001-0000-4000-8000-000000000003',
  'c3000001-0000-4000-8000-000000000005'
)
AND @demo_incident_id IS NOT NULL
AND EXISTS (
  SELECT 1 FROM dispatches d
  WHERE d.incident_id = @demo_incident_id AND d.unit_id = eu.id
)
AND NOT EXISTS (
  SELECT 1 FROM unit_status_history h
  INNER JOIN unit_statuses us ON us.id = h.status_id
  WHERE h.unit_id = eu.id AND us.status_code = 'busy'
    AND h.note = 'Demo seed dispatch assignment'
);
