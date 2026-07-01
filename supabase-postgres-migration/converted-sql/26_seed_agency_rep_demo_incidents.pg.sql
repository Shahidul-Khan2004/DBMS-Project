DO $$
DECLARE
  v_dhaka_area_id BIGINT;
  v_creator_user_id BIGINT;
  v_fire_category_id BIGINT;
  v_severity_id BIGINT;
  v_incident_status_id BIGINT;
  v_assigned_dispatch_status_id BIGINT;
  v_demo_location_id BIGINT;
  v_demo_incident_id BIGINT;
BEGIN
  -- ============================================================
  -- Demo incident with agency participation and assigned dispatches
  -- for agency representative field-demo (requires demo agencies/units)
  -- ============================================================
  SELECT id FROM administrative_areas WHERE code = 'BD-DIV-6' LIMIT 1 INTO v_dhaka_area_id;
  SELECT id FROM users ORDER BY id ASC LIMIT 1 INTO v_creator_user_id;
  SELECT id FROM report_categories WHERE category_code = 'fire' LIMIT 1 INTO v_fire_category_id;
  SELECT id FROM incident_severity_levels WHERE severity_code = 'high' LIMIT 1 INTO v_severity_id;
  SELECT id FROM incident_statuses WHERE status_code = 'unit_assigned' LIMIT 1 INTO v_incident_status_id;
  SELECT id FROM dispatch_statuses WHERE status_code = 'assigned' LIMIT 1 INTO v_assigned_dispatch_status_id;
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
    v_dhaka_area_id,
    23.780800,
    90.400200,
    ST_SetSRID(ST_MakePoint(90.400200, 23.780800), 4326)::geography,
    'Demo Multi-Agency Response Site, Dhaka',
    'Agency Rep Demo Site',
    'manual_entry'
  )
  ON CONFLICT DO UPDATE SET address_text = EXCLUDED.address_text;
  SELECT id FROM locations WHERE public_uuid = 'a1000001-0000-4000-8000-000000000099' LIMIT 1 INTO v_demo_location_id;
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
    v_fire_category_id,
    v_severity_id,
    v_incident_status_id,
    v_demo_location_id,
    'admin_created',
    'Agency representative demo incident',
    'Seeded incident for fire, police, and medical agency rep dispatch demos.',
    v_creator_user_id,
    CURRENT_TIMESTAMP
  WHERE v_creator_user_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM emergency_incidents WHERE public_uuid = 'e5000001-0000-4000-8000-000000000001'
    );
  v_demo_incident_id := (
    SELECT id FROM emergency_incidents WHERE public_uuid = 'e5000001-0000-4000-8000-000000000001' LIMIT 1
  ) ON CONFLICT DO NOTHING;
  INSERT INTO incident_agency_participation (
    incident_id,
    agency_id,
    is_lead_agency,
    participation_status,
    assigned_by_user_id
  )
  SELECT
    v_demo_incident_id,
    a.id,
    CASE WHEN a.agency_code = 'DHK-FIRE-01' THEN 1 ELSE 0 END,
    'active',
    v_creator_user_id
  FROM agencies a
  WHERE a.agency_code IN ('DHK-FIRE-01', 'DHK-POL-01', 'DHK-MED-01')
    AND v_demo_incident_id IS NOT NULL
  ON CONFLICT DO UPDATE SET participation_status = 'active';
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
    v_demo_incident_id,
    eu.id,
    v_creator_user_id,
    v_assigned_dispatch_status_id,
    'high'
  FROM (
    SELECT 'f5000001-0000-4000-8000-000000000001' AS dispatch_uuid, 'c3000001-0000-4000-8000-000000000001' AS unit_uuid UNION ALL
    SELECT 'f5000001-0000-4000-8000-000000000002', 'c3000001-0000-4000-8000-000000000003' UNION ALL
    SELECT 'f5000001-0000-4000-8000-000000000003', 'c3000001-0000-4000-8000-000000000005'
  ) AS v
  INNER JOIN emergency_units eu ON eu.public_uuid = v.unit_uuid
  WHERE v_demo_incident_id IS NOT NULL
    AND v_creator_user_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM dispatches d
      INNER JOIN emergency_units eu2 ON eu2.id = d.unit_id
      WHERE d.incident_id = v_demo_incident_id AND eu2.public_uuid = v.unit_uuid
    ) ON CONFLICT DO NOTHING;
  INSERT INTO dispatch_status_history (
    dispatch_id,
    status_id,
    changed_by_user_id,
    note
  )
  SELECT
    d.id,
    d.current_status_id,
    v_creator_user_id,
    'Demo seed assigned dispatch'
  FROM dispatches d
  WHERE d.public_uuid IN (
    'f5000001-0000-4000-8000-000000000001',
    'f5000001-0000-4000-8000-000000000002',
    'f5000001-0000-4000-8000-000000000003'
  )
  AND NOT EXISTS (
    SELECT 1 FROM dispatch_status_history h WHERE h.dispatch_id = d.id
  ) ON CONFLICT DO NOTHING;
  INSERT INTO incident_status_history (
    incident_id,
    status_id,
    changed_by_user_id,
    note
  )
  SELECT
    v_demo_incident_id,
    v_incident_status_id,
    v_creator_user_id,
    'Demo seed incident at unit_assigned'
  WHERE v_demo_incident_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM incident_status_history h
      WHERE h.incident_id = v_demo_incident_id AND h.status_id = v_incident_status_id
    ) ON CONFLICT DO NOTHING;
  INSERT INTO unit_status_history (
    unit_id,
    status_id,
    changed_by_user_id,
    note
  )
  SELECT
    eu.id,
    us_busy.id,
    v_creator_user_id,
    'Demo seed dispatch assignment'
  FROM emergency_units eu
  INNER JOIN unit_statuses us_busy ON us_busy.status_code = 'busy'
  WHERE eu.public_uuid IN (
    'c3000001-0000-4000-8000-000000000001',
    'c3000001-0000-4000-8000-000000000003',
    'c3000001-0000-4000-8000-000000000005'
  )
  AND v_demo_incident_id IS NOT NULL
  AND EXISTS (
    SELECT 1 FROM dispatches d
    WHERE d.incident_id = v_demo_incident_id AND d.unit_id = eu.id
  )
  AND NOT EXISTS (
    SELECT 1 FROM unit_status_history h
    INNER JOIN unit_statuses us ON us.id = h.status_id
    WHERE h.unit_id = eu.id AND us.status_code = 'busy'
      AND h.note = 'Demo seed dispatch assignment'
  ) ON CONFLICT DO NOTHING;
END $$;