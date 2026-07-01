DO $$
DECLARE
  v_dhaka_area_id BIGINT;
BEGIN
  -- ============================================================
  -- Demo agencies, locations, and emergency units for dispatch testing
  -- Stable public_uuid values are documented in docs/backend-api.md
  -- ============================================================
  SELECT id FROM administrative_areas WHERE code = 'BD-DIV-6' LIMIT 1 INTO v_dhaka_area_id;
  INSERT INTO locations (
    public_uuid,
    admin_area_id,
    latitude,
    longitude,
    geo_point,
    address_text,
    place_name,
    source
  ) VALUES
  (
    'a1000001-0000-4000-8000-000000000001',
    v_dhaka_area_id,
    23.810300,
    90.412500,
    ST_SetSRID(ST_MakePoint(90.412500, 23.810300), 4326)::geography,
    'Dhaka Central Fire Station, Motijheel',
    'Dhaka Fire HQ',
    'manual_entry'
  ),
  (
    'a1000001-0000-4000-8000-000000000002',
    v_dhaka_area_id,
    23.746100,
    90.374200,
    ST_SetSRID(ST_MakePoint(90.374200, 23.746100), 4326)::geography,
    'Dhanmondi Police Station, Road 27',
    'Dhanmondi Police',
    'manual_entry'
  ),
  (
    'a1000001-0000-4000-8000-000000000003',
    v_dhaka_area_id,
    23.778900,
    90.397500,
    ST_SetSRID(ST_MakePoint(90.397500, 23.778900), 4326)::geography,
    'Dhaka Medical College Hospital Ambulance Bay',
    'DMCH Ambulance',
    'manual_entry'
  ) ON CONFLICT DO NOTHING;
  INSERT INTO agencies (
    public_uuid,
    agency_type_id,
    agency_code,
    name,
    head_office_location_id,
    is_active
  )
  SELECT
    v.public_uuid,
    at.id,
    v.agency_code,
    v.name,
    l.id,
    TRUE
  FROM (
    SELECT 'b2000001-0000-4000-8000-000000000001' AS public_uuid, 'fire_service' AS type_code, 'DHK-FIRE-01' AS agency_code, 'Dhaka Fire Service' AS name, 'a1000001-0000-4000-8000-000000000001' AS location_uuid UNION ALL
    SELECT 'b2000001-0000-4000-8000-000000000002', 'police', 'DHK-POL-01', 'Dhaka Metropolitan Police', 'a1000001-0000-4000-8000-000000000002' UNION ALL
    SELECT 'b2000001-0000-4000-8000-000000000003', 'medical_service', 'DHK-MED-01', 'Dhaka Emergency Medical Services', 'a1000001-0000-4000-8000-000000000003'
  ) AS v
  INNER JOIN agency_types at ON at.type_code = v.type_code
  INNER JOIN locations l ON l.public_uuid = v.location_uuid ON CONFLICT DO NOTHING;
  INSERT INTO emergency_units (
    public_uuid,
    agency_id,
    unit_type_id,
    unit_code,
    unit_name,
    base_location_id,
    current_status_id,
    is_active
  )
  SELECT
    v.public_uuid,
    a.id,
    eut.id,
    v.unit_code,
    v.unit_name,
    a.head_office_location_id,
    us.id,
    TRUE
  FROM (
    SELECT 'c3000001-0000-4000-8000-000000000001' AS public_uuid, 'b2000001-0000-4000-8000-000000000001' AS agency_uuid, 'fire_truck' AS type_code, 'FIRE-01' AS unit_code, 'Fire Engine Alpha' AS unit_name, 'available' AS status_code UNION ALL
    SELECT 'c3000001-0000-4000-8000-000000000002', 'b2000001-0000-4000-8000-000000000001', 'fire_truck', 'FIRE-02', 'Fire Engine Bravo', 'available' UNION ALL
    SELECT 'c3000001-0000-4000-8000-000000000003', 'b2000001-0000-4000-8000-000000000002', 'police_vehicle', 'POL-01', 'Patrol Unit One', 'available' UNION ALL
    SELECT 'c3000001-0000-4000-8000-000000000004', 'b2000001-0000-4000-8000-000000000002', 'police_vehicle', 'POL-02', 'Patrol Unit Two', 'busy' UNION ALL
    SELECT 'c3000001-0000-4000-8000-000000000005', 'b2000001-0000-4000-8000-000000000003', 'ambulance', 'MED-01', 'Ambulance One', 'available' UNION ALL
    SELECT 'c3000001-0000-4000-8000-000000000006', 'b2000001-0000-4000-8000-000000000003', 'ambulance', 'MED-02', 'Ambulance Two', 'available' UNION ALL
    SELECT 'c3000001-0000-4000-8000-000000000007', 'b2000001-0000-4000-8000-000000000003', 'medical_van', 'MED-03', 'Medical Response Van', 'busy' UNION ALL
    SELECT 'c3000001-0000-4000-8000-000000000008', 'b2000001-0000-4000-8000-000000000001', 'command_vehicle', 'FIRE-CMD', 'Fire Command Vehicle', 'available'
  ) AS v
  INNER JOIN agencies a ON a.public_uuid = v.agency_uuid
  INNER JOIN emergency_unit_types eut ON eut.type_code = v.type_code
  INNER JOIN unit_statuses us ON us.status_code = v.status_code ON CONFLICT DO NOTHING;
END $$;