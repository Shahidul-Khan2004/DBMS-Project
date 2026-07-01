-- from 23_seed_notification_templates.sql
-- ============================================================
-- Seed: notification_templates
-- ============================================================
-- One in_app + one email template per notification event.
-- template_code convention: <event>__<channel>
-- Subject/body use {{placeholder}} tokens that notificationRepo
-- resolves at runtime before inserting into notifications.
-- ============================================================

INSERT INTO notification_templates (template_code, channel, subject_template, body_template, is_active) VALUES

-- ── Intake received ──────────────────────────────────────────
('intake_received__in_app',  'in_app', NULL,
 'Your report ({{report_code}}) has been received. We will review it shortly.',
 TRUE),

('intake_received__email',   'email',
 'We received your report {{report_code}}',
 'Hello,\n\nThank you for submitting your report.\n\nWe have received your report with reference code {{report_code}}. Our team will review the information you provided and take the necessary next steps.\n\nYou will be notified when there is an update on your report. Please keep this reference code for future communication.\n\nThank you,\nNIERS Support Team',
 TRUE),

-- ── Intake classified as service case ────────────────────────
('intake_classified__in_app', 'in_app', NULL,
 'Your report has been reviewed and a service case ({{case_code}}) has been opened. Our team will follow up with you.',
 TRUE),

('intake_classified__email',  'email',
 'Your report has been reviewed {{case_code}}',
 'Hello,\n\nYour report has been reviewed by our team, and a service case has been opened for further follow-up.\n\nService case reference: {{case_code}}\n\nOur team will review the details and take appropriate action based on the information provided. You will be notified if further updates or actions are required.\n\nThank you for helping us improve public service response.\n\nRegards,\nNIERS Support Team',
 TRUE),

-- ── Intake escalated to emergency (both paths) ───────────────
('intake_escalated__in_app', 'in_app', NULL,
 'Your report has been escalated to emergency incident {{incident_code}}. Emergency responders have been notified.',
 TRUE),

('intake_escalated__email',  'email',
 'Emergency escalation {{incident_code}}',
 'Hello,\n\nYour report has been escalated to an emergency incident.\n\nIncident reference: {{incident_code}}\n\nEmergency responders have been notified, and the incident is now being handled through the emergency response process. Please remain safe and follow any instructions provided by authorized emergency personnel.\n\nRegards,\nNIERS Emergency Response Team',
 TRUE),

-- ── Incident created (standalone) ────────────────────────────
('incident_created__in_app', 'in_app', NULL,
 'Emergency incident {{incident_code}} has been created and is now active.',
 TRUE),

('incident_created__email',  'email',
 'Incident created {{incident_code}}',
 'Hello,\n\nA new emergency incident has been created and is now active.\n\nIncident reference: {{incident_code}}\n\nThe incident has been recorded in the system and can now be tracked by the responsible operations team. Further updates will be recorded as the incident progresses.\n\nRegards,\nNIERS Operations Team',
 TRUE),

-- ── Incident status updated ───────────────────────────────────
('incident_status_updated__in_app', 'in_app', NULL,
 'Incident {{incident_code}} has been updated from ''{{from_status}}'' to ''{{to_status}}''.{{note_line}}',
 TRUE),

('incident_status_updated__email',  'email',
 'Incident {{incident_code}} status update',
 'Hello,\n\nThere has been a status update for emergency incident {{incident_code}}.\n\nPrevious status: {{from_status}}\nNew status: {{to_status}}{{note_line}}\n\nThis update has been recorded by the operations team. Further action will continue according to the current incident status.\n\nRegards,\nNIERS Operations Team',
 TRUE) ON CONFLICT DO NOTHING;

-- from 24_seed_agencies_units_demo.sql
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

-- from 25_seed_agency_reps_demo.sql
DO $$
DECLARE

BEGIN
  -- ============================================================
  -- Demo agency representative memberships (users from bootstrap)
  -- Stable membership public_uuid values documented in docs/backend-api.md
  -- ============================================================
  INSERT INTO agency_memberships (
    public_uuid,
    user_id,
    agency_id,
    membership_role,
    membership_status
  )
  SELECT
    v.membership_uuid,
    u.id,
    a.id,
    'representative',
    'active'
  FROM (
    SELECT 'd4000001-0000-4000-8000-000000000001' AS membership_uuid, 'fire.rep@niers.test' AS email, 'b2000001-0000-4000-8000-000000000001' AS agency_uuid UNION ALL
    SELECT 'd4000001-0000-4000-8000-000000000002', 'police.rep@niers.test', 'b2000001-0000-4000-8000-000000000002' UNION ALL
    SELECT 'd4000001-0000-4000-8000-000000000003', 'medical.rep@niers.test', 'b2000001-0000-4000-8000-000000000003'
  ) AS v
  INNER JOIN users u ON u.email = v.email
  INNER JOIN agencies a ON a.public_uuid = v.agency_uuid
  ON CONFLICT DO UPDATE SET membership_status = 'active',
    left_at = NULL;
END $$;

-- from 26_seed_agency_rep_demo_incidents.sql
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

-- from 28_seed_disaster_demo_master.sql
DO $$
DECLARE
  v_kurigram_sadar_upazila BIGINT;
  v_chilmari_upazila BIGINT;
  v_ulipur_upazila BIGINT;
  v_nageshwari_upazila BIGINT;
BEGIN
  -- ============================================================
  -- Kurigram-area demo agencies, units, and facilities (no disaster ops data)
  -- ============================================================
  SELECT id FROM administrative_areas WHERE code = 'BD-UPZ-448' LIMIT 1 INTO v_kurigram_sadar_upazila;
  SELECT id FROM administrative_areas WHERE code = 'BD-UPZ-454' LIMIT 1 INTO v_chilmari_upazila;
  SELECT id FROM administrative_areas WHERE code = 'BD-UPZ-453' LIMIT 1 INTO v_ulipur_upazila;
  SELECT id FROM administrative_areas WHERE code = 'BD-UPZ-449' LIMIT 1 INTO v_nageshwari_upazila;
  INSERT INTO locations (
    public_uuid, admin_area_id, latitude, longitude, geo_point, address_text, place_name, source
  ) VALUES
  (
    'a2000001-0000-4000-8000-000000000001',
    v_kurigram_sadar_upazila, 25.805000, 89.636400,
    ST_SetSRID(ST_MakePoint(89.636400, 25.805000), 4326)::geography,
    'Kurigram District Disaster Management Office', 'Kurigram DDMO', 'manual_entry'
  ),
  (
    'a2000001-0000-4000-8000-000000000002',
    v_kurigram_sadar_upazila, 25.810000, 89.640000,
    ST_SetSRID(ST_MakePoint(89.640000, 25.810000), 4326)::geography,
    'Red Crescent Kurigram Unit', 'Red Crescent Kurigram', 'manual_entry'
  ),
  (
    'a2000001-0000-4000-8000-000000000003',
    v_chilmari_upazila, 25.580000, 89.670000,
    ST_SetSRID(ST_MakePoint(89.670000, 25.580000), 4326)::geography,
    'Kurigram Fire Service Station, Chilmari', 'Chilmari Fire', 'manual_entry'
  ),
  (
    'a2000001-0000-4000-8000-000000000004',
    v_kurigram_sadar_upazila, 25.800000, 89.630000,
    ST_SetSRID(ST_MakePoint(89.630000, 25.800000), 4326)::geography,
    'Kurigram EMS Depot', 'Kurigram EMS', 'manual_entry'
  ),
  (
    'a2000001-0000-4000-8000-000000000005',
    v_ulipur_upazila, 25.850000, 89.550000,
    ST_SetSRID(ST_MakePoint(89.550000, 25.850000), 4326)::geography,
    'Ulipur Police Station', 'Ulipur Police', 'manual_entry'
  ),
  (
    'a2000001-0000-4000-8000-000000000010',
    v_kurigram_sadar_upazila, 25.812000, 89.638000,
    ST_SetSRID(ST_MakePoint(89.638000, 25.812000), 4326)::geography,
    'Kurigram Government College', 'Kurigram Govt College', 'manual_entry'
  ),
  (
    'a2000001-0000-4000-8000-000000000011',
    v_chilmari_upazila, 25.575000, 89.665000,
    ST_SetSRID(ST_MakePoint(89.665000, 25.575000), 4326)::geography,
    'Chilmari High School Shelter', 'Chilmari School Shelter', 'manual_entry'
  ),
  (
    'a2000001-0000-4000-8000-000000000012',
    v_nageshwari_upazila, 25.900000, 89.700000,
    ST_SetSRID(ST_MakePoint(89.700000, 25.900000), 4326)::geography,
    'Nageshwari Community Centre', 'Nageshwari Community Centre', 'manual_entry'
  ),
  (
    'a2000001-0000-4000-8000-000000000013',
    v_kurigram_sadar_upazila, 25.803000, 89.635000,
    ST_SetSRID(ST_MakePoint(89.635000, 25.803000), 4326)::geography,
    'Kurigram General Hospital', 'Kurigram Hospital', 'manual_entry'
  ),
  (
    'a2000001-0000-4000-8000-000000000014',
    v_ulipur_upazila, 25.848000, 89.552000,
    ST_SetSRID(ST_MakePoint(89.552000, 25.848000), 4326)::geography,
    'Ulipur Relief Warehouse', 'Ulipur Relief Warehouse', 'manual_entry'
  ) ON CONFLICT DO NOTHING;
  INSERT INTO agencies (public_uuid, agency_type_id, agency_code, name, head_office_location_id, is_active)
  SELECT v.public_uuid, at.id, v.agency_code, v.name, l.id, TRUE
  FROM (
    SELECT 'b3000001-0000-4000-8000-000000000001' AS public_uuid, 'disaster_management' AS type_code, 'KUR-DDMO-01' AS agency_code, 'District Disaster Management & Relief Office' AS name, 'a2000001-0000-4000-8000-000000000001' AS loc UNION ALL
    SELECT 'b3000001-0000-4000-8000-000000000002', 'ngo', 'KUR-RC-01', 'Red Crescent Response Unit', 'a2000001-0000-4000-8000-000000000002' UNION ALL
    SELECT 'b3000001-0000-4000-8000-000000000003', 'fire_service', 'KUR-FIRE-01', 'Kurigram Fire Service', 'a2000001-0000-4000-8000-000000000003' UNION ALL
    SELECT 'b3000001-0000-4000-8000-000000000004', 'medical_service', 'KUR-MED-01', 'Kurigram Emergency Medical Services', 'a2000001-0000-4000-8000-000000000004' UNION ALL
    SELECT 'b3000001-0000-4000-8000-000000000005', 'police', 'KUR-POL-01', 'Kurigram Police Response Unit', 'a2000001-0000-4000-8000-000000000005'
  ) AS v
  INNER JOIN agency_types at ON at.type_code = v.type_code
  INNER JOIN locations l ON l.public_uuid = v.loc ON CONFLICT DO NOTHING;
  INSERT INTO emergency_units (public_uuid, agency_id, unit_type_id, unit_code, unit_name, base_location_id, current_status_id, is_active)
  SELECT v.public_uuid, a.id, eut.id, v.unit_code, v.unit_name, a.head_office_location_id, us.id, TRUE
  FROM (
    SELECT 'c4000001-0000-4000-8000-000000000001' AS public_uuid, 'b3000001-0000-4000-8000-000000000003' AS agency_uuid, 'fire_truck' AS type_code, 'KUR-FIRE-01' AS unit_code, 'Fire Engine Alpha' AS unit_name, 'available' AS status UNION ALL
    SELECT 'c4000001-0000-4000-8000-000000000002', 'b3000001-0000-4000-8000-000000000003', 'rescue_boat', 'KUR-BOAT-01', 'Rescue Boat Unit 01', 'available' UNION ALL
    SELECT 'c4000001-0000-4000-8000-000000000003', 'b3000001-0000-4000-8000-000000000003', 'command_vehicle', 'KUR-FIRE-CMD', 'Fire Command Vehicle', 'available' UNION ALL
    SELECT 'c4000001-0000-4000-8000-000000000004', 'b3000001-0000-4000-8000-000000000004', 'ambulance', 'KUR-MED-01', 'Ambulance One', 'available' UNION ALL
    SELECT 'c4000001-0000-4000-8000-000000000005', 'b3000001-0000-4000-8000-000000000004', 'ambulance', 'KUR-MED-02', 'Ambulance Two', 'available' UNION ALL
    SELECT 'c4000001-0000-4000-8000-000000000006', 'b3000001-0000-4000-8000-000000000004', 'medical_van', 'KUR-MED-VAN', 'Mobile Medical Response Van', 'available' UNION ALL
    SELECT 'c4000001-0000-4000-8000-000000000007', 'b3000001-0000-4000-8000-000000000005', 'police_vehicle', 'KUR-POL-01', 'Patrol Unit One', 'available' UNION ALL
    SELECT 'c4000001-0000-4000-8000-000000000008', 'b3000001-0000-4000-8000-000000000005', 'police_vehicle', 'KUR-POL-02', 'Evacuation Security Vehicle', 'available' UNION ALL
    SELECT 'c4000001-0000-4000-8000-000000000009', 'b3000001-0000-4000-8000-000000000002', 'relief_truck', 'KUR-RC-VAN', 'Shelter Assessment Van', 'available' UNION ALL
    SELECT 'c4000001-0000-4000-8000-000000000010', 'b3000001-0000-4000-8000-000000000002', 'relief_truck', 'KUR-RC-TRUCK', 'Relief Transport Truck', 'available' UNION ALL
    SELECT 'c4000001-0000-4000-8000-000000000011', 'b3000001-0000-4000-8000-000000000001', 'relief_truck', 'KUR-DDMO-TRUCK', 'Supply Logistics Truck', 'available' UNION ALL
    SELECT 'c4000001-0000-4000-8000-000000000012', 'b3000001-0000-4000-8000-000000000001', 'command_vehicle', 'KUR-DDMO-CMD', 'Mobile Coordination Vehicle', 'available'
  ) AS v
  INNER JOIN agencies a ON a.public_uuid = v.agency_uuid
  INNER JOIN emergency_unit_types eut ON eut.type_code = v.type_code
  INNER JOIN unit_statuses us ON us.status_code = v.status ON CONFLICT DO NOTHING;
  INSERT INTO facilities (public_uuid, facility_type_id, facility_code, name, location_id, is_active)
  SELECT v.public_uuid, ft.id, v.facility_code, v.name, l.id, TRUE
  FROM (
    SELECT 'f6000001-0000-4000-8000-000000000001' AS public_uuid, 'school_shelter_capable' AS type_code, 'KUR-SCH-01' AS facility_code, 'Kurigram Government College Shelter' AS name, 'a2000001-0000-4000-8000-000000000010' AS loc UNION ALL
    SELECT 'f6000001-0000-4000-8000-000000000002', 'school_shelter_capable', 'KUR-SCH-02', 'Chilmari High School Shelter', 'a2000001-0000-4000-8000-000000000011' UNION ALL
    SELECT 'f6000001-0000-4000-8000-000000000003', 'community_center', 'KUR-CC-01', 'Nageshwari Community Centre', 'a2000001-0000-4000-8000-000000000012' UNION ALL
    SELECT 'f6000001-0000-4000-8000-000000000004', 'hospital', 'KUR-HOS-01', 'Kurigram General Hospital', 'a2000001-0000-4000-8000-000000000013' UNION ALL
    SELECT 'f6000001-0000-4000-8000-000000000005', 'warehouse', 'KUR-WH-01', 'Ulipur Relief Distribution Warehouse', 'a2000001-0000-4000-8000-000000000014' UNION ALL
    SELECT 'f6000001-0000-4000-8000-000000000006', 'relief_center', 'KUR-RC-HUB', 'Kurigram Sadar Relief Hub', 'a2000001-0000-4000-8000-000000000002'
  ) AS v
  INNER JOIN facility_types ft ON ft.type_code = v.type_code
  INNER JOIN locations l ON l.public_uuid = v.loc ON CONFLICT DO NOTHING;
  INSERT INTO facility_capabilities (facility_id, capability_id, is_active)
  SELECT f.id, c.id, TRUE
  FROM facilities f
  INNER JOIN capabilities c ON c.capability_code = 'temporary_shelter'
  WHERE f.facility_code IN ('KUR-SCH-01', 'KUR-SCH-02', 'KUR-CC-01') ON CONFLICT DO NOTHING;
  INSERT INTO facility_capabilities (facility_id, capability_id, is_active)
  SELECT f.id, c.id, TRUE
  FROM facilities f
  INNER JOIN capabilities c ON c.capability_code = 'relief_distribution_hub'
  WHERE f.facility_code IN ('KUR-WH-01', 'KUR-RC-HUB') ON CONFLICT DO NOTHING;
  INSERT INTO facility_default_capacities (facility_id, capacity_type, total_capacity)
  SELECT f.id, 'shelter_people', v.cap
  FROM (
    SELECT 'KUR-SCH-01' AS code, 800 AS cap UNION ALL
    SELECT 'KUR-SCH-02', 500 UNION ALL
    SELECT 'KUR-CC-01', 350
  ) AS v
  INNER JOIN facilities f ON f.facility_code = v.code ON CONFLICT DO NOTHING;
  INSERT INTO facility_default_capacities (facility_id, capacity_type, total_capacity)
  SELECT f.id, 'hospital_beds', 120
  FROM facilities f WHERE f.facility_code = 'KUR-HOS-01' ON CONFLICT DO NOTHING;
  INSERT INTO facility_default_capacities (facility_id, capacity_type, total_capacity)
  SELECT f.id, 'emergency_beds', 24
  FROM facilities f WHERE f.facility_code = 'KUR-HOS-01' ON CONFLICT DO NOTHING;
END $$;

-- from 29_seed_citizen_reporting_demo.sql
DO $$
DECLARE
  v_rahima_id BIGINT;
  v_karim_id BIGINT;
  v_farhana_id BIGINT;
  v_kurigram_sadar BIGINT;
  v_chilmari_upazila BIGINT;
  v_ulipur_upazila BIGINT;
  v_nageshwari_upazila BIGINT;
BEGIN
  -- Migrate legacy non-hex showcase saved-location UUID prefixes
  UPDATE saved_locations
  SET public_uuid = REPLACE(public_uuid, 'sl300001-', '5d300001-')
  WHERE public_uuid LIKE 'sl300001-%';
  -- ============================================================
  -- Showcase: citizen saved locations (Kurigram day-to-day demo)
  -- Requires bootstrap users: citizen.rahima/karim/farhana@niers.test
  -- ============================================================
  SELECT id FROM users WHERE email = 'citizen.rahima@niers.test' LIMIT 1 INTO v_rahima_id;
  SELECT id FROM users WHERE email = 'citizen.karim@niers.test' LIMIT 1 INTO v_karim_id;
  SELECT id FROM users WHERE email = 'citizen.farhana@niers.test' LIMIT 1 INTO v_farhana_id;
  SELECT id FROM administrative_areas WHERE code = 'BD-UPZ-448' LIMIT 1 INTO v_kurigram_sadar;
  SELECT id FROM administrative_areas WHERE code = 'BD-UPZ-454' LIMIT 1 INTO v_chilmari_upazila;
  SELECT id FROM administrative_areas WHERE code = 'BD-UPZ-453' LIMIT 1 INTO v_ulipur_upazila;
  SELECT id FROM administrative_areas WHERE code = 'BD-UPZ-449' LIMIT 1 INTO v_nageshwari_upazila;
  INSERT INTO locations (
    public_uuid, admin_area_id, latitude, longitude, geo_point,
    address_text, place_name, source, created_by_user_id
  )
  SELECT v.public_uuid, v.admin_area_id, v.lat, v.lng,
    ST_SetSRID(ST_MakePoint(v.lng, v.lat), 4326)::geography,
    v.address_text, v.place_name, 'user_shared', v.user_id
  FROM (
    SELECT 'a3000001-0000-4000-8000-000000000001' AS public_uuid, v_kurigram_sadar AS admin_area_id,
      25.805200 AS lat, 89.636800 AS lng,
      'House 12, Residential Block, Kurigram Sadar' AS address_text,
      'Rahima home near hospital' AS place_name, v_rahima_id AS user_id
    UNION ALL
    SELECT 'a3000001-0000-4000-8000-000000000002', v_chilmari_upazila,
      25.581000, 89.668500,
      'Flat 3B, Station Road, Chilmari', 'Karim apartment Station Road', v_karim_id
    UNION ALL
    SELECT 'a3000001-0000-4000-8000-000000000003', v_ulipur_upazila,
      25.848500, 89.551200,
      'Ulipur Bazaar Main Road', 'Ulipur bazaar', v_farhana_id
    UNION ALL
    SELECT 'a3000001-0000-4000-8000-000000000004', v_kurigram_sadar,
      25.803800, 89.634500,
      'Sadar Pharmacy Lane, Kurigram', 'Sadar pharmacy area', v_rahima_id
    UNION ALL
    SELECT 'a3000001-0000-4000-8000-000000000005', v_nageshwari_upazila,
      25.901200, 89.698800,
      'Nageshwari Market Road', 'Nageshwari market', v_farhana_id
  ) AS v
  WHERE v_rahima_id IS NOT NULL AND v_karim_id IS NOT NULL AND v_farhana_id IS NOT NULL
    AND v.admin_area_id IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM locations l WHERE l.public_uuid = v.public_uuid) ON CONFLICT DO NOTHING;
  INSERT INTO saved_locations (public_uuid, user_id, location_id, label)
  SELECT v.sl_uuid, v.user_id, l.id, v.label
  FROM (
    SELECT '5d300001-0000-4000-8000-000000000001' AS sl_uuid,
      'a3000001-0000-4000-8000-000000000001' AS loc_uuid, v_rahima_id AS user_id, 'Home' AS label
    UNION ALL
    SELECT '5d300001-0000-4000-8000-000000000002',
      'a3000001-0000-4000-8000-000000000002', v_karim_id, 'Home'
    UNION ALL
    SELECT '5d300001-0000-4000-8000-000000000003',
      'a3000001-0000-4000-8000-000000000003', v_farhana_id, 'Work'
    UNION ALL
    SELECT '5d300001-0000-4000-8000-000000000004',
      'a3000001-0000-4000-8000-000000000004', v_rahima_id, 'Mother clinic area'
    UNION ALL
    SELECT '5d300001-0000-4000-8000-000000000005',
      'a3000001-0000-4000-8000-000000000005', v_farhana_id, 'Market'
  ) AS v
  INNER JOIN locations l ON l.public_uuid = v.loc_uuid
  WHERE v.user_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM saved_locations s
      WHERE s.user_id = v.user_id AND s.location_id = l.id AND s.is_deleted = FALSE
    ) ON CONFLICT DO NOTHING;
END $$;

-- from 30_seed_pre_disaster_operations_demo.sql
DO $$
DECLARE
  v_rahima_id BIGINT;
  v_karim_id BIGINT;
  v_farhana_id BIGINT;
  v_cat_medical BIGINT;
  v_cat_fire BIGINT;
  v_cat_crime BIGINT;
  v_cat_infrastructure BIGINT;
  v_cat_relief BIGINT;
  v_ch_web BIGINT;
  v_ch_call BIGINT;
  v_st_received BIGINT;
  v_st_under_review BIGINT;
  v_st_linked_case BIGINT;
  v_st_linked_inc BIGINT;
  v_cs_under_review BIGINT;
  v_cs_awaiting BIGINT;
  v_loc_001 BIGINT;
  v_loc_002 BIGINT;
  v_loc_003 BIGINT;
  v_loc_004 BIGINT;
  v_sev_critical BIGINT;
  v_sev_high BIGINT;
  v_sev_medium BIGINT;
  v_is_classified BIGINT;
  v_is_agency_assigned BIGINT;
  v_is_unit_assigned BIGINT;
  v_is_dispatched BIGINT;
  v_is_in_progress BIGINT;
  v_ds_assigned BIGINT;
  v_ds_dispatched BIGINT;
  v_ds_arrived BIGINT;
  v_us_busy BIGINT;
  v_intake_001_id BIGINT;
  v_intake_002_id BIGINT;
  v_intake_003_id BIGINT;
  v_intake_004_id BIGINT;
  v_intake_005_id BIGINT;
  v_intake_006_id BIGINT;
  v_case_001_id BIGINT;
  v_inc_101 BIGINT;
  v_inc_102 BIGINT;
  v_inc_103 BIGINT;
  v_disp_101_id BIGINT;
  v_disp_102_id BIGINT;
  v_disp_103_id BIGINT;
  v_disp_104_id BIGINT;
  v_unit_med_01 BIGINT;
  v_unit_pol_01 BIGINT;
  v_unit_fire_01 BIGINT;
  v_unit_pol_02 BIGINT;
  v_actor_id BIGINT;
BEGIN
  -- Migrate legacy non-hex showcase UUID prefixes (g/sc are not valid UUID hex)
  UPDATE intake_reports
  SET public_uuid = REPLACE(public_uuid, 'g3000001-', 'd3000001-')
  WHERE public_uuid LIKE 'g3000001-%';
  UPDATE service_cases
  SET public_uuid = REPLACE(public_uuid, 'sc300001-', 'dc300001-')
  WHERE public_uuid LIKE 'sc300001-%';
  -- ============================================================
  -- Showcase: day-to-day operations (intakes, case, incidents, dispatches)
  -- No disaster_events, no natural_disaster category
  -- Requires demo citizens + seed 21/28/29
  -- ============================================================
  SELECT id FROM users WHERE email = 'citizen.rahima@niers.test' LIMIT 1 INTO v_rahima_id;
  SELECT id FROM users WHERE email = 'citizen.karim@niers.test' LIMIT 1 INTO v_karim_id;
  SELECT id FROM users WHERE email = 'citizen.farhana@niers.test' LIMIT 1 INTO v_farhana_id;
  v_actor_id := COALESCE(
    (SELECT id FROM users WHERE email = 'dispatcher@niers.test' LIMIT 1),
    (SELECT id FROM users ORDER BY id ASC LIMIT 1)
  );
  SELECT id FROM report_categories WHERE category_code = 'medical' LIMIT 1 INTO v_cat_medical;
  SELECT id FROM report_categories WHERE category_code = 'fire' LIMIT 1 INTO v_cat_fire;
  SELECT id FROM report_categories WHERE category_code = 'crime_public_safety' LIMIT 1 INTO v_cat_crime;
  SELECT id FROM report_categories WHERE category_code = 'infrastructure_emergency' LIMIT 1 INTO v_cat_infrastructure;
  SELECT id FROM report_categories WHERE category_code = 'relief_request' LIMIT 1 INTO v_cat_relief;
  SELECT id FROM report_channels WHERE channel_code = 'web_portal' LIMIT 1 INTO v_ch_web;
  SELECT id FROM report_channels WHERE channel_code = 'emergency_call' LIMIT 1 INTO v_ch_call;
  SELECT id FROM intake_statuses WHERE status_code = 'received' LIMIT 1 INTO v_st_received;
  SELECT id FROM intake_statuses WHERE status_code = 'under_review' LIMIT 1 INTO v_st_under_review;
  SELECT id FROM intake_statuses WHERE status_code = 'linked_to_case' LIMIT 1 INTO v_st_linked_case;
  SELECT id FROM intake_statuses WHERE status_code = 'linked_to_incident' LIMIT 1 INTO v_st_linked_inc;
  SELECT id FROM case_statuses WHERE status_code = 'under_review' LIMIT 1 INTO v_cs_under_review;
  SELECT id FROM case_statuses WHERE status_code = 'awaiting_user_response' LIMIT 1 INTO v_cs_awaiting;
  SELECT id FROM locations WHERE public_uuid = 'a3000001-0000-4000-8000-000000000001' LIMIT 1 INTO v_loc_001;
  SELECT id FROM locations WHERE public_uuid = 'a3000001-0000-4000-8000-000000000002' LIMIT 1 INTO v_loc_002;
  SELECT id FROM locations WHERE public_uuid = 'a3000001-0000-4000-8000-000000000003' LIMIT 1 INTO v_loc_003;
  SELECT id FROM locations WHERE public_uuid = 'a3000001-0000-4000-8000-000000000004' LIMIT 1 INTO v_loc_004;
  SELECT id FROM incident_severity_levels WHERE severity_code = 'critical' LIMIT 1 INTO v_sev_critical;
  SELECT id FROM incident_severity_levels WHERE severity_code = 'high' LIMIT 1 INTO v_sev_high;
  SELECT id FROM incident_severity_levels WHERE severity_code = 'medium' LIMIT 1 INTO v_sev_medium;
  SELECT id FROM incident_statuses WHERE status_code = 'classified' LIMIT 1 INTO v_is_classified;
  SELECT id FROM incident_statuses WHERE status_code = 'agency_assigned' LIMIT 1 INTO v_is_agency_assigned;
  SELECT id FROM incident_statuses WHERE status_code = 'unit_assigned' LIMIT 1 INTO v_is_unit_assigned;
  SELECT id FROM incident_statuses WHERE status_code = 'dispatched' LIMIT 1 INTO v_is_dispatched;
  SELECT id FROM incident_statuses WHERE status_code = 'in_progress' LIMIT 1 INTO v_is_in_progress;
  SELECT id FROM dispatch_statuses WHERE status_code = 'assigned' LIMIT 1 INTO v_ds_assigned;
  SELECT id FROM dispatch_statuses WHERE status_code = 'dispatched' LIMIT 1 INTO v_ds_dispatched;
  SELECT id FROM dispatch_statuses WHERE status_code = 'arrived' LIMIT 1 INTO v_ds_arrived;
  SELECT id FROM unit_statuses WHERE status_code = 'busy' LIMIT 1 INTO v_us_busy;
  -- ── Intake reports ───────────────────────────────────────────
  INSERT INTO intake_reports (
    public_uuid, report_code, reporter_user_id, channel_id, category_id,
    reported_location_id, summary, description, current_status_id, reported_at
  )
  SELECT v.puuid, v.rcode, v.reporter, v.channel, v.category, v.loc, v.summary, v.descr, v_st_received, v.reported_at
  FROM (
    SELECT 'd3000001-0000-4000-8000-000000000001' AS puuid, 'IR-KUR-SHOW-001' AS rcode,
      v_rahima_id AS reporter, v_ch_web AS channel, v_cat_medical AS category, v_loc_001 AS loc,
      'Elderly neighbor reporting chest pain' AS summary,
      'Neighbor aged 68 complains of chest pain and shortness of breath.' AS descr,
      (NOW() - INTERVAL '120 minute') AS reported_at
    UNION ALL
    SELECT 'd3000001-0000-4000-8000-000000000002', 'IR-KUR-SHOW-002',
      v_karim_id, v_ch_call, v_cat_fire, v_loc_002,
      'Strong gas smell from residential building',
      'Caller reports persistent gas odor on third floor.',
      (NOW() - INTERVAL '95 minute')
    UNION ALL
    SELECT 'd3000001-0000-4000-8000-000000000003', 'IR-KUR-SHOW-003',
      v_farhana_id, v_ch_web, v_cat_infrastructure, v_loc_003,
      'Deep potholes causing bike accidents near bazaar',
      'Multiple cyclists fell on Ulipur bazaar approach road.',
      (NOW() - INTERVAL '70 minute')
    UNION ALL
    SELECT 'd3000001-0000-4000-8000-000000000004', 'IR-KUR-SHOW-004',
      v_rahima_id, v_ch_web, v_cat_relief, v_loc_004,
      'Help arranging monthly diabetes medicine for mother',
      'Need assistance coordinating prescription refill delivery.',
      (NOW() - INTERVAL '50 minute')
    UNION ALL
    SELECT 'd3000001-0000-4000-8000-000000000005', 'IR-KUR-SHOW-005',
      v_karim_id, v_ch_web, v_cat_medical, v_loc_001,
      'Child with high fever since this morning',
      'Five-year-old with fever 39C, no rash yet.',
      (NOW() - INTERVAL '35 minute')
    UNION ALL
    SELECT 'd3000001-0000-4000-8000-000000000006', 'IR-KUR-SHOW-006',
      v_farhana_id, v_ch_web, v_cat_fire, v_loc_002,
      'Duplicate gas smell report on Station Road',
      'Second caller reporting same building gas odor.',
      (NOW() - INTERVAL '15 minute')
  ) AS v
  WHERE v_rahima_id IS NOT NULL AND v_karim_id IS NOT NULL AND v_farhana_id IS NOT NULL
    AND v_cat_medical IS NOT NULL AND v_cat_fire IS NOT NULL AND v_cat_crime IS NOT NULL
    AND v_cat_infrastructure IS NOT NULL AND v_cat_relief IS NOT NULL
    AND v_loc_001 IS NOT NULL AND v_loc_002 IS NOT NULL AND v_loc_003 IS NOT NULL AND v_loc_004 IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM intake_reports ir WHERE ir.report_code = v.rcode);
  -- Intake location history ON CONFLICT DO NOTHING;
  INSERT INTO intake_report_location_history (
    intake_report_id, location_id, previous_location_id, change_kind, changed_by_user_id, change_reason
  )
  SELECT ir.id, ir.reported_location_id, NULL, 'initial_create', ir.reporter_user_id, 'Initial reported location'
  FROM intake_reports ir
  WHERE ir.public_uuid LIKE 'd3000001-0000-4000-8000-00000000000%'
    AND NOT EXISTS (
      SELECT 1 FROM intake_report_location_history h WHERE h.intake_report_id = ir.id
    );
  -- Intake IDs (resolve before status history — avoids trigger read/write conflict)
  SELECT id FROM intake_reports WHERE report_code = 'IR-KUR-SHOW-001' LIMIT 1 INTO v_intake_001_id;
  SELECT id FROM intake_reports WHERE report_code = 'IR-KUR-SHOW-002' LIMIT 1 INTO v_intake_002_id;
  SELECT id FROM intake_reports WHERE report_code = 'IR-KUR-SHOW-003' LIMIT 1 INTO v_intake_003_id;
  SELECT id FROM intake_reports WHERE report_code = 'IR-KUR-SHOW-004' LIMIT 1 INTO v_intake_004_id;
  SELECT id FROM intake_reports WHERE report_code = 'IR-KUR-SHOW-005' LIMIT 1 INTO v_intake_005_id;
  SELECT id FROM intake_reports WHERE report_code = 'IR-KUR-SHOW-006' LIMIT 1 INTO v_intake_006_id;
  -- Intake status histories (received -> under_review -> final where applicable) ON CONFLICT DO NOTHING;
  INSERT INTO intake_report_status_history (intake_report_id, status_id, changed_by_user_id, note)
  SELECT v.intake_id, v_st_received, v_actor_id, 'Report received'
  FROM (
    SELECT v_intake_001_id AS intake_id UNION ALL SELECT v_intake_002_id UNION ALL SELECT v_intake_003_id
    UNION ALL SELECT v_intake_004_id UNION ALL SELECT v_intake_005_id UNION ALL SELECT v_intake_006_id
  ) AS v
  WHERE v.intake_id IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM intake_report_status_history h WHERE h.intake_report_id = v.intake_id) ON CONFLICT DO NOTHING;
  INSERT INTO intake_report_status_history (intake_report_id, status_id, changed_by_user_id, note)
  SELECT v.intake_id, v_st_under_review, v_actor_id, 'Dispatcher review started'
  FROM (
    SELECT v_intake_001_id AS intake_id UNION ALL SELECT v_intake_002_id UNION ALL SELECT v_intake_003_id
    UNION ALL SELECT v_intake_004_id UNION ALL SELECT v_intake_006_id
  ) AS v
  WHERE v.intake_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM intake_report_status_history h
      WHERE h.intake_report_id = v.intake_id AND h.status_id = v_st_under_review
    ) ON CONFLICT DO NOTHING;
  INSERT INTO intake_report_status_history (intake_report_id, status_id, changed_by_user_id, note)
  SELECT v.intake_id, v_st_linked_inc, v_actor_id, 'Linked to emergency incident'
  FROM (
    SELECT v_intake_001_id AS intake_id UNION ALL SELECT v_intake_002_id UNION ALL SELECT v_intake_006_id
  ) AS v
  WHERE v.intake_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM intake_report_status_history h
      WHERE h.intake_report_id = v.intake_id AND h.status_id = v_st_linked_inc
    ) ON CONFLICT DO NOTHING;
  INSERT INTO intake_report_status_history (intake_report_id, status_id, changed_by_user_id, note)
  SELECT v_intake_004_id, v_st_linked_case, v_actor_id, 'Classified as service case'
  WHERE v_intake_004_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM intake_report_status_history h
      WHERE h.intake_report_id = v_intake_004_id AND h.status_id = v_st_linked_case
    ) ON CONFLICT DO NOTHING;
  INSERT INTO emergency_calls (
    intake_report_id, dispatcher_id, caller_phone_number, call_started_at, call_status
  )
  SELECT v_intake_002_id, v_actor_id, '01710000002', (NOW() - INTERVAL '94 minute'), 'linked_to_incident'
  WHERE v_intake_002_id IS NOT NULL AND v_actor_id IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM emergency_calls ec WHERE ec.intake_report_id = v_intake_002_id);
  -- ── Service case (intake 4) ────────────────────────────────── ON CONFLICT DO NOTHING;
  INSERT INTO service_cases (
    public_uuid, case_code, intake_report_id, reporter_user_id, category_id,
    current_status_id, current_location_id, title, description, priority_level, source_channel_id
  )
  SELECT
    'dc300001-0000-4000-8000-000000000001',
    'SC-KUR-SHOW-001',
    v_intake_004_id,
    v_rahima_id,
    v_cat_relief,
    v_cs_under_review,
    v_loc_004,
    'Help arranging monthly diabetes medicine for mother',
    'Routine medicine delivery coordination for elderly parent.',
    'medium',
    v_ch_web
  WHERE v_intake_004_id IS NOT NULL AND v_rahima_id IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM service_cases sc WHERE sc.case_code = 'SC-KUR-SHOW-001');
  SELECT id FROM service_cases WHERE case_code = 'SC-KUR-SHOW-001' LIMIT 1) ON CONFLICT DO NOTHING;
  INSERT INTO case_status_history (case_id, status_id, changed_by_user_id, note)
  SELECT v_case_001_id, v_cs_under_review, v_actor_id, 'Case opened from intake classification'
  WHERE v_case_001_id IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM case_status_history h WHERE h.case_id = v_case_001_id AND h.status_id = v_cs_under_review) ON CONFLICT DO NOTHING;
  INSERT INTO case_status_history (case_id, status_id, changed_by_user_id, note)
  SELECT v_case_001_id, v_cs_awaiting, v_actor_id, 'Requested documents from citizen'
  WHERE v_case_001_id IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM case_status_history h WHERE h.case_id = v_case_001_id AND h.status_id = v_cs_awaiting INTO v_case_001_id;
  -- ── Emergency incidents ────────────────────────────────────────
  -- Reset showcase incidents and dependents so status chains can be re-applied idempotently
  DELETE r FROM response_logs r
  INNER JOIN emergency_incidents ei ON ei.id = r.incident_id
  WHERE ei.public_uuid LIKE 'e5000001-0000-4000-8000-00000000010%';
  DELETE h FROM dispatch_status_history h
  INNER JOIN dispatches d ON d.id = h.dispatch_id
  WHERE d.public_uuid LIKE 'f5000001-0000-4000-8000-00000000010%';
  DELETE d FROM dispatches d
  WHERE d.public_uuid LIKE 'f5000001-0000-4000-8000-00000000010%';
  DELETE t FROM incident_timeline_events t
  INNER JOIN emergency_incidents ei ON ei.id = t.incident_id
  WHERE ei.public_uuid LIKE 'e5000001-0000-4000-8000-00000000010%';
  DELETE p FROM incident_agency_participation p
  INNER JOIN emergency_incidents ei ON ei.id = p.incident_id
  WHERE ei.public_uuid LIKE 'e5000001-0000-4000-8000-00000000010%';
  DELETE l FROM incident_report_links l
  INNER JOIN emergency_incidents ei ON ei.id = l.incident_id
  WHERE ei.public_uuid LIKE 'e5000001-0000-4000-8000-00000000010%';
  DELETE h FROM incident_status_history h
  INNER JOIN emergency_incidents ei ON ei.id = h.incident_id
  WHERE ei.public_uuid LIKE 'e5000001-0000-4000-8000-00000000010%';
  DELETE ei FROM emergency_incidents ei
  WHERE ei.public_uuid LIKE 'e5000001-0000-4000-8000-00000000010%' ON CONFLICT DO NOTHING;
  INSERT INTO emergency_incidents (
    public_uuid, incident_code, category_id, severity_level_id, current_status_id,
    current_location_id, origin_type, title, description, created_by_user_id, reported_at
  )
  SELECT v.puuid, v.code, v.cat, v.sev, v.status, v.loc, v.origin, v.title, v.descr, v_actor_id, v.reported_at
  FROM (
    SELECT 'e5000001-0000-4000-8000-000000000101' AS puuid, 'EMI-KUR-PRE-001' AS code,
      v_cat_medical AS cat, v_sev_critical AS sev, v_is_classified AS status, v_loc_001 AS loc,
      'admin_created' AS origin, 'Ambulance response for chest pain patient' AS title,
      'Day-to-day medical emergency response in Sadar residential area.' AS descr,
      (NOW() - INTERVAL '110 minute') AS reported_at
    UNION ALL
    SELECT 'e5000001-0000-4000-8000-000000000102', 'EMI-KUR-PRE-002',
      v_cat_fire, v_sev_high, v_is_classified, v_loc_002,
      'emergency_call', 'Gas leak check on Station Road building',
      'Fire service responding to reported gas odor.',
      (NOW() - INTERVAL '90 minute')
    UNION ALL
    SELECT 'e5000001-0000-4000-8000-000000000103', 'EMI-KUR-PRE-003',
      v_cat_crime, v_sev_medium, v_is_classified, v_loc_002,
      'admin_created', 'Public altercation near Chilmari ferry ghat',
      'Police logging routine public-order incident.',
      (NOW() - INTERVAL '60 minute')
  ) AS v
  WHERE v_actor_id IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM emergency_incidents ei WHERE ei.public_uuid = v.puuid);
  SELECT id FROM emergency_incidents WHERE public_uuid = 'e5000001-0000-4000-8000-000000000101' LIMIT 1 INTO v_inc_101;
  SELECT id FROM emergency_incidents WHERE public_uuid = 'e5000001-0000-4000-8000-000000000102' LIMIT 1 INTO v_inc_102;
  SELECT id FROM emergency_incidents WHERE public_uuid = 'e5000001-0000-4000-8000-000000000103' LIMIT 1) ON CONFLICT DO NOTHING;
  INSERT INTO incident_report_links (incident_id, intake_report_id, link_type, linked_by_user_id)
  SELECT v.inc_id, v.intake_id, v.link_type, v_actor_id
  FROM (
    SELECT v_inc_101 AS inc_id, v_intake_001_id AS intake_id, 'primary_report' AS link_type
    UNION ALL
    SELECT v_inc_102, v_intake_002_id, 'primary_report'
    UNION ALL
    SELECT v_inc_102, v_intake_006_id, 'duplicate_report'
  ) AS v
  WHERE v.inc_id IS NOT NULL AND v.intake_id IS NOT NULL AND v_actor_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM incident_report_links irl
      WHERE irl.incident_id = v.inc_id AND irl.intake_report_id = v.intake_id AND irl.unlinked_at IS NULL INTO v_inc_103;
  -- incident_location_history omitted: current_location_id set on emergency_incidents insert
  -- (trigger on location history conflicts with batched seed execution)
  -- Incident 101 status chain -> in_progress (one transition per statement for trigger order) ON CONFLICT DO NOTHING;
  INSERT INTO incident_status_history (incident_id, status_id, changed_by_user_id, note)
  SELECT v_inc_101, v_is_agency_assigned, v_actor_id, 'Medical and police agencies assigned'
  WHERE v_inc_101 IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM incident_status_history h
      WHERE h.incident_id = v_inc_101 AND h.status_id = v_is_agency_assigned
    ) ON CONFLICT DO NOTHING;
  INSERT INTO incident_status_history (incident_id, status_id, changed_by_user_id, note)
  SELECT v_inc_101, v_is_unit_assigned, v_actor_id, 'Ambulance and patrol units assigned'
  WHERE v_inc_101 IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM incident_status_history h
      WHERE h.incident_id = v_inc_101 AND h.status_id = v_is_unit_assigned
    ) ON CONFLICT DO NOTHING;
  INSERT INTO incident_status_history (incident_id, status_id, changed_by_user_id, note)
  SELECT v_inc_101, v_is_dispatched, v_actor_id, 'Units dispatched'
  WHERE v_inc_101 IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM incident_status_history h
      WHERE h.incident_id = v_inc_101 AND h.status_id = v_is_dispatched
    ) ON CONFLICT DO NOTHING;
  INSERT INTO incident_status_history (incident_id, status_id, changed_by_user_id, note)
  SELECT v_inc_101, v_is_in_progress, v_actor_id, 'On-scene response underway'
  WHERE v_inc_101 IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM incident_status_history h
      WHERE h.incident_id = v_inc_101 AND h.status_id = v_is_in_progress
    );
  -- Incident 102 status chain -> unit_assigned ON CONFLICT DO NOTHING;
  INSERT INTO incident_status_history (incident_id, status_id, changed_by_user_id, note)
  SELECT v_inc_102, v_is_agency_assigned, v_actor_id, 'Fire and police assigned'
  WHERE v_inc_102 IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM incident_status_history h
      WHERE h.incident_id = v_inc_102 AND h.status_id = v_is_agency_assigned
    ) ON CONFLICT DO NOTHING;
  INSERT INTO incident_status_history (incident_id, status_id, changed_by_user_id, note)
  SELECT v_inc_102, v_is_unit_assigned, v_actor_id, 'Fire truck and police unit assigned'
  WHERE v_inc_102 IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM incident_status_history h
      WHERE h.incident_id = v_inc_102 AND h.status_id = v_is_unit_assigned
    ) ON CONFLICT DO NOTHING;
  INSERT INTO incident_timeline_events (incident_id, event_type, event_title, event_description, created_by_user_id, event_time)
  SELECT v.inc_id, 'operator_note', v.title, v.descr, v_actor_id, v.event_time
  FROM (
    SELECT v_inc_101 AS inc_id, 'Ambulance dispatched to Sadar' AS title,
      'EMS unit en route to chest pain patient.' AS descr, (NOW() - INTERVAL '100 minute') AS event_time
    UNION ALL
    SELECT v_inc_101, 'Patient conscious on arrival', 'First responder reports patient alert.', (NOW() - INTERVAL '85 minute')
    UNION ALL
    SELECT v_inc_102, 'Fire crew ventilating building', 'Residents moved to safe distance.', (NOW() - INTERVAL '80 minute')
    UNION ALL
    SELECT v_inc_103, 'Police monitoring ferry ghat', 'Units observing situation before assignment.', (NOW() - INTERVAL '55 minute')
  ) AS v
  WHERE v.inc_id IS NOT NULL AND v_actor_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM incident_timeline_events t
      WHERE t.incident_id = v.inc_id AND t.event_title = v.title
    );
  -- ── Agency participation ─────────────────────────────────────── ON CONFLICT DO NOTHING;
  INSERT INTO incident_agency_participation (incident_id, agency_id, is_lead_agency, participation_status, assigned_by_user_id)
  SELECT v.inc_id, a.id, v.is_lead, 'active', v_actor_id
  FROM (
    SELECT v_inc_101 AS inc_id, 'KUR-MED-01' AS agency_code, 1 AS is_lead
    UNION ALL SELECT v_inc_101, 'KUR-POL-01', 0
    UNION ALL SELECT v_inc_102, 'KUR-FIRE-01', 1
    UNION ALL SELECT v_inc_102, 'KUR-POL-01', 0
    UNION ALL SELECT v_inc_103, 'KUR-POL-01', 1
  ) AS v
  INNER JOIN agencies a ON a.agency_code = v.agency_code
  WHERE v.inc_id IS NOT NULL AND v_actor_id IS NOT NULL
  ON CONFLICT DO UPDATE SET participation_status = 'active';
  -- ── Dispatches ─────────────────────────────────────────────────
  INSERT INTO dispatches (public_uuid, incident_id, unit_id, assigned_by_user_id, current_status_id, priority_level)
  SELECT v.duuid, v.inc_id, eu.id, v_actor_id, v_ds_assigned, v.priority
  FROM (
    SELECT 'f5000001-0000-4000-8000-000000000101' AS duuid, v_inc_101 AS inc_id,
      'c4000001-0000-4000-8000-000000000004' AS unit_uuid, 'critical' AS priority
    UNION ALL
    SELECT 'f5000001-0000-4000-8000-000000000102', v_inc_101,
      'c4000001-0000-4000-8000-000000000007', 'high'
    UNION ALL
    SELECT 'f5000001-0000-4000-8000-000000000103', v_inc_102,
      'c4000001-0000-4000-8000-000000000001', 'high'
    UNION ALL
    SELECT 'f5000001-0000-4000-8000-000000000104', v_inc_102,
      'c4000001-0000-4000-8000-000000000008', 'medium'
  ) AS v
  INNER JOIN emergency_units eu ON eu.public_uuid = v.unit_uuid
  WHERE v.inc_id IS NOT NULL AND v_actor_id IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM dispatches d WHERE d.public_uuid = v.duuid);
  SELECT id FROM dispatches WHERE public_uuid = 'f5000001-0000-4000-8000-000000000101' LIMIT 1 INTO v_disp_101_id;
  SELECT id FROM dispatches WHERE public_uuid = 'f5000001-0000-4000-8000-000000000102' LIMIT 1 INTO v_disp_102_id;
  SELECT id FROM dispatches WHERE public_uuid = 'f5000001-0000-4000-8000-000000000103' LIMIT 1 INTO v_disp_103_id;
  SELECT id FROM dispatches WHERE public_uuid = 'f5000001-0000-4000-8000-000000000104' LIMIT 1 INTO v_disp_104_id;
  -- Dispatch status histories ON CONFLICT DO NOTHING;
  INSERT INTO dispatch_status_history (dispatch_id, status_id, changed_by_user_id, note)
  SELECT v.dispatch_id, v_ds_assigned, v_actor_id, 'Unit assigned'
  FROM (
    SELECT v_disp_101_id AS dispatch_id UNION ALL SELECT v_disp_102_id
    UNION ALL SELECT v_disp_103_id UNION ALL SELECT v_disp_104_id
  ) AS v
  WHERE v.dispatch_id IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM dispatch_status_history h WHERE h.dispatch_id = v.dispatch_id) ON CONFLICT DO NOTHING;
  INSERT INTO dispatch_status_history (dispatch_id, status_id, changed_by_user_id, note)
  SELECT v.dispatch_id, v_ds_dispatched, v_actor_id, 'Unit en route'
  FROM (
    SELECT v_disp_101_id AS dispatch_id UNION ALL SELECT v_disp_103_id
  ) AS v
  WHERE v.dispatch_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM dispatch_status_history h
      WHERE h.dispatch_id = v.dispatch_id AND h.status_id = v_ds_dispatched
    ) ON CONFLICT DO NOTHING;
  INSERT INTO dispatch_status_history (dispatch_id, status_id, changed_by_user_id, note)
  SELECT v_disp_101_id, v_ds_arrived, v_actor_id, 'Unit on scene'
  WHERE v_disp_101_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM dispatch_status_history h
      WHERE h.dispatch_id = v_disp_101_id AND h.status_id = v_ds_arrived
    );
  SELECT id FROM emergency_units WHERE public_uuid = 'c4000001-0000-4000-8000-000000000004' LIMIT 1 INTO v_unit_med_01;
  SELECT id FROM emergency_units WHERE public_uuid = 'c4000001-0000-4000-8000-000000000007' LIMIT 1 INTO v_unit_pol_01;
  SELECT id FROM emergency_units WHERE public_uuid = 'c4000001-0000-4000-8000-000000000001' LIMIT 1 INTO v_unit_fire_01;
  SELECT id FROM emergency_units WHERE public_uuid = 'c4000001-0000-4000-8000-000000000008' LIMIT 1) ON CONFLICT DO NOTHING;
  INSERT INTO unit_status_history (unit_id, status_id, changed_by_user_id, note)
  SELECT v.unit_id, v_us_busy, v_actor_id, 'Showcase dispatch assignment'
  FROM (
    SELECT v_unit_med_01 AS unit_id UNION ALL SELECT v_unit_pol_01
    UNION ALL SELECT v_unit_fire_01 UNION ALL SELECT v_unit_pol_02
  ) AS v
  WHERE v.unit_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM unit_status_history h
      WHERE h.unit_id = v.unit_id AND h.note = 'Showcase dispatch assignment' INTO v_unit_pol_02;
  -- ── Response logs ────────────────────────────────────────────── ON CONFLICT DO NOTHING;
  INSERT INTO response_logs (incident_id, dispatch_id, agency_id, created_by_user_id, log_type, message)
  SELECT v.inc_id, v.dispatch_id, a.id, v_actor_id, 'update', v.message
  FROM (
    SELECT v_inc_101 AS inc_id, v_disp_101_id AS dispatch_id, 'KUR-MED-01' AS agency,
      'Ambulance en route; patient conscious and breathing.' AS message
    UNION ALL
    SELECT v_inc_102, v_disp_103_id, 'KUR-FIRE-01',
      'Fire crew ventilating building; residents at safe distance.'
    UNION ALL
    SELECT v_inc_102, NULL, 'KUR-POL-01',
      'Police coordinating building evacuation on Station Road.'
    UNION ALL
    SELECT v_inc_103, NULL, 'KUR-POL-01',
      'Officers de-escalating altercation near ferry ghat.'
    UNION ALL
    SELECT v_inc_103, NULL, 'KUR-POL-01',
      'Dispatcher requested pothole photos from separate infrastructure report.'
  ) AS v
  INNER JOIN agencies a ON a.agency_code = v.agency
  WHERE v.inc_id IS NOT NULL AND v_actor_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM response_logs rl WHERE rl.incident_id = v.inc_id AND rl.message = v.message
    );
  -- ── Facility readiness (KUR-HOS emergency_care) ──────────────── ON CONFLICT DO NOTHING;
  INSERT INTO facility_capabilities (facility_id, capability_id, is_active)
  SELECT f.id, c.id, TRUE
  FROM facilities f
  INNER JOIN capabilities c ON c.capability_code = 'emergency_care'
  WHERE f.facility_code = 'KUR-HOS-01'
    AND NOT EXISTS (
      SELECT 1 FROM facility_capabilities fc
      WHERE fc.facility_id = f.id AND fc.capability_id = c.id
    ) ON CONFLICT DO NOTHING;
END $$;

-- from 31_seed_case_messages_notifications_demo.sql
DO $$
DECLARE
  v_rahima_id BIGINT;
  v_case_001_id BIGINT;
  v_intake_001_id BIGINT;
  v_intake_005_id BIGINT;
  v_inc_101_id BIGINT;
  v_actor_id BIGINT;
BEGIN
  -- ============================================================
  -- Showcase: service case messages + in-app notifications
  -- ============================================================
  SELECT id FROM users WHERE email = 'citizen.rahima@niers.test' LIMIT 1 INTO v_rahima_id;
  v_actor_id := COALESCE(
    (SELECT id FROM users WHERE email = 'dispatcher@niers.test' LIMIT 1),
    (SELECT id FROM users ORDER BY id ASC LIMIT 1)
  );
  SELECT id FROM service_cases WHERE case_code = 'SC-KUR-SHOW-001' LIMIT 1 INTO v_case_001_id;
  SELECT id FROM intake_reports WHERE report_code = 'IR-KUR-SHOW-001' LIMIT 1 INTO v_intake_001_id;
  SELECT id FROM intake_reports WHERE report_code = 'IR-KUR-SHOW-005' LIMIT 1 INTO v_intake_005_id;
  SELECT id FROM emergency_incidents WHERE incident_code = 'EMI-KUR-PRE-001' LIMIT 1 INTO v_inc_101_id;
  INSERT INTO case_messages (case_id, sender_user_id, message_type, subject, body, is_internal)
  SELECT v_case_001_id, v_rahima_id, 'user_message',
    'Documents for medicine support',
    'Which documents do I need to submit for monthly diabetes medicine assistance?',
    FALSE
  WHERE v_case_001_id IS NOT NULL AND v_rahima_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM case_messages m
      WHERE m.case_id = v_case_001_id AND m.subject = 'Documents for medicine support'
    ) ON CONFLICT DO NOTHING;
  INSERT INTO case_messages (case_id, sender_user_id, message_type, subject, body, is_internal)
  SELECT v_case_001_id, v_actor_id, 'admin_reply',
    'Prescription and clinic details needed',
    'Please upload a photo of the prescription and share your mother''s upazila clinic name.',
    FALSE
  WHERE v_case_001_id IS NOT NULL AND v_actor_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM case_messages m
      WHERE m.case_id = v_case_001_id AND m.subject = 'Prescription and clinic details needed'
    ) ON CONFLICT DO NOTHING;
  INSERT INTO case_messages (case_id, sender_user_id, message_type, subject, body, is_internal)
  SELECT v_case_001_id, v_rahima_id, 'user_message',
    'Clinic and delivery preference',
    'Clinic is Kurigram Sadar Upazila Health Complex. Prefer afternoon delivery.',
    FALSE
  WHERE v_case_001_id IS NOT NULL AND v_rahima_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM case_messages m
      WHERE m.case_id = v_case_001_id AND m.subject = 'Clinic and delivery preference'
    ) ON CONFLICT DO NOTHING;
  INSERT INTO case_messages (case_id, sender_user_id, message_type, subject, body, is_internal)
  SELECT v_case_001_id, v_actor_id, 'system_note',
    'Internal routing',
    'Route to Sadar relief desk for non-urgent medicine coordination.',
    TRUE
  WHERE v_case_001_id IS NOT NULL AND v_actor_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM case_messages m
      WHERE m.case_id = v_case_001_id AND m.subject = 'Internal routing'
    );
  -- Notifications ON CONFLICT DO NOTHING;
  INSERT INTO notifications (template_id, notification_type, title, body, entity_type, entity_id, created_by_user_id)
  SELECT t.id, 'case_reply', 'Your report has been received',
    'Your report (IR-KUR-SHOW-001) has been received. We will review it shortly.',
    'intake_report', v_intake_001_id, NULL
  FROM notification_templates t
  WHERE t.template_code = 'intake_received__in_app'
    AND v_intake_001_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM notifications n
      WHERE n.entity_type = 'intake_report' AND n.entity_id = v_intake_001_id
        AND n.title = 'Your report has been received'
    ) ON CONFLICT DO NOTHING;
  INSERT INTO notifications (template_id, notification_type, title, body, entity_type, entity_id, created_by_user_id)
  SELECT t.id, 'case_reply', 'Your report has been received',
    'Your report (IR-KUR-SHOW-005) has been received. We will review it shortly.',
    'intake_report', v_intake_005_id, NULL
  FROM notification_templates t
  WHERE t.template_code = 'intake_received__in_app'
    AND v_intake_005_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM notifications n
      WHERE n.entity_type = 'intake_report' AND n.entity_id = v_intake_005_id
        AND n.title = 'Your report has been received'
    ) ON CONFLICT DO NOTHING;
  INSERT INTO notifications (template_id, notification_type, title, body, entity_type, entity_id, created_by_user_id)
  SELECT t.id, 'case_reply', 'Service case opened',
    'Your report has been reviewed and service case SC-KUR-SHOW-001 has been opened.',
    'service_case', v_case_001_id, v_actor_id
  FROM notification_templates t
  WHERE t.template_code = 'intake_classified__in_app'
    AND v_case_001_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM notifications n
      WHERE n.entity_type = 'service_case' AND n.entity_id = v_case_001_id
        AND n.title = 'Service case opened'
    ) ON CONFLICT DO NOTHING;
  INSERT INTO notifications (template_id, notification_type, title, body, entity_type, entity_id, created_by_user_id)
  SELECT t.id, 'incident_update', 'Incident EMI-KUR-PRE-001 status update',
    'Incident EMI-KUR-PRE-001 has been updated from ''dispatched'' to ''in_progress''.',
    'emergency_incident', v_inc_101_id, v_actor_id
  FROM notification_templates t
  WHERE t.template_code = 'incident_status_updated__in_app'
    AND v_inc_101_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM notifications n
      WHERE n.entity_type = 'emergency_incident' AND n.entity_id = v_inc_101_id
        AND n.title = 'Incident EMI-KUR-PRE-001 status update'
    ) ON CONFLICT DO NOTHING;
  INSERT INTO notification_recipients (notification_id, recipient_user_id, delivery_channel)
  SELECT n.id, v_rahima_id, 'in_app'
  FROM notifications n
  WHERE n.entity_type = 'intake_report' AND n.entity_id = v_intake_001_id
    AND v_rahima_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM notification_recipients r
      WHERE r.notification_id = n.id AND r.recipient_user_id = v_rahima_id AND r.delivery_channel = 'in_app'
    ) ON CONFLICT DO NOTHING;
  INSERT INTO notification_recipients (notification_id, recipient_user_id, delivery_channel)
  SELECT n.id, (SELECT id FROM users WHERE email = 'citizen.karim@niers.test' LIMIT 1), 'in_app'
  FROM notifications n
  WHERE n.entity_type = 'intake_report' AND n.entity_id = v_intake_005_id
    AND NOT EXISTS (
      SELECT 1 FROM notification_recipients r
      WHERE r.notification_id = n.id AND r.delivery_channel = 'in_app'
    ) ON CONFLICT DO NOTHING;
  INSERT INTO notification_recipients (notification_id, recipient_user_id, delivery_channel)
  SELECT n.id, v_rahima_id, 'in_app'
  FROM notifications n
  WHERE n.entity_type = 'service_case' AND n.entity_id = v_case_001_id
    AND v_rahima_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM notification_recipients r
      WHERE r.notification_id = n.id AND r.recipient_user_id = v_rahima_id AND r.delivery_channel = 'in_app'
    ) ON CONFLICT DO NOTHING;
END $$;

-- from 32_seed_reporter_risk_demo.sql
DO $$
DECLARE
  v_rahima_id BIGINT;
  v_karim_id BIGINT;
  v_farhana_id BIGINT;
  v_rubel_id BIGINT;
  v_shamim_id BIGINT;
  v_ch_web BIGINT;
  v_cat_medical BIGINT;
  v_cat_fire BIGINT;
  v_cat_crime BIGINT;
  v_cat_infra BIGINT;
  v_st_received BIGINT;
  v_st_under_review BIGINT;
  v_loc_001 BIGINT;
  v_loc_002 BIGINT;
  v_loc_003 BIGINT;
  v_loc_004 BIGINT;
  v_loc_005 BIGINT;
  v_dispatcher_id BIGINT;
  v_admin_id BIGINT;
BEGIN
  -- ============================================================
  -- Showcase: reporter reliability / false report handling demo
  -- Requires demo citizens (rahima, karim, farhana, rubel, shamim) + seed 30
  -- Does not create disaster events
  -- ============================================================
  SELECT id FROM users WHERE email = 'citizen.rahima@niers.test' LIMIT 1 INTO v_rahima_id;
  SELECT id FROM users WHERE email = 'citizen.karim@niers.test' LIMIT 1 INTO v_karim_id;
  SELECT id FROM users WHERE email = 'citizen.farhana@niers.test' LIMIT 1 INTO v_farhana_id;
  SELECT id FROM users WHERE email = 'citizen.rubel@niers.test' LIMIT 1 INTO v_rubel_id;
  SELECT id FROM users WHERE email = 'citizen.shamim@niers.test' LIMIT 1 INTO v_shamim_id;
  v_dispatcher_id := COALESCE(
    (SELECT id FROM users WHERE email = 'dispatcher@niers.test' LIMIT 1),
    (SELECT id FROM users ORDER BY id ASC LIMIT 1)
  );
  v_admin_id := COALESCE(
    (SELECT id FROM users WHERE email = 'admin@niers.test' LIMIT 1),
    v_dispatcher_id
  );
  SELECT id FROM report_channels WHERE channel_code = 'web_portal' LIMIT 1 INTO v_ch_web;
  SELECT id FROM report_categories WHERE category_code = 'medical' LIMIT 1 INTO v_cat_medical;
  SELECT id FROM report_categories WHERE category_code = 'fire' LIMIT 1 INTO v_cat_fire;
  SELECT id FROM report_categories WHERE category_code = 'crime_public_safety' LIMIT 1 INTO v_cat_crime;
  SELECT id FROM report_categories WHERE category_code = 'infrastructure_emergency' LIMIT 1 INTO v_cat_infra;
  SELECT id FROM intake_statuses WHERE status_code = 'received' LIMIT 1 INTO v_st_received;
  SELECT id FROM intake_statuses WHERE status_code = 'under_review' LIMIT 1 INTO v_st_under_review;
  SELECT id FROM locations WHERE public_uuid = 'a3000001-0000-4000-8000-000000000001' LIMIT 1 INTO v_loc_001;
  SELECT id FROM locations WHERE public_uuid = 'a3000001-0000-4000-8000-000000000002' LIMIT 1 INTO v_loc_002;
  SELECT id FROM locations WHERE public_uuid = 'a3000001-0000-4000-8000-000000000003' LIMIT 1 INTO v_loc_003;
  SELECT id FROM locations WHERE public_uuid = 'a3000001-0000-4000-8000-000000000004' LIMIT 1 INTO v_loc_004;
  SELECT id FROM locations WHERE public_uuid = 'a3000001-0000-4000-8000-000000000005' LIMIT 1 INTO v_loc_005;
  -- Additional intake reports for reliability demo
  INSERT INTO intake_reports (
    public_uuid, report_code, reporter_user_id, channel_id, category_id,
    reported_location_id, summary, description, current_status_id, reported_at
  )
  SELECT v.puuid, v.rcode, v.reporter, v_ch_web, v.category, v.loc, v.summary, v.descr, v_st_under_review, v.reported_at
  FROM (
    SELECT 'd30000a1-0000-4000-8000-000000000001' AS puuid, 'IR-RISK-DUP-001' AS rcode,
      v_karim_id AS reporter, v_cat_infra AS category, v_loc_002 AS loc,
      'Waterlogging on Station Road again' AS summary,
      'Same flooded stretch reported yesterday during heavy rain.' AS descr,
      (NOW() - INTERVAL '3 day') AS reported_at
    UNION ALL
    SELECT 'd30000a1-0000-4000-8000-000000000002', 'IR-RISK-DUP-002',
      v_karim_id, v_cat_infra, v_loc_002,
      'Station Road flooded — vehicles stuck',
      'Duplicate flooding report from same caller area.',
      (NOW() - INTERVAL '2 day')
    UNION ALL
    SELECT 'd30000a1-0000-4000-8000-000000000003', 'IR-RISK-MIST-001',
      v_farhana_id, v_cat_fire, v_loc_003,
      'Smoke visible from apartment window',
      'Caller thought building was on fire.',
      (NOW() - INTERVAL '5 day')
    UNION ALL
    SELECT 'd30000a1-0000-4000-8000-000000000004', 'IR-RISK-FA-001',
      v_farhana_id, v_cat_fire, v_loc_003,
      'Fire alarm at Ulipur market',
      'Market committee reported blaze; turned out to be festival fireworks.',
      (NOW() - INTERVAL '8 day')
    UNION ALL
    SELECT 'd30000a1-0000-4000-8000-000000000005', 'IR-RISK-FA-002',
      v_farhana_id, v_cat_fire, v_loc_005,
      'Burning smell near Nageshwari bazaar',
      'Strong burning odor; no fire found on inspection.',
      (NOW() - INTERVAL '12 day')
    UNION ALL
    SELECT 'd30000a1-0000-4000-8000-000000000006', 'IR-RISK-FA-003',
      v_farhana_id, v_cat_fire, v_loc_005,
      'Warehouse fire at Nageshwari',
      'Repeated false fire report from same account.',
      (NOW() - INTERVAL '18 day')
    UNION ALL
    SELECT 'd30000a1-0000-4000-8000-000000000007', 'IR-RISK-SPAM-001',
      v_shamim_id, v_cat_fire, v_loc_004,
      'Major fire at Sadar hospital block',
      'Fabricated fire at Kurigram Sadar hospital.',
      (NOW() - INTERVAL '1 day')
    UNION ALL
    SELECT 'd30000a1-0000-4000-8000-000000000008', 'IR-RISK-SPAM-002',
      v_shamim_id, v_cat_crime, v_loc_004,
      'Armed robbery in progress at pharmacy lane',
      'Fake armed robbery report to provoke response.',
      (NOW() - INTERVAL '12 hour')
    UNION ALL
    SELECT 'd30000a1-0000-4000-8000-000000000009', 'IR-RISK-SPAM-003',
      v_shamim_id, v_cat_fire, v_loc_001,
      'School building on fire in Kurigram Sadar',
      'Third malicious fire report today from same user.',
      (NOW() - INTERVAL '4 hour')
    UNION ALL
    SELECT 'd30000a1-0000-4000-8000-000000000010', 'IR-RISK-RUB-001',
      v_rubel_id, v_cat_fire, v_loc_002,
      'Gas cylinder explosion reported',
      'No explosion found; caller may have misheard construction noise.',
      (NOW() - INTERVAL '6 day')
    UNION ALL
    SELECT 'd30000a1-0000-4000-8000-000000000011', 'IR-RISK-RUB-002',
      v_rubel_id, v_cat_fire, v_loc_002,
      'Fire at Chilmari residential complex',
      'False alarm — cooking smoke only.',
      (NOW() - INTERVAL '4 day')
  ) AS v
  WHERE v.reporter IS NOT NULL AND v.loc IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM intake_reports ir WHERE ir.public_uuid = v.puuid);
  -- Verification reviews (latest per report drives reliability view) ON CONFLICT DO NOTHING;
  INSERT INTO intake_report_verification_reviews (
    public_uuid, intake_report_id, reviewed_by_user_id, verdict, reason, evidence_note, confidence_level, created_at
  )
  SELECT v.vuuid, ir.id, v_dispatcher_id, v.verdict, v.reason, v.evidence, v.confidence, v.created_at
  FROM (
    SELECT 'v30000a1-0000-4000-8000-000000000001' AS vuuid, 'd3000001-0000-4000-8000-000000000001' AS rpt,
      'genuine' AS verdict, 'Medical symptoms confirmed by follow-up' AS reason,
      'Neighbor later transported to Kurigram General Hospital.' AS evidence, 'high' AS confidence,
      (NOW() - INTERVAL '110 minute') AS created_at
    UNION ALL
    SELECT 'v30000a1-0000-4000-8000-000000000002', 'd3000001-0000-4000-8000-000000000002',
      'genuine', 'Fire service detected gas leak on site',
      'Fire unit confirmed odor source and ventilated building.', 'high',
      (NOW() - INTERVAL '90 minute')
    UNION ALL
    SELECT 'v30000a1-0000-4000-8000-000000000003', 'd30000a1-0000-4000-8000-000000000001',
      'duplicate', 'Same location as prior flood report',
      'Linked to IR-RISK-DUP-001 from previous day.', 'medium',
      (NOW() - INTERVAL '2 day')
    UNION ALL
    SELECT 'v30000a1-0000-4000-8000-000000000004', 'd30000a1-0000-4000-8000-000000000003',
      'mistaken', 'Cooking smoke mistaken for structural fire',
      'Resident confirmed heavy spice frying; no fire.', 'medium',
      (NOW() - INTERVAL '4 day')
    UNION ALL
    SELECT 'v30000a1-0000-4000-8000-000000000005', 'd30000a1-0000-4000-8000-000000000004',
      'false_alarm', 'Festival fireworks caused smoke',
      'Local UP confirmed permitted fireworks display.', 'high',
      (NOW() - INTERVAL '7 day')
    UNION ALL
    SELECT 'v30000a1-0000-4000-8000-000000000006', 'd30000a1-0000-4000-8000-000000000005',
      'false_alarm', 'Burning trash pile — no emergency',
      'Municipal workers burning waste legally.', 'medium',
      (NOW() - INTERVAL '11 day')
    UNION ALL
    SELECT 'v30000a1-0000-4000-8000-000000000007', 'd30000a1-0000-4000-8000-000000000006',
      'false_alarm', 'Third false fire from same reporter',
      'No fire found on three consecutive checks.', 'high',
      (NOW() - INTERVAL '17 day')
    UNION ALL
    SELECT 'v30000a1-0000-4000-8000-000000000008', 'd30000a1-0000-4000-8000-000000000007',
      'malicious_false_report', 'Hospital confirmed no incident',
      'Kurigram Sadar hospital security denied any fire.', 'high',
      (NOW() - INTERVAL '20 hour')
    UNION ALL
    SELECT 'v30000a1-0000-4000-8000-000000000009', 'd30000a1-0000-4000-8000-000000000008',
      'malicious_false_report', 'Police patrol found no robbery',
      'Pharmacy lane quiet; likely intentional hoax.', 'high',
      (NOW() - INTERVAL '10 hour')
    UNION ALL
    SELECT 'v30000a1-0000-4000-8000-000000000010', 'd30000a1-0000-4000-8000-000000000009',
      'malicious_false_report', 'Repeated hoax fire reports same day',
      'Three fabricated school fire reports within 24 hours.', 'high',
      (NOW() - INTERVAL '3 hour')
    UNION ALL
    SELECT 'v30000a1-0000-4000-8000-000000000011', 'd30000a1-0000-4000-8000-000000000010',
      'false_alarm', 'Construction noise misreported as explosion',
      'Site supervisor confirmed routine welding.', 'medium',
      (NOW() - INTERVAL '5 day')
    UNION ALL
    SELECT 'v30000a1-0000-4000-8000-000000000012', 'd30000a1-0000-4000-8000-000000000011',
      'false_alarm', 'Cooking smoke only',
      'Tenant admitted leaving stove unattended.', 'medium',
      (NOW() - INTERVAL '3 day')
  ) AS v
  INNER JOIN intake_reports ir ON ir.public_uuid = v.rpt
  WHERE v_dispatcher_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM intake_report_verification_reviews x WHERE x.public_uuid = v.vuuid
    );
  -- Account actions demo ON CONFLICT DO NOTHING;
  INSERT INTO reporter_account_actions (
    public_uuid, target_user_id, action_by_user_id, action_type,
    previous_account_status, new_account_status, reason, suspension_ends_at, created_at
  )
  SELECT v.auuid, v.target, v_admin_id, v.action_type, v.prev, v.new_status, v.reason, v.suspension_ends_at, v.created_at
  FROM (
    SELECT 'a30000a1-0000-4000-8000-000000000001' AS auuid, v_farhana_id AS target,
      'warning' AS action_type, 'active' AS prev, 'active' AS new_status,
      'First confirmed false report. Citizen warned about verifying emergencies before submitting.' AS reason,
      NULL AS suspension_ends_at,
      (NOW() - INTERVAL '10 day') AS created_at
    UNION ALL
    SELECT 'a30000a1-0000-4000-8000-000000000002', v_shamim_id,
      'suspension', 'active', 'suspended',
      'Repeated confirmed malicious false reports within 24 hours. 30-day suspension.',
      (NOW() + INTERVAL '30 day'),
      (NOW() - INTERVAL '2 hour')
  ) AS v
  WHERE v.target IS NOT NULL AND v_admin_id IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM reporter_account_actions raa WHERE raa.public_uuid = v.auuid);
  UPDATE users
  SET
    account_status = 'suspended',
    account_status_reason = 'Repeated confirmed malicious false reports within 24 hours. 30-day suspension.',
    account_status_expires_at = (NOW() + INTERVAL '30 day')
  WHERE id = v_shamim_id
    AND v_shamim_id IS NOT NULL
    AND EXISTS (
      SELECT 1 FROM reporter_account_actions
      WHERE target_user_id = v_shamim_id AND action_type = 'suspension'
    ) ON CONFLICT DO NOTHING;
END $$;
