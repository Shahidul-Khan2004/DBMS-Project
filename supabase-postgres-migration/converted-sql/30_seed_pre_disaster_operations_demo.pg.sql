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