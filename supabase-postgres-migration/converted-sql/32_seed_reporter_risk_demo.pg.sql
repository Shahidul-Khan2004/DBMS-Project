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