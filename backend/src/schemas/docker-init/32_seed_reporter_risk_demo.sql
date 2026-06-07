-- ============================================================
-- Showcase: reporter reliability / false report handling demo
-- Requires demo citizens (rahima, karim, farhana, rubel, shamim) + seed 30
-- Does not create disaster events
-- ============================================================

SET @rahima_id = (SELECT id FROM users WHERE email = 'citizen.rahima@niers.test' LIMIT 1);
SET @karim_id = (SELECT id FROM users WHERE email = 'citizen.karim@niers.test' LIMIT 1);
SET @farhana_id = (SELECT id FROM users WHERE email = 'citizen.farhana@niers.test' LIMIT 1);
SET @rubel_id = (SELECT id FROM users WHERE email = 'citizen.rubel@niers.test' LIMIT 1);
SET @shamim_id = (SELECT id FROM users WHERE email = 'citizen.shamim@niers.test' LIMIT 1);
SET @dispatcher_id = COALESCE(
  (SELECT id FROM users WHERE email = 'dispatcher@niers.test' LIMIT 1),
  (SELECT id FROM users ORDER BY id ASC LIMIT 1)
);
SET @admin_id = COALESCE(
  (SELECT id FROM users WHERE email = 'admin@niers.test' LIMIT 1),
  @dispatcher_id
);

SET @ch_web = (SELECT id FROM report_channels WHERE channel_code = 'web_portal' LIMIT 1);
SET @cat_medical = (SELECT id FROM report_categories WHERE category_code = 'medical' LIMIT 1);
SET @cat_fire = (SELECT id FROM report_categories WHERE category_code = 'fire' LIMIT 1);
SET @cat_crime = (SELECT id FROM report_categories WHERE category_code = 'crime_public_safety' LIMIT 1);
SET @cat_infra = (SELECT id FROM report_categories WHERE category_code = 'infrastructure_emergency' LIMIT 1);
SET @st_received = (SELECT id FROM intake_statuses WHERE status_code = 'received' LIMIT 1);
SET @st_under_review = (SELECT id FROM intake_statuses WHERE status_code = 'under_review' LIMIT 1);

SET @loc_001 = (SELECT id FROM locations WHERE public_uuid = 'a3000001-0000-4000-8000-000000000001' LIMIT 1);
SET @loc_002 = (SELECT id FROM locations WHERE public_uuid = 'a3000001-0000-4000-8000-000000000002' LIMIT 1);
SET @loc_003 = (SELECT id FROM locations WHERE public_uuid = 'a3000001-0000-4000-8000-000000000003' LIMIT 1);
SET @loc_004 = (SELECT id FROM locations WHERE public_uuid = 'a3000001-0000-4000-8000-000000000004' LIMIT 1);
SET @loc_005 = (SELECT id FROM locations WHERE public_uuid = 'a3000001-0000-4000-8000-000000000005' LIMIT 1);

-- Additional intake reports for reliability demo
INSERT INTO intake_reports (
  public_uuid, report_code, reporter_user_id, channel_id, category_id,
  reported_location_id, summary, description, current_status_id, reported_at
)
SELECT v.puuid, v.rcode, v.reporter, @ch_web, v.category, v.loc, v.summary, v.descr, @st_under_review, v.reported_at
FROM (
  SELECT 'd30000a1-0000-4000-8000-000000000001' AS puuid, 'IR-RISK-DUP-001' AS rcode,
    @karim_id AS reporter, @cat_infra AS category, @loc_002 AS loc,
    'Waterlogging on Station Road again' AS summary,
    'Same flooded stretch reported yesterday during heavy rain.' AS descr,
    DATE_SUB(NOW(), INTERVAL 3 DAY) AS reported_at
  UNION ALL
  SELECT 'd30000a1-0000-4000-8000-000000000002', 'IR-RISK-DUP-002',
    @karim_id, @cat_infra, @loc_002,
    'Station Road flooded — vehicles stuck',
    'Duplicate flooding report from same caller area.',
    DATE_SUB(NOW(), INTERVAL 2 DAY)
  UNION ALL
  SELECT 'd30000a1-0000-4000-8000-000000000003', 'IR-RISK-MIST-001',
    @farhana_id, @cat_fire, @loc_003,
    'Smoke visible from apartment window',
    'Caller thought building was on fire.',
    DATE_SUB(NOW(), INTERVAL 5 DAY)
  UNION ALL
  SELECT 'd30000a1-0000-4000-8000-000000000004', 'IR-RISK-FA-001',
    @farhana_id, @cat_fire, @loc_003,
    'Fire alarm at Ulipur market',
    'Market committee reported blaze; turned out to be festival fireworks.',
    DATE_SUB(NOW(), INTERVAL 8 DAY)
  UNION ALL
  SELECT 'd30000a1-0000-4000-8000-000000000005', 'IR-RISK-FA-002',
    @farhana_id, @cat_fire, @loc_005,
    'Burning smell near Nageshwari bazaar',
    'Strong burning odor; no fire found on inspection.',
    DATE_SUB(NOW(), INTERVAL 12 DAY)
  UNION ALL
  SELECT 'd30000a1-0000-4000-8000-000000000006', 'IR-RISK-FA-003',
    @farhana_id, @cat_fire, @loc_005,
    'Warehouse fire at Nageshwari',
    'Repeated false fire report from same account.',
    DATE_SUB(NOW(), INTERVAL 18 DAY)
  UNION ALL
  SELECT 'd30000a1-0000-4000-8000-000000000007', 'IR-RISK-SPAM-001',
    @shamim_id, @cat_fire, @loc_004,
    'Major fire at Sadar hospital block',
    'Fabricated fire at Kurigram Sadar hospital.',
    DATE_SUB(NOW(), INTERVAL 1 DAY)
  UNION ALL
  SELECT 'd30000a1-0000-4000-8000-000000000008', 'IR-RISK-SPAM-002',
    @shamim_id, @cat_crime, @loc_004,
    'Armed robbery in progress at pharmacy lane',
    'Fake armed robbery report to provoke response.',
    DATE_SUB(NOW(), INTERVAL 12 HOUR)
  UNION ALL
  SELECT 'd30000a1-0000-4000-8000-000000000009', 'IR-RISK-SPAM-003',
    @shamim_id, @cat_fire, @loc_001,
    'School building on fire in Kurigram Sadar',
    'Third malicious fire report today from same user.',
    DATE_SUB(NOW(), INTERVAL 4 HOUR)
  UNION ALL
  SELECT 'd30000a1-0000-4000-8000-000000000010', 'IR-RISK-RUB-001',
    @rubel_id, @cat_fire, @loc_002,
    'Gas cylinder explosion reported',
    'No explosion found; caller may have misheard construction noise.',
    DATE_SUB(NOW(), INTERVAL 6 DAY)
  UNION ALL
  SELECT 'd30000a1-0000-4000-8000-000000000011', 'IR-RISK-RUB-002',
    @rubel_id, @cat_fire, @loc_002,
    'Fire at Chilmari residential complex',
    'False alarm — cooking smoke only.',
    DATE_SUB(NOW(), INTERVAL 4 DAY)
) AS v
WHERE v.reporter IS NOT NULL AND v.loc IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM intake_reports ir WHERE ir.public_uuid = v.puuid);

-- Verification reviews (latest per report drives reliability view)
INSERT INTO intake_report_verification_reviews (
  public_uuid, intake_report_id, reviewed_by_user_id, verdict, reason, evidence_note, confidence_level, created_at
)
SELECT v.vuuid, ir.id, @dispatcher_id, v.verdict, v.reason, v.evidence, v.confidence, v.created_at
FROM (
  SELECT 'v30000a1-0000-4000-8000-000000000001' AS vuuid, 'd3000001-0000-4000-8000-000000000001' AS rpt,
    'genuine' AS verdict, 'Medical symptoms confirmed by follow-up' AS reason,
    'Neighbor later transported to Kurigram General Hospital.' AS evidence, 'high' AS confidence,
    DATE_SUB(NOW(), INTERVAL 110 MINUTE) AS created_at
  UNION ALL
  SELECT 'v30000a1-0000-4000-8000-000000000002', 'd3000001-0000-4000-8000-000000000002',
    'genuine', 'Fire service detected gas leak on site',
    'Fire unit confirmed odor source and ventilated building.', 'high',
    DATE_SUB(NOW(), INTERVAL 90 MINUTE)
  UNION ALL
  SELECT 'v30000a1-0000-4000-8000-000000000003', 'd30000a1-0000-4000-8000-000000000001',
    'duplicate', 'Same location as prior flood report',
    'Linked to IR-RISK-DUP-001 from previous day.', 'medium',
    DATE_SUB(NOW(), INTERVAL 2 DAY)
  UNION ALL
  SELECT 'v30000a1-0000-4000-8000-000000000004', 'd30000a1-0000-4000-8000-000000000003',
    'mistaken', 'Cooking smoke mistaken for structural fire',
    'Resident confirmed heavy spice frying; no fire.', 'medium',
    DATE_SUB(NOW(), INTERVAL 4 DAY)
  UNION ALL
  SELECT 'v30000a1-0000-4000-8000-000000000005', 'd30000a1-0000-4000-8000-000000000004',
    'false_alarm', 'Festival fireworks caused smoke',
    'Local UP confirmed permitted fireworks display.', 'high',
    DATE_SUB(NOW(), INTERVAL 7 DAY)
  UNION ALL
  SELECT 'v30000a1-0000-4000-8000-000000000006', 'd30000a1-0000-4000-8000-000000000005',
    'false_alarm', 'Burning trash pile — no emergency',
    'Municipal workers burning waste legally.', 'medium',
    DATE_SUB(NOW(), INTERVAL 11 DAY)
  UNION ALL
  SELECT 'v30000a1-0000-4000-8000-000000000007', 'd30000a1-0000-4000-8000-000000000006',
    'false_alarm', 'Third false fire from same reporter',
    'No fire found on three consecutive checks.', 'high',
    DATE_SUB(NOW(), INTERVAL 17 DAY)
  UNION ALL
  SELECT 'v30000a1-0000-4000-8000-000000000008', 'd30000a1-0000-4000-8000-000000000007',
    'malicious_false_report', 'Hospital confirmed no incident',
    'Kurigram Sadar hospital security denied any fire.', 'high',
    DATE_SUB(NOW(), INTERVAL 20 HOUR)
  UNION ALL
  SELECT 'v30000a1-0000-4000-8000-000000000009', 'd30000a1-0000-4000-8000-000000000008',
    'malicious_false_report', 'Police patrol found no robbery',
    'Pharmacy lane quiet; likely intentional hoax.', 'high',
    DATE_SUB(NOW(), INTERVAL 10 HOUR)
  UNION ALL
  SELECT 'v30000a1-0000-4000-8000-000000000010', 'd30000a1-0000-4000-8000-000000000009',
    'malicious_false_report', 'Repeated hoax fire reports same day',
    'Three fabricated school fire reports within 24 hours.', 'high',
    DATE_SUB(NOW(), INTERVAL 3 HOUR)
  UNION ALL
  SELECT 'v30000a1-0000-4000-8000-000000000011', 'd30000a1-0000-4000-8000-000000000010',
    'false_alarm', 'Construction noise misreported as explosion',
    'Site supervisor confirmed routine welding.', 'medium',
    DATE_SUB(NOW(), INTERVAL 5 DAY)
  UNION ALL
  SELECT 'v30000a1-0000-4000-8000-000000000012', 'd30000a1-0000-4000-8000-000000000011',
    'false_alarm', 'Cooking smoke only',
    'Tenant admitted leaving stove unattended.', 'medium',
    DATE_SUB(NOW(), INTERVAL 3 DAY)
) AS v
INNER JOIN intake_reports ir ON ir.public_uuid = v.rpt
WHERE @dispatcher_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM intake_report_verification_reviews x WHERE x.public_uuid = v.vuuid
  );

-- Account actions demo
INSERT INTO reporter_account_actions (
  public_uuid, target_user_id, action_by_user_id, action_type,
  previous_account_status, new_account_status, reason, suspension_ends_at, created_at
)
SELECT v.auuid, v.target, @admin_id, v.action_type, v.prev, v.new_status, v.reason, v.suspension_ends_at, v.created_at
FROM (
  SELECT 'a30000a1-0000-4000-8000-000000000001' AS auuid, @farhana_id AS target,
    'warning' AS action_type, 'active' AS prev, 'active' AS new_status,
    'First confirmed false report. Citizen warned about verifying emergencies before submitting.' AS reason,
    NULL AS suspension_ends_at,
    DATE_SUB(NOW(), INTERVAL 10 DAY) AS created_at
  UNION ALL
  SELECT 'a30000a1-0000-4000-8000-000000000002', @shamim_id,
    'suspension', 'active', 'suspended',
    'Repeated confirmed malicious false reports within 24 hours. 30-day suspension.',
    DATE_ADD(NOW(), INTERVAL 30 DAY),
    DATE_SUB(NOW(), INTERVAL 2 HOUR)
) AS v
WHERE v.target IS NOT NULL AND @admin_id IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM reporter_account_actions raa WHERE raa.public_uuid = v.auuid);

UPDATE users
SET
  account_status = 'suspended',
  account_status_reason = 'Repeated confirmed malicious false reports within 24 hours. 30-day suspension.',
  account_status_expires_at = DATE_ADD(NOW(), INTERVAL 30 DAY)
WHERE id = @shamim_id
  AND @shamim_id IS NOT NULL
  AND EXISTS (
    SELECT 1 FROM reporter_account_actions
    WHERE target_user_id = @shamim_id AND action_type = 'suspension'
  );
