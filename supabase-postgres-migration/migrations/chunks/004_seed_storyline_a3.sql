DO $$
DECLARE
  v_system_admin_id BIGINT;
  v_dispatcher_id BIGINT;
  v_rahima_id BIGINT;
  v_karim_id BIGINT;
  v_farhana_id BIGINT;
  v_rubel_id BIGINT;
  v_fire_rep_id BIGINT;
  v_police_rep_id BIGINT;
  v_medical_rep_id BIGINT;
  v_relief_rep_id BIGINT;
  v_shelter_rep_id BIGINT;
  v_ch_web BIGINT;
  v_cat_fire BIGINT;
  v_cat_infra BIGINT;
  v_cat_disaster BIGINT;
  v_cat_relief BIGINT;
  v_cat_medical BIGINT;
  v_intake_received BIGINT;
  v_intake_under_review BIGINT;
  v_intake_linked_case BIGINT;
  v_case_under_review BIGINT;
  v_case_submitted BIGINT;
  v_unit_available BIGINT;
  v_area_dhaka_div BIGINT;
  v_area_dhaka_dist BIGINT;
  v_area_puran_dhaka BIGINT;
  v_area_rangpur_div BIGINT;
  v_area_kurigram_dist BIGINT;
  v_area_kur_sadar BIGINT;
  v_area_chilmari BIGINT;
  v_area_ulipur BIGINT;
  v_area_gaibandha_dist BIGINT;
  v_area_gai_sadar BIGINT;
  v_area_fulchhari BIGINT;
  v_area_sundarganj BIGINT;
  v_loc_fire_main BIGINT;
  v_loc_fire_smoke BIGINT;
  v_loc_fire_market BIGINT;
  v_loc_fire_lane BIGINT;
  v_loc_fire_wrong BIGINT;
  v_loc_service BIGINT;
  v_loc_kur_sadar BIGINT;
  v_loc_chilmari BIGINT;
  v_loc_ulipur BIGINT;
  v_loc_gai_sadar BIGINT;
  v_loc_fulchhari BIGINT;
  v_loc_sundarganj BIGINT;
  v_contact_shop_owner BIGINT;
  v_contact_passerby BIGINT;
  v_contact_kur_volunteer BIGINT;
  v_contact_gai_volunteer BIGINT;
  v_contact_ulipur_volunteer BIGINT;
  v_contact_sundarganj_volunteer BIGINT;
  v_ir_service BIGINT;
  v_case_civic BIGINT;
  v_ir_false_fire BIGINT;
  v_atype_fire BIGINT;
  v_atype_police BIGINT;
  v_atype_medical BIGINT;
  v_atype_disaster BIGINT;
  v_atype_ngo BIGINT;
  v_atype_local BIGINT;
  v_agency_dhk_fire BIGINT;
  v_agency_dhk_police BIGINT;
  v_agency_dhk_medical BIGINT;
  v_agency_nat_dmr BIGINT;
  v_agency_nat_shelter BIGINT;
  v_agency_nat_medical BIGINT;
  v_agency_nat_police BIGINT;
  v_agency_nat_rescue BIGINT;
  v_ut_fire_truck BIGINT;
  v_ut_command BIGINT;
  v_ut_ambulance BIGINT;
  v_ut_police BIGINT;
  v_ut_rescue_boat BIGINT;
  v_ut_relief_truck BIGINT;
  v_ft_hospital BIGINT;
  v_ft_shelter BIGINT;
  v_ft_warehouse BIGINT;
  v_ft_school_shelter BIGINT;
  v_ft_community_center BIGINT;
  v_loc_fac_kur_shelter BIGINT;
  v_loc_fac_chilmari_shelter BIGINT;
  v_loc_fac_kur_hub BIGINT;
  v_loc_fac_kur_hospital BIGINT;
  v_loc_fac_gai_shelter BIGINT;
  v_loc_fac_fulchhari_shelter BIGINT;
  v_loc_fac_gai_hub BIGINT;
  v_loc_fac_gai_hospital BIGINT;
  v_fac_shelter_kur_01 BIGINT;
  v_fac_shelter_kur_02 BIGINT;
  v_fac_hub_kur_01 BIGINT;
  v_fac_hosp_kur_01 BIGINT;
  v_fac_shelter_gai_01 BIGINT;
  v_fac_shelter_gai_02 BIGINT;
  v_fac_hub_gai_01 BIGINT;
  v_fac_hosp_gai_01 BIGINT;
BEGIN
-- ============================================================
-- 1. Common lookups and user variables
-- ============================================================

  SELECT u.id
    FROM users u
    INNER JOIN user_roles ur ON ur.user_id = u.id
    INNER JOIN roles r ON r.id = ur.role_id
    WHERE r.role_code = 'system_admin'
    ORDER BY u.id
    LIMIT 1 INTO v_system_admin_id;

  v_dispatcher_id := COALESCE(
    (SELECT id FROM users WHERE email = 'dispatcher@niers.test' LIMIT 1),
    (SELECT u.id
     FROM users u
     INNER JOIN user_roles ur ON ur.user_id = u.id
     INNER JOIN roles r ON r.id = ur.role_id
     WHERE r.role_code = 'dispatcher'
     ORDER BY u.id
     LIMIT 1)
  );

  SELECT id FROM users WHERE email = 'citizen.rahima@niers.test' LIMIT 1 INTO v_rahima_id;
  SELECT id FROM users WHERE email = 'citizen.karim@niers.test' LIMIT 1 INTO v_karim_id;
  SELECT id FROM users WHERE email = 'citizen.farhana@niers.test' LIMIT 1 INTO v_farhana_id;
  SELECT id FROM users WHERE email = 'citizen.rubel@niers.test' LIMIT 1 INTO v_rubel_id;
  SELECT id FROM users WHERE email = 'fire.rep@niers.test' LIMIT 1 INTO v_fire_rep_id;
  SELECT id FROM users WHERE email = 'police.rep@niers.test' LIMIT 1 INTO v_police_rep_id;
  SELECT id FROM users WHERE email = 'medical.rep@niers.test' LIMIT 1 INTO v_medical_rep_id;
  SELECT id FROM users WHERE email = 'relief.rep@niers.test' LIMIT 1 INTO v_relief_rep_id;
  SELECT id FROM users WHERE email = 'shelter.rep@niers.test' LIMIT 1 INTO v_shelter_rep_id;

  SELECT id FROM report_channels WHERE channel_code = 'web_portal' LIMIT 1 INTO v_ch_web;
  SELECT id FROM report_categories WHERE category_code = 'fire' LIMIT 1 INTO v_cat_fire;
  SELECT id FROM report_categories WHERE category_code = 'infrastructure_emergency' LIMIT 1 INTO v_cat_infra;
  SELECT id FROM report_categories WHERE category_code = 'natural_disaster' LIMIT 1 INTO v_cat_disaster;
  SELECT id FROM report_categories WHERE category_code = 'relief_request' LIMIT 1 INTO v_cat_relief;
  SELECT id FROM report_categories WHERE category_code = 'medical' LIMIT 1 INTO v_cat_medical;

  SELECT id FROM intake_statuses WHERE status_code = 'received' LIMIT 1 INTO v_intake_received;
  SELECT id FROM intake_statuses WHERE status_code = 'under_review' LIMIT 1 INTO v_intake_under_review;
  SELECT id FROM intake_statuses WHERE status_code = 'linked_to_case' LIMIT 1 INTO v_intake_linked_case;
  SELECT id FROM case_statuses WHERE status_code = 'under_review' LIMIT 1 INTO v_case_under_review;
  SELECT id FROM case_statuses WHERE status_code = 'submitted' LIMIT 1 INTO v_case_submitted;
  SELECT id FROM unit_statuses WHERE status_code = 'available' LIMIT 1 INTO v_unit_available;

SELECT id FROM locations WHERE public_uuid = 'a9110001-0000-4000-8000-000000000001' LIMIT 1 INTO v_loc_fire_main;
  SELECT id FROM locations WHERE public_uuid = 'a9110002-0000-4000-8000-000000000002' LIMIT 1 INTO v_loc_fire_smoke;
  SELECT id FROM locations WHERE public_uuid = 'a9110003-0000-4000-8000-000000000003' LIMIT 1 INTO v_loc_fire_market;
  SELECT id FROM locations WHERE public_uuid = 'a9110004-0000-4000-8000-000000000004' LIMIT 1 INTO v_loc_fire_lane;
  SELECT id FROM locations WHERE public_uuid = 'a9110005-0000-4000-8000-000000000005' LIMIT 1 INTO v_loc_fire_wrong;
  SELECT id FROM locations WHERE public_uuid = 'a9110006-0000-4000-8000-000000000006' LIMIT 1 INTO v_loc_service;

  SELECT id FROM locations WHERE public_uuid = 'a9220001-0000-4000-8000-000000000001' LIMIT 1 INTO v_loc_kur_sadar;
  SELECT id FROM locations WHERE public_uuid = 'a9220002-0000-4000-8000-000000000002' LIMIT 1 INTO v_loc_chilmari;
  SELECT id FROM locations WHERE public_uuid = 'a9220003-0000-4000-8000-000000000003' LIMIT 1 INTO v_loc_ulipur;
  SELECT id FROM locations WHERE public_uuid = 'a9220004-0000-4000-8000-000000000004' LIMIT 1 INTO v_loc_gai_sadar;
  SELECT id FROM locations WHERE public_uuid = 'a9220005-0000-4000-8000-000000000005' LIMIT 1 INTO v_loc_fulchhari;
  SELECT id FROM locations WHERE public_uuid = 'a9220006-0000-4000-8000-000000000006' LIMIT 1 INTO v_loc_sundarganj;

SELECT id FROM reporter_contacts WHERE phone_number = '01710001001' LIMIT 1 INTO v_contact_shop_owner;
  SELECT id FROM reporter_contacts WHERE phone_number = '01710001002' LIMIT 1 INTO v_contact_passerby;
  SELECT id FROM reporter_contacts WHERE phone_number = '01710002001' LIMIT 1 INTO v_contact_kur_volunteer;
  SELECT id FROM reporter_contacts WHERE phone_number = '01710002002' LIMIT 1 INTO v_contact_gai_volunteer;
  SELECT id FROM reporter_contacts WHERE phone_number = '01710002003' LIMIT 1 INTO v_contact_ulipur_volunteer;
  SELECT id FROM reporter_contacts WHERE phone_number = '01710002004' LIMIT 1 INTO v_contact_sundarganj_volunteer;

-- ============================================================
-- 6. Storyline 1: Fire intake reports before live 999 call
-- ============================================================

  INSERT INTO intake_reports (public_uuid, report_code, reporter_user_id, reporter_contact_id, channel_id, category_id, reported_location_id, summary, description, current_status_id, final_disposition, received_by_user_id, reported_at)
  SELECT 'b9110001-0000-4000-8000-000000000001', 'IR-DHK-FIRE-001', v_rahima_id, NULL, v_ch_web, v_cat_fire, v_loc_fire_smoke,
         'Heavy black smoke near old warehouse lane',
         'Heavy black smoke is coming from an old warehouse lane in Puran Dhaka. The exact source is not confirmed yet.',
         v_intake_received, NULL, NULL, NOW() - INTERVAL '32 minute'
  WHERE v_rahima_id IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM intake_reports WHERE report_code = 'IR-DHK-FIRE-001');

  INSERT INTO intake_reports (public_uuid, report_code, reporter_user_id, reporter_contact_id, channel_id, category_id, reported_location_id, summary, description, current_status_id, final_disposition, received_by_user_id, reported_at)
  SELECT 'b9110002-0000-4000-8000-000000000002', 'IR-DHK-FIRE-002', v_karim_id, NULL, v_ch_web, v_cat_fire, v_loc_fire_market,
         'Smoke spreading near market entrance',
         'Smoke is spreading toward the market entrance. People are gathering and traffic is slowing down.',
         v_intake_received, NULL, NULL, NOW() - INTERVAL '28 minute'
  WHERE v_karim_id IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM intake_reports WHERE report_code = 'IR-DHK-FIRE-002');

  INSERT INTO intake_reports (public_uuid, report_code, reporter_user_id, reporter_contact_id, channel_id, category_id, reported_location_id, summary, description, current_status_id, final_disposition, received_by_user_id, reported_at)
  SELECT 'b9110003-0000-4000-8000-000000000003', 'IR-DHK-FIRE-003', NULL, v_contact_shop_owner, v_ch_web, v_cat_fire, v_loc_fire_lane,
         'Flames visible from second floor of warehouse',
         'A shop owner reports visible flames from the second floor of the old warehouse building.',
         v_intake_received, NULL, NULL, NOW() - INTERVAL '24 minute'
  WHERE v_contact_shop_owner IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM intake_reports WHERE report_code = 'IR-DHK-FIRE-003');

  INSERT INTO intake_reports (public_uuid, report_code, reporter_user_id, reporter_contact_id, channel_id, category_id, reported_location_id, summary, description, current_status_id, final_disposition, received_by_user_id, reported_at)
  SELECT 'b9110004-0000-4000-8000-000000000004', 'IR-DHK-FIRE-004', NULL, v_contact_passerby, v_ch_web, v_cat_fire, v_loc_fire_market,
         'People running from smoke near market lane',
         'Several people are moving away from the market lane because of thick smoke and possible fire spread.',
         v_intake_received, NULL, NULL, NOW() - INTERVAL '20 minute'
  WHERE v_contact_passerby IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM intake_reports WHERE report_code = 'IR-DHK-FIRE-004');

  INSERT INTO intake_reports (public_uuid, report_code, reporter_user_id, reporter_contact_id, channel_id, category_id, reported_location_id, summary, description, current_status_id, final_disposition, received_by_user_id, reported_at)
  SELECT 'b9110005-0000-4000-8000-000000000005', 'IR-DHK-FIRE-005', v_farhana_id, NULL, v_ch_web, v_cat_fire, v_loc_fire_wrong,
         'Huge fire reported in a different lane',
         'Reporter claims a huge fire is happening in a different lane, but the location does not match other reports.',
         v_intake_under_review, NULL, v_dispatcher_id, NOW() - INTERVAL '18 minute'
  WHERE v_farhana_id IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM intake_reports WHERE report_code = 'IR-DHK-FIRE-005');

  INSERT INTO intake_reports (public_uuid, report_code, reporter_user_id, reporter_contact_id, channel_id, category_id, reported_location_id, summary, description, current_status_id, final_disposition, received_by_user_id, reported_at)
  SELECT 'b9110006-0000-4000-8000-000000000006', 'IR-DHK-FIRE-006', v_rubel_id, NULL, v_ch_web, v_cat_fire, v_loc_fire_market,
         'Smoke affecting traffic near old Dhaka road',
         'Smoke from the old warehouse area is affecting nearby traffic and pedestrians.',
         v_intake_received, NULL, NULL, NOW() - INTERVAL '15 minute'
  WHERE v_rubel_id IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM intake_reports WHERE report_code = 'IR-DHK-FIRE-006');

-- Optional verification record for the conflicting report. The presenter can also create/update this live if the UI supports it.
  SELECT id FROM intake_reports WHERE report_code = 'IR-DHK-FIRE-005' LIMIT 1 INTO v_ir_false_fire;
  INSERT INTO intake_report_verification_reviews (public_uuid, intake_report_id, reviewed_by_user_id, verdict, reason, evidence_note, confidence_level)
  SELECT 'e9110005-0000-4000-8000-000000000005', v_ir_false_fire, v_dispatcher_id, 'unverified',
         'Location and description do not match confirmed fire location',
         'Other reports and the incoming 999 call point to the old warehouse lane, not this separate lane.',
         'medium'
  WHERE v_ir_false_fire IS NOT NULL
    AND v_dispatcher_id IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM intake_report_verification_reviews WHERE public_uuid = 'e9110005-0000-4000-8000-000000000005');

-- ============================================================
END $$;