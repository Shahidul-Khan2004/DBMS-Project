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
-- NIERS Storyline Demo Seed Data
--   Storyline 1: Fire in Puran Dhaka
--   Storyline 2: National Flood Disaster in Kurigram and Gaibandha
-- 
--   Intended use:
--   - Open this file in DBeaver connected to the NIERS MySQL database.
--   - Run the whole script once before recording.
--   - It is idempotent: it uses stable codes/UUIDs and does not delete/reset existing data.
-- 
--   Important:
--   - Demo users are NOT inserted here. They should already be bootstrapped by the backend.
--   - This script prepares setup data only.
--   - The following should still be created live in the UI for the video:
--     1) 999 intake for Puran Dhaka fire
--     2) Fire emergency incident creation
--     3) Linking fire reports to the incident
--     4) Agency assignment and dispatch creation/status updates
--     5) Disaster event creation and declaration
--     6) Shelter activation and agency relief request
--     7) Final incident/disaster resolution






-- ============================================================
-- 0. Reference data safety inserts
-- ============================================================

  INSERT INTO report_channels (channel_code, name, description) VALUES
  ('web_portal','Web Portal','Logged-in web portal report'),
  ('emergency_call','999 Emergency Call','Emergency phone call intake'),
  ('admin_entry','Admin Entry','Created by admin/operator'),
  ('agency_report','Agency Report','Reported by an agency') ON CONFLICT DO NOTHING;

  INSERT INTO report_categories (category_code, name, description) VALUES
  ('medical','Medical','Medical emergency or health-related issue'),
  ('crime_public_safety','Crime/Public Safety','Crime, assault, missing person, public safety'),
  ('fire','Fire','Fire, explosion, gas leak'),
  ('natural_disaster','Natural Disaster','Flood, cyclone, earthquake, landslide'),
  ('infrastructure_emergency','Infrastructure Emergency','Bridge collapse, power failure, road hazard'),
  ('relief_request','Relief Request','Food, water, medicine or shelter need') ON CONFLICT DO NOTHING;

  INSERT INTO agency_types (type_code, name) VALUES
  ('police','Police'),
  ('fire_service','Fire Service'),
  ('medical_service','Medical Service'),
  ('disaster_management','Disaster Management'),
  ('ngo','NGO'),
  ('local_government','Local Government') ON CONFLICT DO NOTHING;

  INSERT INTO capabilities (capability_code, name, capability_group) VALUES
  ('ambulance_service','Ambulance Service','medical'),
  ('fire_suppression','Fire Suppression','fire'),
  ('water_rescue','Water Rescue','rescue'),
  ('search_and_rescue','Search and Rescue','rescue'),
  ('crowd_control','Crowd Control','security'),
  ('medical_triage','Medical Triage','medical'),
  ('food_distribution','Food Distribution','relief'),
  ('relief_distribution_hub','Relief Distribution Hub','relief'),
  ('temporary_shelter','Temporary Shelter','shelter'),
  ('emergency_care','Emergency Care','medical') ON CONFLICT DO NOTHING;

  INSERT INTO emergency_unit_types (type_code, name) VALUES
  ('ambulance','Ambulance'),
  ('fire_truck','Fire Truck'),
  ('police_vehicle','Police Vehicle'),
  ('rescue_boat','Rescue Boat'),
  ('relief_truck','Relief Truck'),
  ('command_vehicle','Command Vehicle') ON CONFLICT DO NOTHING;

  INSERT INTO disaster_event_types (type_code, name) VALUES
  ('flood','Flood'),
  ('cyclone','Cyclone'),
  ('earthquake','Earthquake'),
  ('landslide','Landslide') ON CONFLICT DO NOTHING;

  INSERT INTO facility_types (type_code, name) VALUES
  ('hospital','Hospital'),
  ('shelter','Shelter'),
  ('relief_center','Relief Center'),
  ('warehouse','Warehouse'),
  ('school_shelter_capable','School / Shelter Capable'),
  ('community_center','Community Center') ON CONFLICT DO NOTHING;

  INSERT INTO relief_items (item_code, name, unit_of_measure) VALUES
  ('rice','Rice','kg'),
  ('bottled_water','Bottled Water','bottle'),
  ('dry_food_packet','Dry Food Packet','packet'),
  ('blanket','Blanket','piece'),
  ('medicine_kit','Medicine Kit','kit'),
  ('hygiene_kit','Hygiene Kit','kit') ON CONFLICT DO NOTHING;

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

-- ============================================================
-- 2. Administrative areas for Dhaka, Kurigram, and Gaibandha
-- ============================================================

  INSERT INTO administrative_areas (parent_area_id, area_type, name, code)
  SELECT NULL, 'division', 'Dhaka Division', 'BD-DIV-DHAKA'
  WHERE NOT EXISTS (SELECT 1 FROM administrative_areas WHERE code = 'BD-DIV-DHAKA');
  SELECT id FROM administrative_areas WHERE code = 'BD-DIV-DHAKA' LIMIT 1 INTO v_area_dhaka_div;

  INSERT INTO administrative_areas (parent_area_id, area_type, name, code)
  SELECT v_area_dhaka_div, 'district', 'Dhaka', 'BD-DIST-DHAKA'
  WHERE NOT EXISTS (SELECT 1 FROM administrative_areas WHERE code = 'BD-DIST-DHAKA');
  SELECT id FROM administrative_areas WHERE code = 'BD-DIST-DHAKA' LIMIT 1 INTO v_area_dhaka_dist;

  INSERT INTO administrative_areas (parent_area_id, area_type, name, code)
  SELECT v_area_dhaka_dist, 'area', 'Puran Dhaka', 'BD-AREA-PURAN-DHAKA'
  WHERE NOT EXISTS (SELECT 1 FROM administrative_areas WHERE code = 'BD-AREA-PURAN-DHAKA');
  SELECT id FROM administrative_areas WHERE code = 'BD-AREA-PURAN-DHAKA' LIMIT 1 INTO v_area_puran_dhaka;

  INSERT INTO administrative_areas (parent_area_id, area_type, name, code)
  SELECT NULL, 'division', 'Rangpur Division', 'BD-DIV-RANGPUR'
  WHERE NOT EXISTS (SELECT 1 FROM administrative_areas WHERE code = 'BD-DIV-RANGPUR');
  SELECT id FROM administrative_areas WHERE code = 'BD-DIV-RANGPUR' LIMIT 1 INTO v_area_rangpur_div;

  INSERT INTO administrative_areas (parent_area_id, area_type, name, code)
  SELECT v_area_rangpur_div, 'district', 'Kurigram', 'BD-DIST-KURIGRAM'
  WHERE NOT EXISTS (SELECT 1 FROM administrative_areas WHERE code = 'BD-DIST-KURIGRAM');
  SELECT id FROM administrative_areas WHERE code = 'BD-DIST-KURIGRAM' LIMIT 1 INTO v_area_kurigram_dist;

  INSERT INTO administrative_areas (parent_area_id, area_type, name, code)
  SELECT v_area_kurigram_dist, 'upazila', 'Kurigram Sadar', 'BD-UPZ-KUR-SADAR'
  WHERE NOT EXISTS (SELECT 1 FROM administrative_areas WHERE code = 'BD-UPZ-KUR-SADAR');
  INSERT INTO administrative_areas (parent_area_id, area_type, name, code)
  SELECT v_area_kurigram_dist, 'upazila', 'Chilmari', 'BD-UPZ-CHILMARI'
  WHERE NOT EXISTS (SELECT 1 FROM administrative_areas WHERE code = 'BD-UPZ-CHILMARI');
  INSERT INTO administrative_areas (parent_area_id, area_type, name, code)
  SELECT v_area_kurigram_dist, 'upazila', 'Ulipur', 'BD-UPZ-ULIPUR'
  WHERE NOT EXISTS (SELECT 1 FROM administrative_areas WHERE code = 'BD-UPZ-ULIPUR');

  SELECT id FROM administrative_areas WHERE code = 'BD-UPZ-KUR-SADAR' LIMIT 1 INTO v_area_kur_sadar;
  SELECT id FROM administrative_areas WHERE code = 'BD-UPZ-CHILMARI' LIMIT 1 INTO v_area_chilmari;
  SELECT id FROM administrative_areas WHERE code = 'BD-UPZ-ULIPUR' LIMIT 1 INTO v_area_ulipur;

  INSERT INTO administrative_areas (parent_area_id, area_type, name, code)
  SELECT v_area_rangpur_div, 'district', 'Gaibandha', 'BD-DIST-GAIBANDHA'
  WHERE NOT EXISTS (SELECT 1 FROM administrative_areas WHERE code = 'BD-DIST-GAIBANDHA');
  SELECT id FROM administrative_areas WHERE code = 'BD-DIST-GAIBANDHA' LIMIT 1 INTO v_area_gaibandha_dist;

  INSERT INTO administrative_areas (parent_area_id, area_type, name, code)
  SELECT v_area_gaibandha_dist, 'upazila', 'Gaibandha Sadar', 'BD-UPZ-GAI-SADAR'
  WHERE NOT EXISTS (SELECT 1 FROM administrative_areas WHERE code = 'BD-UPZ-GAI-SADAR');
  INSERT INTO administrative_areas (parent_area_id, area_type, name, code)
  SELECT v_area_gaibandha_dist, 'upazila', 'Fulchhari', 'BD-UPZ-FULCHHARI'
  WHERE NOT EXISTS (SELECT 1 FROM administrative_areas WHERE code = 'BD-UPZ-FULCHHARI');
  INSERT INTO administrative_areas (parent_area_id, area_type, name, code)
  SELECT v_area_gaibandha_dist, 'upazila', 'Sundarganj', 'BD-UPZ-SUNDARGANJ'
  WHERE NOT EXISTS (SELECT 1 FROM administrative_areas WHERE code = 'BD-UPZ-SUNDARGANJ');

  SELECT id FROM administrative_areas WHERE code = 'BD-UPZ-GAI-SADAR' LIMIT 1 INTO v_area_gai_sadar;
  SELECT id FROM administrative_areas WHERE code = 'BD-UPZ-FULCHHARI' LIMIT 1 INTO v_area_fulchhari;
  SELECT id FROM administrative_areas WHERE code = 'BD-UPZ-SUNDARGANJ' LIMIT 1 INTO v_area_sundarganj;

-- ============================================================
-- 8. Storyline 2: Flood intake reports before live disaster declaration
-- ============================================================

  INSERT INTO intake_reports (public_uuid, report_code, reporter_user_id, reporter_contact_id, channel_id, category_id, reported_location_id, summary, description, current_status_id, final_disposition, received_by_user_id, reported_at)
  SELECT 'b9220001-0000-4000-8000-000000000001', 'IR-KUR-FLD-001', v_rahima_id, NULL, v_ch_web, v_cat_disaster, v_loc_kur_sadar,
         'River water entering houses near Kurigram Sadar',
         'River water is entering low-lying homes near Kurigram Sadar. Families are moving belongings to higher ground.',
         v_intake_received, NULL, NULL, NOW() - INTERVAL '50 minute'
  WHERE v_rahima_id IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM intake_reports WHERE report_code = 'IR-KUR-FLD-001');

  INSERT INTO intake_reports (public_uuid, report_code, reporter_user_id, reporter_contact_id, channel_id, category_id, reported_location_id, summary, description, current_status_id, final_disposition, received_by_user_id, reported_at)
  SELECT 'b9220002-0000-4000-8000-000000000002', 'IR-KUR-FLD-002', v_karim_id, NULL, v_ch_web, v_cat_disaster, v_loc_chilmari,
         'Several families stranded near embankment',
         'Families are stranded near the Chilmari embankment and need rescue support as water keeps rising.',
         v_intake_received, NULL, NULL, NOW() - INTERVAL '46 minute'
  WHERE v_karim_id IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM intake_reports WHERE report_code = 'IR-KUR-FLD-002');

  INSERT INTO intake_reports (public_uuid, report_code, reporter_user_id, reporter_contact_id, channel_id, category_id, reported_location_id, summary, description, current_status_id, final_disposition, received_by_user_id, reported_at)
  SELECT 'b9220003-0000-4000-8000-000000000003', 'IR-KUR-FLD-003', NULL, v_contact_ulipur_volunteer, v_ch_web, v_cat_infra, v_loc_ulipur,
         'Road access blocked by floodwater in Ulipur',
         'Road access is blocked by floodwater and vehicles cannot move toward the affected village.',
         v_intake_received, NULL, NULL, NOW() - INTERVAL '42 minute'
  WHERE v_contact_ulipur_volunteer IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM intake_reports WHERE report_code = 'IR-KUR-FLD-003');

  INSERT INTO intake_reports (public_uuid, report_code, reporter_user_id, reporter_contact_id, channel_id, category_id, reported_location_id, summary, description, current_status_id, final_disposition, received_by_user_id, reported_at)
  SELECT 'b9220004-0000-4000-8000-000000000004', 'IR-KUR-FLD-004', NULL, v_contact_kur_volunteer, v_ch_web, v_cat_relief, v_loc_kur_sadar,
         'Families need dry food and drinking water',
         'Flood-affected families near Kurigram Sadar need dry food, drinking water, and basic medicine.',
         v_intake_received, NULL, NULL, NOW() - INTERVAL '38 minute'
  WHERE v_contact_kur_volunteer IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM intake_reports WHERE report_code = 'IR-KUR-FLD-004');

  INSERT INTO intake_reports (public_uuid, report_code, reporter_user_id, reporter_contact_id, channel_id, category_id, reported_location_id, summary, description, current_status_id, final_disposition, received_by_user_id, reported_at)
  SELECT 'b9220005-0000-4000-8000-000000000005', 'IR-GAI-FLD-001', v_farhana_id, NULL, v_ch_web, v_cat_disaster, v_loc_gai_sadar,
         'Low-lying homes flooded in Gaibandha Sadar',
         'Low-lying homes in Gaibandha Sadar are flooded. Families are requesting shelter information.',
         v_intake_received, NULL, NULL, NOW() - INTERVAL '35 minute'
  WHERE v_farhana_id IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM intake_reports WHERE report_code = 'IR-GAI-FLD-001');

  INSERT INTO intake_reports (public_uuid, report_code, reporter_user_id, reporter_contact_id, channel_id, category_id, reported_location_id, summary, description, current_status_id, final_disposition, received_by_user_id, reported_at)
  SELECT 'b9220006-0000-4000-8000-000000000006', 'IR-GAI-FLD-002', NULL, v_contact_gai_volunteer, v_ch_web, v_cat_relief, v_loc_fulchhari,
         'Shelter needed for displaced families in Fulchhari',
         'Displaced families near Fulchhari need shelter placement and drinking water support.',
         v_intake_received, NULL, NULL, NOW() - INTERVAL '31 minute'
  WHERE v_contact_gai_volunteer IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM intake_reports WHERE report_code = 'IR-GAI-FLD-002');

  INSERT INTO intake_reports (public_uuid, report_code, reporter_user_id, reporter_contact_id, channel_id, category_id, reported_location_id, summary, description, current_status_id, final_disposition, received_by_user_id, reported_at)
  SELECT 'b9220007-0000-4000-8000-000000000007', 'IR-GAI-FLD-003', NULL, v_contact_sundarganj_volunteer, v_ch_web, v_cat_infra, v_loc_sundarganj,
         'Embankment road damaged in Sundarganj',
         'The embankment road is damaged and vehicles cannot pass safely. Local residents need warning and route support.',
         v_intake_received, NULL, NULL, NOW() - INTERVAL '28 minute'
  WHERE v_contact_sundarganj_volunteer IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM intake_reports WHERE report_code = 'IR-GAI-FLD-003');

-- ============================================================
-- 9. Storyline 2: Facilities, shelters, hospitals, and relief hubs
-- ============================================================

  SELECT id FROM facility_types WHERE type_code = 'hospital' LIMIT 1 INTO v_ft_hospital;
  SELECT id FROM facility_types WHERE type_code = 'shelter' LIMIT 1 INTO v_ft_shelter;
  SELECT id FROM facility_types WHERE type_code = 'warehouse' LIMIT 1 INTO v_ft_warehouse;
  SELECT id FROM facility_types WHERE type_code = 'school_shelter_capable' LIMIT 1 INTO v_ft_school_shelter;
  SELECT id FROM facility_types WHERE type_code = 'community_center' LIMIT 1 INTO v_ft_community_center;

  SELECT id FROM locations WHERE public_uuid = 'a9330001-0000-4000-8000-000000000001' LIMIT 1 INTO v_loc_fac_kur_shelter;
  SELECT id FROM locations WHERE public_uuid = 'a9330002-0000-4000-8000-000000000002' LIMIT 1 INTO v_loc_fac_chilmari_shelter;
  SELECT id FROM locations WHERE public_uuid = 'a9330003-0000-4000-8000-000000000003' LIMIT 1 INTO v_loc_fac_kur_hub;
  SELECT id FROM locations WHERE public_uuid = 'a9330004-0000-4000-8000-000000000004' LIMIT 1 INTO v_loc_fac_kur_hospital;
  SELECT id FROM locations WHERE public_uuid = 'a9330005-0000-4000-8000-000000000005' LIMIT 1 INTO v_loc_fac_gai_shelter;
  SELECT id FROM locations WHERE public_uuid = 'a9330006-0000-4000-8000-000000000006' LIMIT 1 INTO v_loc_fac_fulchhari_shelter;
  SELECT id FROM locations WHERE public_uuid = 'a9330007-0000-4000-8000-000000000007' LIMIT 1 INTO v_loc_fac_gai_hub;
  SELECT id FROM locations WHERE public_uuid = 'a9330008-0000-4000-8000-000000000008' LIMIT 1 INTO v_loc_fac_gai_hospital;

  INSERT INTO facilities (public_uuid, facility_type_id, facility_code, name, location_id, owning_agency_id, is_active)
  SELECT 'f9330001-0000-4000-8000-000000000001', v_ft_school_shelter, 'SHELTER-KUR-01', 'Kurigram College Shelter', v_loc_fac_kur_shelter, v_agency_nat_shelter, TRUE
  WHERE NOT EXISTS (SELECT 1 FROM facilities WHERE facility_code = 'SHELTER-KUR-01');
  INSERT INTO facilities (public_uuid, facility_type_id, facility_code, name, location_id, owning_agency_id, is_active)
  SELECT 'f9330002-0000-4000-8000-000000000002', v_ft_school_shelter, 'SHELTER-KUR-02', 'Chilmari High School Shelter', v_loc_fac_chilmari_shelter, v_agency_nat_shelter, TRUE
  WHERE NOT EXISTS (SELECT 1 FROM facilities WHERE facility_code = 'SHELTER-KUR-02');
  INSERT INTO facilities (public_uuid, facility_type_id, facility_code, name, location_id, owning_agency_id, is_active)
  SELECT 'f9330003-0000-4000-8000-000000000003', v_ft_warehouse, 'HUB-KUR-01', 'Kurigram Relief Warehouse', v_loc_fac_kur_hub, v_agency_nat_dmr, TRUE
  WHERE NOT EXISTS (SELECT 1 FROM facilities WHERE facility_code = 'HUB-KUR-01');
  INSERT INTO facilities (public_uuid, facility_type_id, facility_code, name, location_id, owning_agency_id, is_active)
  SELECT 'f9330004-0000-4000-8000-000000000004', v_ft_hospital, 'HOSP-KUR-01', 'Kurigram Sadar Hospital', v_loc_fac_kur_hospital, v_agency_nat_medical, TRUE
  WHERE NOT EXISTS (SELECT 1 FROM facilities WHERE facility_code = 'HOSP-KUR-01');
  INSERT INTO facilities (public_uuid, facility_type_id, facility_code, name, location_id, owning_agency_id, is_active)
  SELECT 'f9330005-0000-4000-8000-000000000005', v_ft_school_shelter, 'SHELTER-GAI-01', 'Gaibandha Govt High School Shelter', v_loc_fac_gai_shelter, v_agency_nat_shelter, TRUE
  WHERE NOT EXISTS (SELECT 1 FROM facilities WHERE facility_code = 'SHELTER-GAI-01');
  INSERT INTO facilities (public_uuid, facility_type_id, facility_code, name, location_id, owning_agency_id, is_active)
  SELECT 'f9330006-0000-4000-8000-000000000006', v_ft_community_center, 'SHELTER-GAI-02', 'Fulchhari Union Parishad Shelter', v_loc_fac_fulchhari_shelter, v_agency_nat_shelter, TRUE
  WHERE NOT EXISTS (SELECT 1 FROM facilities WHERE facility_code = 'SHELTER-GAI-02');
  INSERT INTO facilities (public_uuid, facility_type_id, facility_code, name, location_id, owning_agency_id, is_active)
  SELECT 'f9330007-0000-4000-8000-000000000007', v_ft_warehouse, 'HUB-GAI-01', 'Gaibandha Relief Warehouse', v_loc_fac_gai_hub, v_agency_nat_dmr, TRUE
  WHERE NOT EXISTS (SELECT 1 FROM facilities WHERE facility_code = 'HUB-GAI-01');
  INSERT INTO facilities (public_uuid, facility_type_id, facility_code, name, location_id, owning_agency_id, is_active)
  SELECT 'f9330008-0000-4000-8000-000000000008', v_ft_hospital, 'HOSP-GAI-01', 'Gaibandha District Hospital', v_loc_fac_gai_hospital, v_agency_nat_medical, TRUE
  WHERE NOT EXISTS (SELECT 1 FROM facilities WHERE facility_code = 'HOSP-GAI-01');

-- Facility capacities used by shelter/facility screens
  SELECT id FROM facilities WHERE facility_code = 'SHELTER-KUR-01' LIMIT 1 INTO v_fac_shelter_kur_01;
  SELECT id FROM facilities WHERE facility_code = 'SHELTER-KUR-02' LIMIT 1 INTO v_fac_shelter_kur_02;
  SELECT id FROM facilities WHERE facility_code = 'HUB-KUR-01' LIMIT 1 INTO v_fac_hub_kur_01;
  SELECT id FROM facilities WHERE facility_code = 'HOSP-KUR-01' LIMIT 1 INTO v_fac_hosp_kur_01;
  SELECT id FROM facilities WHERE facility_code = 'SHELTER-GAI-01' LIMIT 1 INTO v_fac_shelter_gai_01;
  SELECT id FROM facilities WHERE facility_code = 'SHELTER-GAI-02' LIMIT 1 INTO v_fac_shelter_gai_02;
  SELECT id FROM facilities WHERE facility_code = 'HUB-GAI-01' LIMIT 1 INTO v_fac_hub_gai_01;
  SELECT id FROM facilities WHERE facility_code = 'HOSP-GAI-01' LIMIT 1 INTO v_fac_hosp_gai_01;

  INSERT INTO facility_default_capacities (facility_id, capacity_type, total_capacity, note)
  SELECT v_fac_shelter_kur_01, 'shelter_people', 500, 'Demo shelter capacity for Kurigram College Shelter'
  WHERE v_fac_shelter_kur_01 IS NOT NULL AND NOT EXISTS (SELECT 1 FROM facility_default_capacities WHERE facility_id = v_fac_shelter_kur_01 AND capacity_type = 'shelter_people');
  INSERT INTO facility_default_capacities (facility_id, capacity_type, total_capacity, note)
  SELECT v_fac_shelter_kur_02, 'shelter_people', 350, 'Demo shelter capacity for Chilmari High School Shelter'
  WHERE v_fac_shelter_kur_02 IS NOT NULL AND NOT EXISTS (SELECT 1 FROM facility_default_capacities WHERE facility_id = v_fac_shelter_kur_02 AND capacity_type = 'shelter_people');
  INSERT INTO facility_default_capacities (facility_id, capacity_type, total_capacity, note)
  SELECT v_fac_shelter_gai_01, 'shelter_people', 450, 'Demo shelter capacity for Gaibandha Govt High School Shelter'
  WHERE v_fac_shelter_gai_01 IS NOT NULL AND NOT EXISTS (SELECT 1 FROM facility_default_capacities WHERE facility_id = v_fac_shelter_gai_01 AND capacity_type = 'shelter_people');
  INSERT INTO facility_default_capacities (facility_id, capacity_type, total_capacity, note)
  SELECT v_fac_shelter_gai_02, 'shelter_people', 300, 'Demo shelter capacity for Fulchhari Union Parishad Shelter'
  WHERE v_fac_shelter_gai_02 IS NOT NULL AND NOT EXISTS (SELECT 1 FROM facility_default_capacities WHERE facility_id = v_fac_shelter_gai_02 AND capacity_type = 'shelter_people');
  INSERT INTO facility_default_capacities (facility_id, capacity_type, total_capacity, note)
  SELECT v_fac_hosp_kur_01, 'hospital_beds', 120, 'Demo hospital capacity for Kurigram Sadar Hospital'
  WHERE v_fac_hosp_kur_01 IS NOT NULL AND NOT EXISTS (SELECT 1 FROM facility_default_capacities WHERE facility_id = v_fac_hosp_kur_01 AND capacity_type = 'hospital_beds');
  INSERT INTO facility_default_capacities (facility_id, capacity_type, total_capacity, note)
  SELECT v_fac_hosp_gai_01, 'hospital_beds', 100, 'Demo hospital capacity for Gaibandha District Hospital'
  WHERE v_fac_hosp_gai_01 IS NOT NULL AND NOT EXISTS (SELECT 1 FROM facility_default_capacities WHERE facility_id = v_fac_hosp_gai_01 AND capacity_type = 'hospital_beds');

-- Live demo note:
-- The actual disaster event, disaster declaration, affected-area assessments, shelter activations,
-- shelter occupancy snapshots, relief request, relief approval, disaster-linked incidents,
-- and final disaster resolution should be created from the UI during recording.



-- ============================================================
-- Suggested live values for the presenter/backend engineer
-- ============================================================
-- Storyline 1 live 999 intake:
-- Caller: Md. Selim, phone 01710000999
-- Category: fire
-- Summary: Active fire near old warehouse in Puran Dhaka
-- Note: Smoke is spreading fast; people may be trapped inside.
-- Location: Old Warehouse Lane, Puran Dhaka
-- Incident title: Warehouse fire near old market lane, Puran Dhaka
-- Severity: critical
-- Agencies to assign: DHK-FIRE-01, DHK-POL-01, DHK-MED-01
-- Units to dispatch: FIRE-01, FIRE-RES-01, FIRE-CMD, MED-01, POL-01
-- Fire response log: Fire contained. Search completed. No further spread detected.

-- Storyline 2 live disaster declaration:
-- Event title: Northern Flood Emergency — Kurigram and Gaibandha
-- Event type: flood
-- Severity: critical or national, depending on current enum/UI options
-- Affected areas: Kurigram Sadar, Chilmari, Ulipur, Gaibandha Sadar, Fulchhari, Sundarganj
-- Public guidance: Evacuate low-lying areas, move to designated shelters, avoid flooded roads, and follow official NIERS updates.
-- Agencies to assign: NAT-DMR-01, NAT-SHELTER-01, NAT-MED-01, NAT-POL-01, NAT-RESCUE-01
-- Shelters to activate: SHELTER-KUR-01, SHELTER-KUR-02, SHELTER-GAI-01, SHELTER-GAI-02
-- Relief hubs: HUB-KUR-01, HUB-GAI-01
-- Agency relief request: food, drinking water, medicine, blankets, hygiene kits for Kurigram College Shelter

END $$;
