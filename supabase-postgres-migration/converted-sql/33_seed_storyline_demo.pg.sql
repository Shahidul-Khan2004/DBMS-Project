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
-- 3. Locations
-- ============================================================

-- Storyline 1: Puran Dhaka fire locations
  INSERT INTO locations (public_uuid, admin_area_id, latitude, longitude, geo_point, address_text, place_name, source, created_by_user_id)
  SELECT 'a9110001-0000-4000-8000-000000000001', v_area_puran_dhaka, 23.715600, 90.396800, ST_SetSRID(ST_MakePoint(90.396800, 23.715600), 4326)::geography, 'Old Warehouse Lane, Puran Dhaka', 'Old Warehouse Lane', 'manual_entry', v_dispatcher_id
  WHERE NOT EXISTS (SELECT 1 FROM locations WHERE public_uuid = 'a9110001-0000-4000-8000-000000000001');
  INSERT INTO locations (public_uuid, admin_area_id, latitude, longitude, geo_point, address_text, place_name, source, created_by_user_id)
  SELECT 'a9110002-0000-4000-8000-000000000002', v_area_puran_dhaka, 23.716200, 90.397400, ST_SetSRID(ST_MakePoint(90.397400, 23.716200), 4326)::geography, 'Rooftop near old warehouse, Puran Dhaka', 'Rooftop near old warehouse', 'manual_entry', v_rahima_id
  WHERE NOT EXISTS (SELECT 1 FROM locations WHERE public_uuid = 'a9110002-0000-4000-8000-000000000002');
  INSERT INTO locations (public_uuid, admin_area_id, latitude, longitude, geo_point, address_text, place_name, source, created_by_user_id)
  SELECT 'a9110003-0000-4000-8000-000000000003', v_area_puran_dhaka, 23.715100, 90.397900, ST_SetSRID(ST_MakePoint(90.397900, 23.715100), 4326)::geography, 'Market entrance, Puran Dhaka', 'Old Market Entrance', 'manual_entry', v_dispatcher_id
  WHERE NOT EXISTS (SELECT 1 FROM locations WHERE public_uuid = 'a9110003-0000-4000-8000-000000000003');
  INSERT INTO locations (public_uuid, admin_area_id, latitude, longitude, geo_point, address_text, place_name, source, created_by_user_id)
  SELECT 'a9110004-0000-4000-8000-000000000004', v_area_puran_dhaka, 23.714800, 90.396000, ST_SetSRID(ST_MakePoint(90.396000, 23.714800), 4326)::geography, 'Nearby shop lane, Puran Dhaka', 'Nearby Shop Lane', 'manual_entry', v_dispatcher_id
  WHERE NOT EXISTS (SELECT 1 FROM locations WHERE public_uuid = 'a9110004-0000-4000-8000-000000000004');
  INSERT INTO locations (public_uuid, admin_area_id, latitude, longitude, geo_point, address_text, place_name, source, created_by_user_id)
  SELECT 'a9110005-0000-4000-8000-000000000005', v_area_puran_dhaka, 23.722000, 90.391500, ST_SetSRID(ST_MakePoint(90.391500, 23.722000), 4326)::geography, 'Different lane, Puran Dhaka', 'Different Lane', 'manual_entry', v_farhana_id
  WHERE NOT EXISTS (SELECT 1 FROM locations WHERE public_uuid = 'a9110005-0000-4000-8000-000000000005');
  INSERT INTO locations (public_uuid, admin_area_id, latitude, longitude, geo_point, address_text, place_name, source, created_by_user_id)
  SELECT 'a9110006-0000-4000-8000-000000000006', v_area_puran_dhaka, 23.719000, 90.388000, ST_SetSRID(ST_MakePoint(90.388000, 23.719000), 4326)::geography, 'Lalbagh civic issue location, Dhaka', 'Lalbagh civic issue location', 'manual_entry', v_rahima_id
  WHERE NOT EXISTS (SELECT 1 FROM locations WHERE public_uuid = 'a9110006-0000-4000-8000-000000000006');

-- Storyline 2: Flood locations
  INSERT INTO locations (public_uuid, admin_area_id, latitude, longitude, geo_point, address_text, place_name, source, created_by_user_id)
  SELECT 'a9220001-0000-4000-8000-000000000001', v_area_kur_sadar, 25.810300, 89.648700, ST_SetSRID(ST_MakePoint(89.648700, 25.810300), 4326)::geography, 'Kurigram Sadar riverside neighborhood', 'Kurigram Sadar Riverside', 'manual_entry', v_dispatcher_id
  WHERE NOT EXISTS (SELECT 1 FROM locations WHERE public_uuid = 'a9220001-0000-4000-8000-000000000001');
  INSERT INTO locations (public_uuid, admin_area_id, latitude, longitude, geo_point, address_text, place_name, source, created_by_user_id)
  SELECT 'a9220002-0000-4000-8000-000000000002', v_area_chilmari, 25.560200, 89.678400, ST_SetSRID(ST_MakePoint(89.678400, 25.560200), 4326)::geography, 'Chilmari embankment area, Kurigram', 'Chilmari Embankment', 'manual_entry', v_dispatcher_id
  WHERE NOT EXISTS (SELECT 1 FROM locations WHERE public_uuid = 'a9220002-0000-4000-8000-000000000002');
  INSERT INTO locations (public_uuid, admin_area_id, latitude, longitude, geo_point, address_text, place_name, source, created_by_user_id)
  SELECT 'a9220003-0000-4000-8000-000000000003', v_area_ulipur, 25.662200, 89.622700, ST_SetSRID(ST_MakePoint(89.622700, 25.662200), 4326)::geography, 'Ulipur road access point, Kurigram', 'Ulipur Flooded Road', 'manual_entry', v_dispatcher_id
  WHERE NOT EXISTS (SELECT 1 FROM locations WHERE public_uuid = 'a9220003-0000-4000-8000-000000000003');
  INSERT INTO locations (public_uuid, admin_area_id, latitude, longitude, geo_point, address_text, place_name, source, created_by_user_id)
  SELECT 'a9220004-0000-4000-8000-000000000004', v_area_gai_sadar, 25.329700, 89.543000, ST_SetSRID(ST_MakePoint(89.543000, 25.329700), 4326)::geography, 'Gaibandha Sadar low-lying neighborhood', 'Gaibandha Sadar Flood Area', 'manual_entry', v_dispatcher_id
  WHERE NOT EXISTS (SELECT 1 FROM locations WHERE public_uuid = 'a9220004-0000-4000-8000-000000000004');
  INSERT INTO locations (public_uuid, admin_area_id, latitude, longitude, geo_point, address_text, place_name, source, created_by_user_id)
  SELECT 'a9220005-0000-4000-8000-000000000005', v_area_fulchhari, 25.175600, 89.684800, ST_SetSRID(ST_MakePoint(89.684800, 25.175600), 4326)::geography, 'Fulchhari displaced family cluster, Gaibandha', 'Fulchhari Shelter Need Area', 'manual_entry', v_dispatcher_id
  WHERE NOT EXISTS (SELECT 1 FROM locations WHERE public_uuid = 'a9220005-0000-4000-8000-000000000005');
  INSERT INTO locations (public_uuid, admin_area_id, latitude, longitude, geo_point, address_text, place_name, source, created_by_user_id)
  SELECT 'a9220006-0000-4000-8000-000000000006', v_area_sundarganj, 25.565000, 89.512500, ST_SetSRID(ST_MakePoint(89.512500, 25.565000), 4326)::geography, 'Sundarganj embankment road, Gaibandha', 'Sundarganj Embankment Road', 'manual_entry', v_dispatcher_id
  WHERE NOT EXISTS (SELECT 1 FROM locations WHERE public_uuid = 'a9220006-0000-4000-8000-000000000006');

-- Facility locations
  INSERT INTO locations (public_uuid, admin_area_id, latitude, longitude, geo_point, address_text, place_name, source, created_by_user_id)
  SELECT 'a9330001-0000-4000-8000-000000000001', v_area_kur_sadar, 25.807500, 89.646200, ST_SetSRID(ST_MakePoint(89.646200, 25.807500), 4326)::geography, 'Kurigram College Shelter, Kurigram Sadar', 'Kurigram College Shelter', 'manual_entry', v_system_admin_id
  WHERE NOT EXISTS (SELECT 1 FROM locations WHERE public_uuid = 'a9330001-0000-4000-8000-000000000001');
  INSERT INTO locations (public_uuid, admin_area_id, latitude, longitude, geo_point, address_text, place_name, source, created_by_user_id)
  SELECT 'a9330002-0000-4000-8000-000000000002', v_area_chilmari, 25.557500, 89.680000, ST_SetSRID(ST_MakePoint(89.680000, 25.557500), 4326)::geography, 'Chilmari High School Shelter, Kurigram', 'Chilmari High School Shelter', 'manual_entry', v_system_admin_id
  WHERE NOT EXISTS (SELECT 1 FROM locations WHERE public_uuid = 'a9330002-0000-4000-8000-000000000002');
  INSERT INTO locations (public_uuid, admin_area_id, latitude, longitude, geo_point, address_text, place_name, source, created_by_user_id)
  SELECT 'a9330003-0000-4000-8000-000000000003', v_area_kur_sadar, 25.812000, 89.650500, ST_SetSRID(ST_MakePoint(89.650500, 25.812000), 4326)::geography, 'Kurigram Relief Warehouse, Kurigram Sadar', 'Kurigram Relief Warehouse', 'manual_entry', v_system_admin_id
  WHERE NOT EXISTS (SELECT 1 FROM locations WHERE public_uuid = 'a9330003-0000-4000-8000-000000000003');
  INSERT INTO locations (public_uuid, admin_area_id, latitude, longitude, geo_point, address_text, place_name, source, created_by_user_id)
  SELECT 'a9330004-0000-4000-8000-000000000004', v_area_kur_sadar, 25.804300, 89.641600, ST_SetSRID(ST_MakePoint(89.641600, 25.804300), 4326)::geography, 'Kurigram Sadar Hospital', 'Kurigram Sadar Hospital', 'manual_entry', v_system_admin_id
  WHERE NOT EXISTS (SELECT 1 FROM locations WHERE public_uuid = 'a9330004-0000-4000-8000-000000000004');
  INSERT INTO locations (public_uuid, admin_area_id, latitude, longitude, geo_point, address_text, place_name, source, created_by_user_id)
  SELECT 'a9330005-0000-4000-8000-000000000005', v_area_gai_sadar, 25.331000, 89.543900, ST_SetSRID(ST_MakePoint(89.543900, 25.331000), 4326)::geography, 'Gaibandha Govt High School Shelter', 'Gaibandha Govt High School Shelter', 'manual_entry', v_system_admin_id
  WHERE NOT EXISTS (SELECT 1 FROM locations WHERE public_uuid = 'a9330005-0000-4000-8000-000000000005');
  INSERT INTO locations (public_uuid, admin_area_id, latitude, longitude, geo_point, address_text, place_name, source, created_by_user_id)
  SELECT 'a9330006-0000-4000-8000-000000000006', v_area_fulchhari, 25.177000, 89.686200, ST_SetSRID(ST_MakePoint(89.686200, 25.177000), 4326)::geography, 'Fulchhari Union Parishad Shelter', 'Fulchhari Union Parishad Shelter', 'manual_entry', v_system_admin_id
  WHERE NOT EXISTS (SELECT 1 FROM locations WHERE public_uuid = 'a9330006-0000-4000-8000-000000000006');
  INSERT INTO locations (public_uuid, admin_area_id, latitude, longitude, geo_point, address_text, place_name, source, created_by_user_id)
  SELECT 'a9330007-0000-4000-8000-000000000007', v_area_gai_sadar, 25.328900, 89.546700, ST_SetSRID(ST_MakePoint(89.546700, 25.328900), 4326)::geography, 'Gaibandha Relief Warehouse', 'Gaibandha Relief Warehouse', 'manual_entry', v_system_admin_id
  WHERE NOT EXISTS (SELECT 1 FROM locations WHERE public_uuid = 'a9330007-0000-4000-8000-000000000007');
  INSERT INTO locations (public_uuid, admin_area_id, latitude, longitude, geo_point, address_text, place_name, source, created_by_user_id)
  SELECT 'a9330008-0000-4000-8000-000000000008', v_area_gai_sadar, 25.326500, 89.542100, ST_SetSRID(ST_MakePoint(89.542100, 25.326500), 4326)::geography, 'Gaibandha District Hospital', 'Gaibandha District Hospital', 'manual_entry', v_system_admin_id
  WHERE NOT EXISTS (SELECT 1 FROM locations WHERE public_uuid = 'a9330008-0000-4000-8000-000000000008');

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

-- Rahima saved location for citizen report flow
  INSERT INTO saved_locations (public_uuid, user_id, location_id, label, is_deleted)
  SELECT '59110001-0000-4000-8000-000000000001', v_rahima_id, v_loc_fire_smoke, 'Old Dhaka visit area', FALSE
  WHERE v_rahima_id IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM saved_locations WHERE public_uuid = '59110001-0000-4000-8000-000000000001');

-- ============================================================
-- 4. Reporter contacts
-- ============================================================

  INSERT INTO reporter_contacts (linked_user_id, full_name, phone_number, email, is_anonymous)
  SELECT NULL, 'Puran Dhaka Shop Owner', '01710001001', NULL, FALSE
  WHERE NOT EXISTS (SELECT 1 FROM reporter_contacts WHERE phone_number = '01710001001');
  INSERT INTO reporter_contacts (linked_user_id, full_name, phone_number, email, is_anonymous)
  SELECT NULL, 'Anonymous Puran Dhaka Passerby', '01710001002', NULL, TRUE
  WHERE NOT EXISTS (SELECT 1 FROM reporter_contacts WHERE phone_number = '01710001002');
  INSERT INTO reporter_contacts (linked_user_id, full_name, phone_number, email, is_anonymous)
  SELECT NULL, 'Kurigram Field Volunteer', '01710002001', NULL, FALSE
  WHERE NOT EXISTS (SELECT 1 FROM reporter_contacts WHERE phone_number = '01710002001');
  INSERT INTO reporter_contacts (linked_user_id, full_name, phone_number, email, is_anonymous)
  SELECT NULL, 'Gaibandha Shelter Volunteer', '01710002002', NULL, FALSE
  WHERE NOT EXISTS (SELECT 1 FROM reporter_contacts WHERE phone_number = '01710002002');
  INSERT INTO reporter_contacts (linked_user_id, full_name, phone_number, email, is_anonymous)
  SELECT NULL, 'Ulipur Road Watch Volunteer', '01710002003', NULL, FALSE
  WHERE NOT EXISTS (SELECT 1 FROM reporter_contacts WHERE phone_number = '01710002003');
  INSERT INTO reporter_contacts (linked_user_id, full_name, phone_number, email, is_anonymous)
  SELECT NULL, 'Sundarganj Union Volunteer', '01710002004', NULL, FALSE
  WHERE NOT EXISTS (SELECT 1 FROM reporter_contacts WHERE phone_number = '01710002004');

  SELECT id FROM reporter_contacts WHERE phone_number = '01710001001' LIMIT 1 INTO v_contact_shop_owner;
  SELECT id FROM reporter_contacts WHERE phone_number = '01710001002' LIMIT 1 INTO v_contact_passerby;
  SELECT id FROM reporter_contacts WHERE phone_number = '01710002001' LIMIT 1 INTO v_contact_kur_volunteer;
  SELECT id FROM reporter_contacts WHERE phone_number = '01710002002' LIMIT 1 INTO v_contact_gai_volunteer;
  SELECT id FROM reporter_contacts WHERE phone_number = '01710002003' LIMIT 1 INTO v_contact_ulipur_volunteer;
  SELECT id FROM reporter_contacts WHERE phone_number = '01710002004' LIMIT 1 INTO v_contact_sundarganj_volunteer;

-- ============================================================
-- 5. Storyline 1: Citizen service case setup
-- ============================================================

  INSERT INTO intake_reports (public_uuid, report_code, reporter_user_id, reporter_contact_id, channel_id, category_id, reported_location_id, summary, description, current_status_id, final_disposition, received_by_user_id, reported_at)
  SELECT 'b9110000-0000-4000-8000-000000000000', 'IR-DHK-SERVICE-001', v_rahima_id, NULL, v_ch_web, v_cat_infra, v_loc_service,
         'Broken drain cover near Lalbagh Road',
         'A drain cover near Lalbagh Road has been broken for two days and pedestrians are at risk.',
         v_intake_linked_case, NULL, v_dispatcher_id, NOW() - INTERVAL '2 day'
  WHERE v_rahima_id IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM intake_reports WHERE report_code = 'IR-DHK-SERVICE-001');
  SELECT id FROM intake_reports WHERE report_code = 'IR-DHK-SERVICE-001' LIMIT 1 INTO v_ir_service;

  INSERT INTO service_cases (public_uuid, case_code, intake_report_id, reporter_user_id, parent_case_id, category_id, current_status_id, current_location_id, title, description, priority_level, source_channel_id)
  SELECT 'c9110000-0000-4000-8000-000000000000', 'SC-DHK-CIVIC-001', v_ir_service, v_rahima_id, NULL, v_cat_infra, v_case_under_review, v_loc_service,
         'Broken drain cover near Lalbagh Road',
         'Citizen requested action on a broken drain cover that may create pedestrian injury risk.',
         'medium', v_ch_web
  WHERE v_ir_service IS NOT NULL
    AND v_rahima_id IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM service_cases WHERE case_code = 'SC-DHK-CIVIC-001');
  SELECT id FROM service_cases WHERE case_code = 'SC-DHK-CIVIC-001' LIMIT 1 INTO v_case_civic;

  INSERT INTO case_messages (case_id, sender_user_id, message_type, subject, body, is_internal)
  SELECT v_case_civic, v_rahima_id, 'user_message', 'Drain cover is broken',
         'A drain cover near Lalbagh Road has been broken for two days and pedestrians are at risk.', FALSE
  WHERE v_case_civic IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM case_messages WHERE case_id = v_case_civic AND subject = 'Drain cover is broken');

  INSERT INTO case_messages (case_id, sender_user_id, message_type, subject, body, is_internal)
  SELECT v_case_civic, v_dispatcher_id, 'admin_reply', 'Inspection completed',
         'The issue has been forwarded to the local maintenance team. Temporary warning markers have been placed.', FALSE
  WHERE v_case_civic IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM case_messages WHERE case_id = v_case_civic AND subject = 'Inspection completed');

-- Final reply should be added live in the video before resolving the case.

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
-- 7. Agencies, memberships, and emergency units
-- ============================================================

  SELECT id FROM agency_types WHERE type_code = 'fire_service' LIMIT 1 INTO v_atype_fire;
  SELECT id FROM agency_types WHERE type_code = 'police' LIMIT 1 INTO v_atype_police;
  SELECT id FROM agency_types WHERE type_code = 'medical_service' LIMIT 1 INTO v_atype_medical;
  SELECT id FROM agency_types WHERE type_code = 'disaster_management' LIMIT 1 INTO v_atype_disaster;
  SELECT id FROM agency_types WHERE type_code = 'ngo' LIMIT 1 INTO v_atype_ngo;
  SELECT id FROM agency_types WHERE type_code = 'local_government' LIMIT 1 INTO v_atype_local;

  INSERT INTO agencies (public_uuid, agency_type_id, agency_code, name, description, head_office_location_id, is_active)
  SELECT 'd9110001-0000-4000-8000-000000000001', v_atype_fire, 'DHK-FIRE-01', 'Dhaka Fire Service', 'Fire suppression and rescue support for Dhaka demo operations.', v_loc_fire_main, TRUE
  WHERE NOT EXISTS (SELECT 1 FROM agencies WHERE agency_code = 'DHK-FIRE-01');
  INSERT INTO agencies (public_uuid, agency_type_id, agency_code, name, description, head_office_location_id, is_active)
  SELECT 'd9110002-0000-4000-8000-000000000002', v_atype_police, 'DHK-POL-01', 'Dhaka Metropolitan Police Demo Unit', 'Crowd control, traffic diversion, and public safety support.', v_loc_fire_market, TRUE
  WHERE NOT EXISTS (SELECT 1 FROM agencies WHERE agency_code = 'DHK-POL-01');
  INSERT INTO agencies (public_uuid, agency_type_id, agency_code, name, description, head_office_location_id, is_active)
  SELECT 'd9110003-0000-4000-8000-000000000003', v_atype_medical, 'DHK-MED-01', 'Dhaka Medical Emergency Unit', 'Ambulance and casualty support for emergency incidents.', v_loc_fire_lane, TRUE
  WHERE NOT EXISTS (SELECT 1 FROM agencies WHERE agency_code = 'DHK-MED-01');

  INSERT INTO agencies (public_uuid, agency_type_id, agency_code, name, description, head_office_location_id, is_active)
  SELECT 'd9220001-0000-4000-8000-000000000001', v_atype_disaster, 'NAT-DMR-01', 'National Disaster Management and Relief Office', 'Lead coordination agency for disaster demo operations.', v_loc_kur_sadar, TRUE
  WHERE NOT EXISTS (SELECT 1 FROM agencies WHERE agency_code = 'NAT-DMR-01');
  INSERT INTO agencies (public_uuid, agency_type_id, agency_code, name, description, head_office_location_id, is_active)
  SELECT 'd9220002-0000-4000-8000-000000000002', v_atype_ngo, 'NAT-SHELTER-01', 'Red Crescent Shelter Response Unit', 'Shelter management and occupancy reporting for flood response.', v_loc_kur_sadar, TRUE
  WHERE NOT EXISTS (SELECT 1 FROM agencies WHERE agency_code = 'NAT-SHELTER-01');
  INSERT INTO agencies (public_uuid, agency_type_id, agency_code, name, description, head_office_location_id, is_active)
  SELECT 'd9220003-0000-4000-8000-000000000003', v_atype_medical, 'NAT-MED-01', 'Northern Medical Response Unit', 'Medical support and emergency care for flood-affected people.', v_loc_gai_sadar, TRUE
  WHERE NOT EXISTS (SELECT 1 FROM agencies WHERE agency_code = 'NAT-MED-01');
  INSERT INTO agencies (public_uuid, agency_type_id, agency_code, name, description, head_office_location_id, is_active)
  SELECT 'd9220004-0000-4000-8000-000000000004', v_atype_police, 'NAT-POL-01', 'Northern Police Safety Unit', 'Security, road safety, and evacuation support for flood response.', v_loc_gai_sadar, TRUE
  WHERE NOT EXISTS (SELECT 1 FROM agencies WHERE agency_code = 'NAT-POL-01');
  INSERT INTO agencies (public_uuid, agency_type_id, agency_code, name, description, head_office_location_id, is_active)
  SELECT 'd9220005-0000-4000-8000-000000000005', v_atype_fire, 'NAT-RESCUE-01', 'Northern Fire and Rescue Unit', 'Water rescue and emergency evacuation support for flood response.', v_loc_chilmari, TRUE
  WHERE NOT EXISTS (SELECT 1 FROM agencies WHERE agency_code = 'NAT-RESCUE-01');

  SELECT id FROM agencies WHERE agency_code = 'DHK-FIRE-01' LIMIT 1 INTO v_agency_dhk_fire;
  SELECT id FROM agencies WHERE agency_code = 'DHK-POL-01' LIMIT 1 INTO v_agency_dhk_police;
  SELECT id FROM agencies WHERE agency_code = 'DHK-MED-01' LIMIT 1 INTO v_agency_dhk_medical;
  SELECT id FROM agencies WHERE agency_code = 'NAT-DMR-01' LIMIT 1 INTO v_agency_nat_dmr;
  SELECT id FROM agencies WHERE agency_code = 'NAT-SHELTER-01' LIMIT 1 INTO v_agency_nat_shelter;
  SELECT id FROM agencies WHERE agency_code = 'NAT-MED-01' LIMIT 1 INTO v_agency_nat_medical;
  SELECT id FROM agencies WHERE agency_code = 'NAT-POL-01' LIMIT 1 INTO v_agency_nat_police;
  SELECT id FROM agencies WHERE agency_code = 'NAT-RESCUE-01' LIMIT 1 INTO v_agency_nat_rescue;

-- Agency memberships for demo representative dashboards
  INSERT INTO agency_memberships (public_uuid, user_id, agency_id, membership_role, membership_status)
  SELECT 'e9110001-0000-4000-8000-000000000001', v_fire_rep_id, v_agency_dhk_fire, 'representative', 'active'
  WHERE v_fire_rep_id IS NOT NULL AND v_agency_dhk_fire IS NOT NULL
  ON CONFLICT (user_id, agency_id) DO UPDATE SET membership_status = 'active', membership_role = EXCLUDED.membership_role, left_at = NULL;
  INSERT INTO agency_memberships (public_uuid, user_id, agency_id, membership_role, membership_status)
  SELECT 'e9110002-0000-4000-8000-000000000002', v_police_rep_id, v_agency_dhk_police, 'representative', 'active'
  WHERE v_police_rep_id IS NOT NULL AND v_agency_dhk_police IS NOT NULL
  ON CONFLICT (user_id, agency_id) DO UPDATE SET membership_status = 'active', membership_role = EXCLUDED.membership_role, left_at = NULL;
  INSERT INTO agency_memberships (public_uuid, user_id, agency_id, membership_role, membership_status)
  SELECT 'e9110003-0000-4000-8000-000000000003', v_medical_rep_id, v_agency_dhk_medical, 'representative', 'active'
  WHERE v_medical_rep_id IS NOT NULL AND v_agency_dhk_medical IS NOT NULL
  ON CONFLICT (user_id, agency_id) DO UPDATE SET membership_status = 'active', membership_role = EXCLUDED.membership_role, left_at = NULL;
  INSERT INTO agency_memberships (public_uuid, user_id, agency_id, membership_role, membership_status)
  SELECT 'e9220001-0000-4000-8000-000000000001', v_relief_rep_id, v_agency_nat_dmr, 'coordinator', 'active'
  WHERE v_relief_rep_id IS NOT NULL AND v_agency_nat_dmr IS NOT NULL
  ON CONFLICT (user_id, agency_id) DO UPDATE SET membership_status = 'active', membership_role = EXCLUDED.membership_role, left_at = NULL;
  INSERT INTO agency_memberships (public_uuid, user_id, agency_id, membership_role, membership_status)
  SELECT 'e9220002-0000-4000-8000-000000000002', v_shelter_rep_id, v_agency_nat_shelter, 'coordinator', 'active'
  WHERE v_shelter_rep_id IS NOT NULL AND v_agency_nat_shelter IS NOT NULL
  ON CONFLICT (user_id, agency_id) DO UPDATE SET membership_status = 'active', membership_role = EXCLUDED.membership_role, left_at = NULL;

-- Emergency units for fire storyline
  SELECT id FROM emergency_unit_types WHERE type_code = 'fire_truck' LIMIT 1 INTO v_ut_fire_truck;
  SELECT id FROM emergency_unit_types WHERE type_code = 'command_vehicle' LIMIT 1 INTO v_ut_command;
  SELECT id FROM emergency_unit_types WHERE type_code = 'ambulance' LIMIT 1 INTO v_ut_ambulance;
  SELECT id FROM emergency_unit_types WHERE type_code = 'police_vehicle' LIMIT 1 INTO v_ut_police;
  SELECT id FROM emergency_unit_types WHERE type_code = 'rescue_boat' LIMIT 1 INTO v_ut_rescue_boat;
  SELECT id FROM emergency_unit_types WHERE type_code = 'relief_truck' LIMIT 1 INTO v_ut_relief_truck;

  INSERT INTO emergency_units (public_uuid, agency_id, unit_type_id, unit_code, unit_name, base_location_id, current_status_id, is_active)
  SELECT 'e9310001-0000-4000-8000-000000000001', v_agency_dhk_fire, v_ut_fire_truck, 'FIRE-01', 'Fire Engine Alpha', v_loc_fire_main, v_unit_available, TRUE
  WHERE NOT EXISTS (SELECT 1 FROM emergency_units WHERE unit_code = 'FIRE-01' AND agency_id = v_agency_dhk_fire);
  INSERT INTO emergency_units (public_uuid, agency_id, unit_type_id, unit_code, unit_name, base_location_id, current_status_id, is_active)
  SELECT 'e9310002-0000-4000-8000-000000000002', v_agency_dhk_fire, v_ut_fire_truck, 'FIRE-02', 'Fire Engine Bravo', v_loc_fire_main, v_unit_available, TRUE
  WHERE NOT EXISTS (SELECT 1 FROM emergency_units WHERE unit_code = 'FIRE-02' AND agency_id = v_agency_dhk_fire);
  INSERT INTO emergency_units (public_uuid, agency_id, unit_type_id, unit_code, unit_name, base_location_id, current_status_id, is_active)
  SELECT 'e9310003-0000-4000-8000-000000000003', v_agency_dhk_fire, v_ut_fire_truck, 'FIRE-RES-01', 'Rescue Unit One', v_loc_fire_main, v_unit_available, TRUE
  WHERE NOT EXISTS (SELECT 1 FROM emergency_units WHERE unit_code = 'FIRE-RES-01' AND agency_id = v_agency_dhk_fire);
  INSERT INTO emergency_units (public_uuid, agency_id, unit_type_id, unit_code, unit_name, base_location_id, current_status_id, is_active)
  SELECT 'e9310004-0000-4000-8000-000000000004', v_agency_dhk_fire, v_ut_command, 'FIRE-CMD', 'Fire Command Vehicle', v_loc_fire_main, v_unit_available, TRUE
  WHERE NOT EXISTS (SELECT 1 FROM emergency_units WHERE unit_code = 'FIRE-CMD' AND agency_id = v_agency_dhk_fire);
  INSERT INTO emergency_units (public_uuid, agency_id, unit_type_id, unit_code, unit_name, base_location_id, current_status_id, is_active)
  SELECT 'e9310005-0000-4000-8000-000000000005', v_agency_dhk_medical, v_ut_ambulance, 'MED-01', 'Ambulance One', v_loc_fire_lane, v_unit_available, TRUE
  WHERE NOT EXISTS (SELECT 1 FROM emergency_units WHERE unit_code = 'MED-01' AND agency_id = v_agency_dhk_medical);
  INSERT INTO emergency_units (public_uuid, agency_id, unit_type_id, unit_code, unit_name, base_location_id, current_status_id, is_active)
  SELECT 'e9310006-0000-4000-8000-000000000006', v_agency_dhk_medical, v_ut_ambulance, 'MED-02', 'Ambulance Two', v_loc_fire_lane, v_unit_available, TRUE
  WHERE NOT EXISTS (SELECT 1 FROM emergency_units WHERE unit_code = 'MED-02' AND agency_id = v_agency_dhk_medical);
  INSERT INTO emergency_units (public_uuid, agency_id, unit_type_id, unit_code, unit_name, base_location_id, current_status_id, is_active)
  SELECT 'e9310007-0000-4000-8000-000000000007', v_agency_dhk_police, v_ut_police, 'POL-01', 'Patrol Unit One', v_loc_fire_market, v_unit_available, TRUE
  WHERE NOT EXISTS (SELECT 1 FROM emergency_units WHERE unit_code = 'POL-01' AND agency_id = v_agency_dhk_police);
  INSERT INTO emergency_units (public_uuid, agency_id, unit_type_id, unit_code, unit_name, base_location_id, current_status_id, is_active)
  SELECT 'e9310008-0000-4000-8000-000000000008', v_agency_dhk_police, v_ut_police, 'POL-02', 'Patrol Unit Two', v_loc_fire_market, v_unit_available, TRUE
  WHERE NOT EXISTS (SELECT 1 FROM emergency_units WHERE unit_code = 'POL-02' AND agency_id = v_agency_dhk_police);

-- Units for flood/disaster agencies
  INSERT INTO emergency_units (public_uuid, agency_id, unit_type_id, unit_code, unit_name, base_location_id, current_status_id, is_active)
  SELECT 'e9320001-0000-4000-8000-000000000001', v_agency_nat_rescue, v_ut_rescue_boat, 'RESCUE-BOAT-01', 'Rescue Boat One', v_loc_chilmari, v_unit_available, TRUE
  WHERE NOT EXISTS (SELECT 1 FROM emergency_units WHERE unit_code = 'RESCUE-BOAT-01' AND agency_id = v_agency_nat_rescue);
  INSERT INTO emergency_units (public_uuid, agency_id, unit_type_id, unit_code, unit_name, base_location_id, current_status_id, is_active)
  SELECT 'e9320002-0000-4000-8000-000000000002', v_agency_nat_dmr, v_ut_relief_truck, 'RELIEF-TRUCK-01', 'Relief Truck One', v_loc_kur_sadar, v_unit_available, TRUE
  WHERE NOT EXISTS (SELECT 1 FROM emergency_units WHERE unit_code = 'RELIEF-TRUCK-01' AND agency_id = v_agency_nat_dmr);
  INSERT INTO emergency_units (public_uuid, agency_id, unit_type_id, unit_code, unit_name, base_location_id, current_status_id, is_active)
  SELECT 'e9320003-0000-4000-8000-000000000003', v_agency_nat_medical, v_ut_ambulance, 'FLOOD-MED-01', 'Flood Medical Ambulance One', v_loc_gai_sadar, v_unit_available, TRUE
  WHERE NOT EXISTS (SELECT 1 FROM emergency_units WHERE unit_code = 'FLOOD-MED-01' AND agency_id = v_agency_nat_medical);
  INSERT INTO emergency_units (public_uuid, agency_id, unit_type_id, unit_code, unit_name, base_location_id, current_status_id, is_active)
  SELECT 'e9320004-0000-4000-8000-000000000004', v_agency_nat_police, v_ut_police, 'FLOOD-POL-01', 'Flood Safety Patrol One', v_loc_gai_sadar, v_unit_available, TRUE
  WHERE NOT EXISTS (SELECT 1 FROM emergency_units WHERE unit_code = 'FLOOD-POL-01' AND agency_id = v_agency_nat_police);

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
