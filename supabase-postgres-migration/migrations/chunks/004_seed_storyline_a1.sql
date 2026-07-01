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
END $$;