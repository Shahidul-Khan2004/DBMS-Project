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
-- Re-resolve lookups (this part runs as a separate migration after part_a)
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