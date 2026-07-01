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
END $$;