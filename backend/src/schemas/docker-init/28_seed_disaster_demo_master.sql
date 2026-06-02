-- ============================================================
-- Kurigram-area demo agencies, units, and facilities (no disaster ops data)
-- ============================================================

SET @kurigram_sadar_upazila = (SELECT id FROM administrative_areas WHERE code = 'BD-UPZ-448' LIMIT 1);
SET @chilmari_upazila = (SELECT id FROM administrative_areas WHERE code = 'BD-UPZ-454' LIMIT 1);
SET @ulipur_upazila = (SELECT id FROM administrative_areas WHERE code = 'BD-UPZ-453' LIMIT 1);
SET @nageshwari_upazila = (SELECT id FROM administrative_areas WHERE code = 'BD-UPZ-449' LIMIT 1);

INSERT INTO locations (
  public_uuid, admin_area_id, latitude, longitude, geo_point, address_text, place_name, source
) VALUES
(
  'a2000001-0000-4000-8000-000000000001',
  @kurigram_sadar_upazila, 25.805000, 89.636400,
  ST_SRID(POINT(89.636400, 25.805000), 4326),
  'Kurigram District Disaster Management Office', 'Kurigram DDMO', 'manual_entry'
),
(
  'a2000001-0000-4000-8000-000000000002',
  @kurigram_sadar_upazila, 25.810000, 89.640000,
  ST_SRID(POINT(89.640000, 25.810000), 4326),
  'Red Crescent Kurigram Unit', 'Red Crescent Kurigram', 'manual_entry'
),
(
  'a2000001-0000-4000-8000-000000000003',
  @chilmari_upazila, 25.580000, 89.670000,
  ST_SRID(POINT(89.670000, 25.580000), 4326),
  'Kurigram Fire Service Station, Chilmari', 'Chilmari Fire', 'manual_entry'
),
(
  'a2000001-0000-4000-8000-000000000004',
  @kurigram_sadar_upazila, 25.800000, 89.630000,
  ST_SRID(POINT(89.630000, 25.800000), 4326),
  'Kurigram EMS Depot', 'Kurigram EMS', 'manual_entry'
),
(
  'a2000001-0000-4000-8000-000000000005',
  @ulipur_upazila, 25.850000, 89.550000,
  ST_SRID(POINT(89.550000, 25.850000), 4326),
  'Ulipur Police Station', 'Ulipur Police', 'manual_entry'
),
(
  'a2000001-0000-4000-8000-000000000010',
  @kurigram_sadar_upazila, 25.812000, 89.638000,
  ST_SRID(POINT(89.638000, 25.812000), 4326),
  'Kurigram Government College', 'Kurigram Govt College', 'manual_entry'
),
(
  'a2000001-0000-4000-8000-000000000011',
  @chilmari_upazila, 25.575000, 89.665000,
  ST_SRID(POINT(89.665000, 25.575000), 4326),
  'Chilmari High School Shelter', 'Chilmari School Shelter', 'manual_entry'
),
(
  'a2000001-0000-4000-8000-000000000012',
  @nageshwari_upazila, 25.900000, 89.700000,
  ST_SRID(POINT(89.700000, 25.900000), 4326),
  'Nageshwari Community Centre', 'Nageshwari Community Centre', 'manual_entry'
),
(
  'a2000001-0000-4000-8000-000000000013',
  @kurigram_sadar_upazila, 25.803000, 89.635000,
  ST_SRID(POINT(89.635000, 25.803000), 4326),
  'Kurigram General Hospital', 'Kurigram Hospital', 'manual_entry'
),
(
  'a2000001-0000-4000-8000-000000000014',
  @ulipur_upazila, 25.848000, 89.552000,
  ST_SRID(POINT(89.552000, 25.848000), 4326),
  'Ulipur Relief Warehouse', 'Ulipur Relief Warehouse', 'manual_entry'
);

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
INNER JOIN locations l ON l.public_uuid = v.loc;

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
INNER JOIN unit_statuses us ON us.status_code = v.status;

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
INNER JOIN locations l ON l.public_uuid = v.loc;

INSERT INTO facility_capabilities (facility_id, capability_id, is_active)
SELECT f.id, c.id, TRUE
FROM facilities f
INNER JOIN capabilities c ON c.capability_code = 'temporary_shelter'
WHERE f.facility_code IN ('KUR-SCH-01', 'KUR-SCH-02', 'KUR-CC-01');

INSERT INTO facility_capabilities (facility_id, capability_id, is_active)
SELECT f.id, c.id, TRUE
FROM facilities f
INNER JOIN capabilities c ON c.capability_code = 'relief_distribution_hub'
WHERE f.facility_code IN ('KUR-WH-01', 'KUR-RC-HUB');

INSERT INTO facility_default_capacities (facility_id, capacity_type, total_capacity)
SELECT f.id, 'shelter_people', v.cap
FROM (
  SELECT 'KUR-SCH-01' AS code, 800 AS cap UNION ALL
  SELECT 'KUR-SCH-02', 500 UNION ALL
  SELECT 'KUR-CC-01', 350
) AS v
INNER JOIN facilities f ON f.facility_code = v.code;

INSERT INTO facility_default_capacities (facility_id, capacity_type, total_capacity)
SELECT f.id, 'hospital_beds', 120
FROM facilities f WHERE f.facility_code = 'KUR-HOS-01';

INSERT INTO facility_default_capacities (facility_id, capacity_type, total_capacity)
SELECT f.id, 'emergency_beds', 24
FROM facilities f WHERE f.facility_code = 'KUR-HOS-01';
