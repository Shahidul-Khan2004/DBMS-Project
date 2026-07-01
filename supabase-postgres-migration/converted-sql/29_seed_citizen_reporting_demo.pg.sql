DO $$
DECLARE
  v_rahima_id BIGINT;
  v_karim_id BIGINT;
  v_farhana_id BIGINT;
  v_kurigram_sadar BIGINT;
  v_chilmari_upazila BIGINT;
  v_ulipur_upazila BIGINT;
  v_nageshwari_upazila BIGINT;
BEGIN
  -- Migrate legacy non-hex showcase saved-location UUID prefixes
  UPDATE saved_locations
  SET public_uuid = REPLACE(public_uuid, 'sl300001-', '5d300001-')
  WHERE public_uuid LIKE 'sl300001-%';
  -- ============================================================
  -- Showcase: citizen saved locations (Kurigram day-to-day demo)
  -- Requires bootstrap users: citizen.rahima/karim/farhana@niers.test
  -- ============================================================
  SELECT id FROM users WHERE email = 'citizen.rahima@niers.test' LIMIT 1 INTO v_rahima_id;
  SELECT id FROM users WHERE email = 'citizen.karim@niers.test' LIMIT 1 INTO v_karim_id;
  SELECT id FROM users WHERE email = 'citizen.farhana@niers.test' LIMIT 1 INTO v_farhana_id;
  SELECT id FROM administrative_areas WHERE code = 'BD-UPZ-448' LIMIT 1 INTO v_kurigram_sadar;
  SELECT id FROM administrative_areas WHERE code = 'BD-UPZ-454' LIMIT 1 INTO v_chilmari_upazila;
  SELECT id FROM administrative_areas WHERE code = 'BD-UPZ-453' LIMIT 1 INTO v_ulipur_upazila;
  SELECT id FROM administrative_areas WHERE code = 'BD-UPZ-449' LIMIT 1 INTO v_nageshwari_upazila;
  INSERT INTO locations (
    public_uuid, admin_area_id, latitude, longitude, geo_point,
    address_text, place_name, source, created_by_user_id
  )
  SELECT v.public_uuid, v.admin_area_id, v.lat, v.lng,
    ST_SetSRID(ST_MakePoint(v.lng, v.lat), 4326)::geography,
    v.address_text, v.place_name, 'user_shared', v.user_id
  FROM (
    SELECT 'a3000001-0000-4000-8000-000000000001' AS public_uuid, v_kurigram_sadar AS admin_area_id,
      25.805200 AS lat, 89.636800 AS lng,
      'House 12, Residential Block, Kurigram Sadar' AS address_text,
      'Rahima home near hospital' AS place_name, v_rahima_id AS user_id
    UNION ALL
    SELECT 'a3000001-0000-4000-8000-000000000002', v_chilmari_upazila,
      25.581000, 89.668500,
      'Flat 3B, Station Road, Chilmari', 'Karim apartment Station Road', v_karim_id
    UNION ALL
    SELECT 'a3000001-0000-4000-8000-000000000003', v_ulipur_upazila,
      25.848500, 89.551200,
      'Ulipur Bazaar Main Road', 'Ulipur bazaar', v_farhana_id
    UNION ALL
    SELECT 'a3000001-0000-4000-8000-000000000004', v_kurigram_sadar,
      25.803800, 89.634500,
      'Sadar Pharmacy Lane, Kurigram', 'Sadar pharmacy area', v_rahima_id
    UNION ALL
    SELECT 'a3000001-0000-4000-8000-000000000005', v_nageshwari_upazila,
      25.901200, 89.698800,
      'Nageshwari Market Road', 'Nageshwari market', v_farhana_id
  ) AS v
  WHERE v_rahima_id IS NOT NULL AND v_karim_id IS NOT NULL AND v_farhana_id IS NOT NULL
    AND v.admin_area_id IS NOT NULL
    AND NOT EXISTS (SELECT 1 FROM locations l WHERE l.public_uuid = v.public_uuid) ON CONFLICT DO NOTHING;
  INSERT INTO saved_locations (public_uuid, user_id, location_id, label)
  SELECT v.sl_uuid, v.user_id, l.id, v.label
  FROM (
    SELECT '5d300001-0000-4000-8000-000000000001' AS sl_uuid,
      'a3000001-0000-4000-8000-000000000001' AS loc_uuid, v_rahima_id AS user_id, 'Home' AS label
    UNION ALL
    SELECT '5d300001-0000-4000-8000-000000000002',
      'a3000001-0000-4000-8000-000000000002', v_karim_id, 'Home'
    UNION ALL
    SELECT '5d300001-0000-4000-8000-000000000003',
      'a3000001-0000-4000-8000-000000000003', v_farhana_id, 'Work'
    UNION ALL
    SELECT '5d300001-0000-4000-8000-000000000004',
      'a3000001-0000-4000-8000-000000000004', v_rahima_id, 'Mother clinic area'
    UNION ALL
    SELECT '5d300001-0000-4000-8000-000000000005',
      'a3000001-0000-4000-8000-000000000005', v_farhana_id, 'Market'
  ) AS v
  INNER JOIN locations l ON l.public_uuid = v.loc_uuid
  WHERE v.user_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM saved_locations s
      WHERE s.user_id = v.user_id AND s.location_id = l.id AND s.is_deleted = FALSE
    ) ON CONFLICT DO NOTHING;
END $$;