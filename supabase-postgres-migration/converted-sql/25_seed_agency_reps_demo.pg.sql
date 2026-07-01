DO $$
DECLARE

BEGIN
  -- ============================================================
  -- Demo agency representative memberships (users from bootstrap)
  -- Stable membership public_uuid values documented in docs/backend-api.md
  -- ============================================================
  INSERT INTO agency_memberships (
    public_uuid,
    user_id,
    agency_id,
    membership_role,
    membership_status
  )
  SELECT
    v.membership_uuid,
    u.id,
    a.id,
    'representative',
    'active'
  FROM (
    SELECT 'd4000001-0000-4000-8000-000000000001' AS membership_uuid, 'fire.rep@niers.test' AS email, 'b2000001-0000-4000-8000-000000000001' AS agency_uuid UNION ALL
    SELECT 'd4000001-0000-4000-8000-000000000002', 'police.rep@niers.test', 'b2000001-0000-4000-8000-000000000002' UNION ALL
    SELECT 'd4000001-0000-4000-8000-000000000003', 'medical.rep@niers.test', 'b2000001-0000-4000-8000-000000000003'
  ) AS v
  INNER JOIN users u ON u.email = v.email
  INNER JOIN agencies a ON a.public_uuid = v.agency_uuid
  ON CONFLICT DO UPDATE SET membership_status = 'active',
    left_at = NULL;
END $$;