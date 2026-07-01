DO $$
DECLARE
  v_rahima_id BIGINT;
  v_case_001_id BIGINT;
  v_intake_001_id BIGINT;
  v_intake_005_id BIGINT;
  v_inc_101_id BIGINT;
  v_actor_id BIGINT;
BEGIN
  -- ============================================================
  -- Showcase: service case messages + in-app notifications
  -- ============================================================
  SELECT id FROM users WHERE email = 'citizen.rahima@niers.test' LIMIT 1 INTO v_rahima_id;
  v_actor_id := COALESCE(
    (SELECT id FROM users WHERE email = 'dispatcher@niers.test' LIMIT 1),
    (SELECT id FROM users ORDER BY id ASC LIMIT 1)
  );
  SELECT id FROM service_cases WHERE case_code = 'SC-KUR-SHOW-001' LIMIT 1 INTO v_case_001_id;
  SELECT id FROM intake_reports WHERE report_code = 'IR-KUR-SHOW-001' LIMIT 1 INTO v_intake_001_id;
  SELECT id FROM intake_reports WHERE report_code = 'IR-KUR-SHOW-005' LIMIT 1 INTO v_intake_005_id;
  SELECT id FROM emergency_incidents WHERE incident_code = 'EMI-KUR-PRE-001' LIMIT 1 INTO v_inc_101_id;
  INSERT INTO case_messages (case_id, sender_user_id, message_type, subject, body, is_internal)
  SELECT v_case_001_id, v_rahima_id, 'user_message',
    'Documents for medicine support',
    'Which documents do I need to submit for monthly diabetes medicine assistance?',
    FALSE
  WHERE v_case_001_id IS NOT NULL AND v_rahima_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM case_messages m
      WHERE m.case_id = v_case_001_id AND m.subject = 'Documents for medicine support'
    ) ON CONFLICT DO NOTHING;
  INSERT INTO case_messages (case_id, sender_user_id, message_type, subject, body, is_internal)
  SELECT v_case_001_id, v_actor_id, 'admin_reply',
    'Prescription and clinic details needed',
    'Please upload a photo of the prescription and share your mother''s upazila clinic name.',
    FALSE
  WHERE v_case_001_id IS NOT NULL AND v_actor_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM case_messages m
      WHERE m.case_id = v_case_001_id AND m.subject = 'Prescription and clinic details needed'
    ) ON CONFLICT DO NOTHING;
  INSERT INTO case_messages (case_id, sender_user_id, message_type, subject, body, is_internal)
  SELECT v_case_001_id, v_rahima_id, 'user_message',
    'Clinic and delivery preference',
    'Clinic is Kurigram Sadar Upazila Health Complex. Prefer afternoon delivery.',
    FALSE
  WHERE v_case_001_id IS NOT NULL AND v_rahima_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM case_messages m
      WHERE m.case_id = v_case_001_id AND m.subject = 'Clinic and delivery preference'
    ) ON CONFLICT DO NOTHING;
  INSERT INTO case_messages (case_id, sender_user_id, message_type, subject, body, is_internal)
  SELECT v_case_001_id, v_actor_id, 'system_note',
    'Internal routing',
    'Route to Sadar relief desk for non-urgent medicine coordination.',
    TRUE
  WHERE v_case_001_id IS NOT NULL AND v_actor_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM case_messages m
      WHERE m.case_id = v_case_001_id AND m.subject = 'Internal routing'
    );
  -- Notifications ON CONFLICT DO NOTHING;
  INSERT INTO notifications (template_id, notification_type, title, body, entity_type, entity_id, created_by_user_id)
  SELECT t.id, 'case_reply', 'Your report has been received',
    'Your report (IR-KUR-SHOW-001) has been received. We will review it shortly.',
    'intake_report', v_intake_001_id, NULL
  FROM notification_templates t
  WHERE t.template_code = 'intake_received__in_app'
    AND v_intake_001_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM notifications n
      WHERE n.entity_type = 'intake_report' AND n.entity_id = v_intake_001_id
        AND n.title = 'Your report has been received'
    ) ON CONFLICT DO NOTHING;
  INSERT INTO notifications (template_id, notification_type, title, body, entity_type, entity_id, created_by_user_id)
  SELECT t.id, 'case_reply', 'Your report has been received',
    'Your report (IR-KUR-SHOW-005) has been received. We will review it shortly.',
    'intake_report', v_intake_005_id, NULL
  FROM notification_templates t
  WHERE t.template_code = 'intake_received__in_app'
    AND v_intake_005_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM notifications n
      WHERE n.entity_type = 'intake_report' AND n.entity_id = v_intake_005_id
        AND n.title = 'Your report has been received'
    ) ON CONFLICT DO NOTHING;
  INSERT INTO notifications (template_id, notification_type, title, body, entity_type, entity_id, created_by_user_id)
  SELECT t.id, 'case_reply', 'Service case opened',
    'Your report has been reviewed and service case SC-KUR-SHOW-001 has been opened.',
    'service_case', v_case_001_id, v_actor_id
  FROM notification_templates t
  WHERE t.template_code = 'intake_classified__in_app'
    AND v_case_001_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM notifications n
      WHERE n.entity_type = 'service_case' AND n.entity_id = v_case_001_id
        AND n.title = 'Service case opened'
    ) ON CONFLICT DO NOTHING;
  INSERT INTO notifications (template_id, notification_type, title, body, entity_type, entity_id, created_by_user_id)
  SELECT t.id, 'incident_update', 'Incident EMI-KUR-PRE-001 status update',
    'Incident EMI-KUR-PRE-001 has been updated from ''dispatched'' to ''in_progress''.',
    'emergency_incident', v_inc_101_id, v_actor_id
  FROM notification_templates t
  WHERE t.template_code = 'incident_status_updated__in_app'
    AND v_inc_101_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM notifications n
      WHERE n.entity_type = 'emergency_incident' AND n.entity_id = v_inc_101_id
        AND n.title = 'Incident EMI-KUR-PRE-001 status update'
    ) ON CONFLICT DO NOTHING;
  INSERT INTO notification_recipients (notification_id, recipient_user_id, delivery_channel)
  SELECT n.id, v_rahima_id, 'in_app'
  FROM notifications n
  WHERE n.entity_type = 'intake_report' AND n.entity_id = v_intake_001_id
    AND v_rahima_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM notification_recipients r
      WHERE r.notification_id = n.id AND r.recipient_user_id = v_rahima_id AND r.delivery_channel = 'in_app'
    ) ON CONFLICT DO NOTHING;
  INSERT INTO notification_recipients (notification_id, recipient_user_id, delivery_channel)
  SELECT n.id, (SELECT id FROM users WHERE email = 'citizen.karim@niers.test' LIMIT 1), 'in_app'
  FROM notifications n
  WHERE n.entity_type = 'intake_report' AND n.entity_id = v_intake_005_id
    AND NOT EXISTS (
      SELECT 1 FROM notification_recipients r
      WHERE r.notification_id = n.id AND r.delivery_channel = 'in_app'
    ) ON CONFLICT DO NOTHING;
  INSERT INTO notification_recipients (notification_id, recipient_user_id, delivery_channel)
  SELECT n.id, v_rahima_id, 'in_app'
  FROM notifications n
  WHERE n.entity_type = 'service_case' AND n.entity_id = v_case_001_id
    AND v_rahima_id IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM notification_recipients r
      WHERE r.notification_id = n.id AND r.recipient_user_id = v_rahima_id AND r.delivery_channel = 'in_app'
    ) ON CONFLICT DO NOTHING;
END $$;