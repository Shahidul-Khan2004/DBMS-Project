-- ============================================================
-- Showcase: service case messages + in-app notifications
-- ============================================================

SET @rahima_id = (SELECT id FROM users WHERE email = 'citizen.rahima@niers.test' LIMIT 1);
SET @actor_id = COALESCE(
  (SELECT id FROM users WHERE email = 'dispatcher@niers.test' LIMIT 1),
  (SELECT id FROM users ORDER BY id ASC LIMIT 1)
);
SET @case_001_id = (SELECT id FROM service_cases WHERE case_code = 'SC-KUR-SHOW-001' LIMIT 1);
SET @intake_001_id = (SELECT id FROM intake_reports WHERE report_code = 'IR-KUR-SHOW-001' LIMIT 1);
SET @intake_005_id = (SELECT id FROM intake_reports WHERE report_code = 'IR-KUR-SHOW-005' LIMIT 1);
SET @inc_101_id = (SELECT id FROM emergency_incidents WHERE incident_code = 'EMI-KUR-PRE-001' LIMIT 1);

INSERT INTO case_messages (case_id, sender_user_id, message_type, subject, body, is_internal)
SELECT @case_001_id, @rahima_id, 'user_message',
  'Documents for medicine support',
  'Which documents do I need to submit for monthly diabetes medicine assistance?',
  FALSE
FROM DUAL
WHERE @case_001_id IS NOT NULL AND @rahima_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM case_messages m
    WHERE m.case_id = @case_001_id AND m.subject = 'Documents for medicine support'
  );

INSERT INTO case_messages (case_id, sender_user_id, message_type, subject, body, is_internal)
SELECT @case_001_id, @actor_id, 'admin_reply',
  'Prescription and clinic details needed',
  'Please upload a photo of the prescription and share your mother''s upazila clinic name.',
  FALSE
FROM DUAL
WHERE @case_001_id IS NOT NULL AND @actor_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM case_messages m
    WHERE m.case_id = @case_001_id AND m.subject = 'Prescription and clinic details needed'
  );

INSERT INTO case_messages (case_id, sender_user_id, message_type, subject, body, is_internal)
SELECT @case_001_id, @rahima_id, 'user_message',
  'Clinic and delivery preference',
  'Clinic is Kurigram Sadar Upazila Health Complex. Prefer afternoon delivery.',
  FALSE
FROM DUAL
WHERE @case_001_id IS NOT NULL AND @rahima_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM case_messages m
    WHERE m.case_id = @case_001_id AND m.subject = 'Clinic and delivery preference'
  );

INSERT INTO case_messages (case_id, sender_user_id, message_type, subject, body, is_internal)
SELECT @case_001_id, @actor_id, 'system_note',
  'Internal routing',
  'Route to Sadar relief desk for non-urgent medicine coordination.',
  TRUE
FROM DUAL
WHERE @case_001_id IS NOT NULL AND @actor_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM case_messages m
    WHERE m.case_id = @case_001_id AND m.subject = 'Internal routing'
  );

-- Notifications
INSERT INTO notifications (template_id, notification_type, title, body, entity_type, entity_id, created_by_user_id)
SELECT t.id, 'case_reply', 'Your report has been received',
  'Your report (IR-KUR-SHOW-001) has been received. We will review it shortly.',
  'intake_report', @intake_001_id, NULL
FROM notification_templates t
WHERE t.template_code = 'intake_received__in_app'
  AND @intake_001_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM notifications n
    WHERE n.entity_type = 'intake_report' AND n.entity_id = @intake_001_id
      AND n.title = 'Your report has been received'
  );

INSERT INTO notifications (template_id, notification_type, title, body, entity_type, entity_id, created_by_user_id)
SELECT t.id, 'case_reply', 'Your report has been received',
  'Your report (IR-KUR-SHOW-005) has been received. We will review it shortly.',
  'intake_report', @intake_005_id, NULL
FROM notification_templates t
WHERE t.template_code = 'intake_received__in_app'
  AND @intake_005_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM notifications n
    WHERE n.entity_type = 'intake_report' AND n.entity_id = @intake_005_id
      AND n.title = 'Your report has been received'
  );

INSERT INTO notifications (template_id, notification_type, title, body, entity_type, entity_id, created_by_user_id)
SELECT t.id, 'case_reply', 'Service case opened',
  'Your report has been reviewed and service case SC-KUR-SHOW-001 has been opened.',
  'service_case', @case_001_id, @actor_id
FROM notification_templates t
WHERE t.template_code = 'intake_classified__in_app'
  AND @case_001_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM notifications n
    WHERE n.entity_type = 'service_case' AND n.entity_id = @case_001_id
      AND n.title = 'Service case opened'
  );

INSERT INTO notifications (template_id, notification_type, title, body, entity_type, entity_id, created_by_user_id)
SELECT t.id, 'incident_update', 'Incident EMI-KUR-PRE-001 status update',
  'Incident EMI-KUR-PRE-001 has been updated from ''dispatched'' to ''in_progress''.',
  'emergency_incident', @inc_101_id, @actor_id
FROM notification_templates t
WHERE t.template_code = 'incident_status_updated__in_app'
  AND @inc_101_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM notifications n
    WHERE n.entity_type = 'emergency_incident' AND n.entity_id = @inc_101_id
      AND n.title = 'Incident EMI-KUR-PRE-001 status update'
  );

INSERT INTO notification_recipients (notification_id, recipient_user_id, delivery_channel)
SELECT n.id, @rahima_id, 'in_app'
FROM notifications n
WHERE n.entity_type = 'intake_report' AND n.entity_id = @intake_001_id
  AND @rahima_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM notification_recipients r
    WHERE r.notification_id = n.id AND r.recipient_user_id = @rahima_id AND r.delivery_channel = 'in_app'
  );

INSERT INTO notification_recipients (notification_id, recipient_user_id, delivery_channel)
SELECT n.id, (SELECT id FROM users WHERE email = 'citizen.karim@niers.test' LIMIT 1), 'in_app'
FROM notifications n
WHERE n.entity_type = 'intake_report' AND n.entity_id = @intake_005_id
  AND NOT EXISTS (
    SELECT 1 FROM notification_recipients r
    WHERE r.notification_id = n.id AND r.delivery_channel = 'in_app'
  );

INSERT INTO notification_recipients (notification_id, recipient_user_id, delivery_channel)
SELECT n.id, @rahima_id, 'in_app'
FROM notifications n
WHERE n.entity_type = 'service_case' AND n.entity_id = @case_001_id
  AND @rahima_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM notification_recipients r
    WHERE r.notification_id = n.id AND r.recipient_user_id = @rahima_id AND r.delivery_channel = 'in_app'
  );
