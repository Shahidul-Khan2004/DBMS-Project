-- ============================================================
-- Seed: notification_templates
-- ============================================================
-- One in_app + one email template per notification event.
-- template_code convention: <event>__<channel>
-- Subject/body use {{placeholder}} tokens that notificationRepo
-- resolves at runtime before inserting into notifications.
-- ============================================================

INSERT INTO notification_templates (template_code, channel, subject_template, body_template, is_active) VALUES

-- ── Intake received ──────────────────────────────────────────
('intake_received__in_app',  'in_app', NULL,
 'Your report ({{report_code}}) has been received. We will review it shortly.',
 TRUE),

('intake_received__email',   'email',
 'We received your report – {{report_code}}',
 'Hello,\n\nThank you for submitting your report.\n\nWe have received your report with reference code {{report_code}}. Our team will review the information you provided and take the necessary next steps.\n\nYou will be notified when there is an update on your report. Please keep this reference code for future communication.\n\nThank you,\nNIERS Support Team',
 TRUE),

-- ── Intake classified as service case ────────────────────────
('intake_classified__in_app', 'in_app', NULL,
 'Your report has been reviewed and a service case ({{case_code}}) has been opened. Our team will follow up with you.',
 TRUE),

('intake_classified__email',  'email',
 'Your report has been reviewed – {{case_code}}',
 'Hello,\n\nYour report has been reviewed by our team, and a service case has been opened for further follow-up.\n\nService case reference: {{case_code}}\n\nOur team will review the details and take appropriate action based on the information provided. You will be notified if further updates or actions are required.\n\nThank you for helping us improve public service response.\n\nRegards,\nNIERS Support Team',
 TRUE),

-- ── Intake escalated to emergency (both paths) ───────────────
('intake_escalated__in_app', 'in_app', NULL,
 'Your report has been escalated to emergency incident {{incident_code}}. Emergency responders have been notified.',
 TRUE),

('intake_escalated__email',  'email',
 'Emergency escalation – {{incident_code}}',
 'Hello,\n\nYour report has been escalated to an emergency incident.\n\nIncident reference: {{incident_code}}\n\nEmergency responders have been notified, and the incident is now being handled through the emergency response process. Please remain safe and follow any instructions provided by authorized emergency personnel.\n\nRegards,\nNIERS Emergency Response Team',
 TRUE),

-- ── Incident created (standalone) ────────────────────────────
('incident_created__in_app', 'in_app', NULL,
 'Emergency incident {{incident_code}} has been created and is now active.',
 TRUE),

('incident_created__email',  'email',
 'Incident created – {{incident_code}}',
 'Hello,\n\nA new emergency incident has been created and is now active.\n\nIncident reference: {{incident_code}}\n\nThe incident has been recorded in the system and can now be tracked by the responsible operations team. Further updates will be recorded as the incident progresses.\n\nRegards,\nNIERS Operations Team',
 TRUE),

-- ── Incident status updated ───────────────────────────────────
('incident_status_updated__in_app', 'in_app', NULL,
 'Incident {{incident_code}} has been updated from ''{{from_status}}'' to ''{{to_status}}''.{{note_line}}',
 TRUE),

('incident_status_updated__email',  'email',
 'Incident {{incident_code}} status update',
 'Hello,\n\nThere has been a status update for emergency incident {{incident_code}}.\n\nPrevious status: {{from_status}}\nNew status: {{to_status}}{{note_line}}\n\nThis update has been recorded by the operations team. Further action will continue according to the current incident status.\n\nRegards,\nNIERS Operations Team',
 TRUE);