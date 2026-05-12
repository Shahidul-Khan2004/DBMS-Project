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
 'Hello,\n\nWe have received your report ({{report_code}}).\nYou will be notified as it is reviewed.\n\nThank you.',
 TRUE),

-- ── Intake classified as service case ────────────────────────
('intake_classified__in_app', 'in_app', NULL,
 'Your report has been reviewed and a service case ({{case_code}}) has been opened. Our team will follow up with you.',
 TRUE),

('intake_classified__email',  'email',
 'Your report has been reviewed – {{case_code}}',
 'Hello,\n\nYour report has been reviewed and a service case ({{case_code}}) has been opened.\nOur team will follow up with you shortly.\n\nThank you.',
 TRUE),

-- ── Intake escalated to emergency (both paths) ───────────────
('intake_escalated__in_app', 'in_app', NULL,
 'Your report has been escalated to emergency incident {{incident_code}}. Emergency responders have been notified.',
 TRUE),

('intake_escalated__email',  'email',
 'Emergency escalation – {{incident_code}}',
 'Hello,\n\nYour intake report has been escalated to emergency incident {{incident_code}}.\nEmergency responders have been notified and are responding.\n\nStay safe.',
 TRUE),

-- ── Incident created (standalone) ────────────────────────────
('incident_created__in_app', 'in_app', NULL,
 'Emergency incident {{incident_code}} has been created and is now active.',
 TRUE),

('incident_created__email',  'email',
 'Incident created – {{incident_code}}',
 'Hello,\n\nEmergency incident {{incident_code}} has been created and is now active.\n\nThank you.',
 TRUE),

-- ── Incident status updated ───────────────────────────────────
('incident_status_updated__in_app', 'in_app', NULL,
 'Incident {{incident_code}} has been updated from ''{{from_status}}'' to ''{{to_status}}''.{{note_line}}',
 TRUE),

('incident_status_updated__email',  'email',
 'Incident {{incident_code}} status update',
 'Hello,\n\nIncident {{incident_code}} has been updated.\n\nPrevious status: {{from_status}}\nNew status:      {{to_status}}{{note_line}}\n\nThank you.',
 TRUE);