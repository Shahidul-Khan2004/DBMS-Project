-- ============================================================
-- Project-show views
-- ============================================================

CREATE VIEW vw_user_case_dashboard AS
SELECT
    sc.id AS case_id,
    sc.case_code,
    sc.reporter_user_id,
    sc.parent_case_id,
    sc.title,
    rc.name AS category_name,
    cs.status_code AS current_status,
    sc.priority_level,
    sc.created_at,
    sc.updated_at,
    cr.resolution_type,
    cr.resolved_at,
    ce.emergency_incident_id,
    COUNT(child.id) AS follow_up_count,
    MAX(cm.created_at) AS latest_message_at
FROM service_cases sc
JOIN report_categories rc ON rc.id = sc.category_id
JOIN case_statuses cs ON cs.id = sc.current_status_id
LEFT JOIN case_resolutions cr ON cr.case_id = sc.id
LEFT JOIN case_escalations ce ON ce.case_id = sc.id
LEFT JOIN service_cases child ON child.parent_case_id = sc.id
LEFT JOIN case_messages cm ON cm.case_id = sc.id
GROUP BY sc.id, sc.case_code, sc.reporter_user_id, sc.parent_case_id, sc.title, rc.name,
         cs.status_code, sc.priority_level, sc.created_at, sc.updated_at,
         cr.resolution_type, cr.resolved_at, ce.emergency_incident_id;

CREATE VIEW vw_admin_case_queue AS
SELECT
    sc.id AS case_id,
    sc.case_code,
    sc.title,
    rc.name AS category_name,
    cs.status_code AS current_status,
    sc.priority_level,
    sc.created_at,
    TIMESTAMPDIFF(MINUTE, sc.created_at, CURRENT_TIMESTAMP) AS age_minutes,
    ca.assigned_admin_id
FROM service_cases sc
JOIN report_categories rc ON rc.id = sc.category_id
JOIN case_statuses cs ON cs.id = sc.current_status_id
LEFT JOIN case_assignments ca
       ON ca.case_id = sc.id
      AND ca.assignment_status = 'active'
      AND ca.ended_at IS NULL
WHERE cs.is_terminal = FALSE;

CREATE VIEW vw_duplicate_emergency_call_clusters AS
SELECT
    ei.id AS incident_id,
    ei.incident_code,
    ei.title,
    COUNT(ec.id) AS linked_emergency_calls,
    MIN(ec.call_started_at) AS first_call_at,
    MAX(ec.call_started_at) AS latest_call_at
FROM emergency_incidents ei
JOIN incident_report_links irl ON irl.incident_id = ei.id
JOIN emergency_calls ec ON ec.intake_report_id = irl.intake_report_id
GROUP BY ei.id, ei.incident_code, ei.title;

CREATE VIEW vw_dispatcher_performance AS
SELECT
    ec.dispatcher_id,
    up.full_name AS dispatcher_name,
    COUNT(ec.id) AS total_calls,
    AVG(TIMESTAMPDIFF(SECOND, ec.call_started_at, ei.created_at)) AS avg_seconds_call_to_incident
FROM emergency_calls ec
LEFT JOIN incident_report_links irl ON irl.intake_report_id = ec.intake_report_id
LEFT JOIN emergency_incidents ei ON ei.id = irl.incident_id
LEFT JOIN user_profiles up ON up.user_id = ec.dispatcher_id
GROUP BY ec.dispatcher_id, up.full_name;

CREATE VIEW vw_false_alarm_by_area AS
SELECT
    aa.id AS admin_area_id,
    aa.name AS area_name,
    COUNT(ei.id) AS total_incidents,
    SUM(CASE WHEN io.outcome_code = 'false_alarm' THEN 1 ELSE 0 END) AS false_alarm_count,
    ROUND(SUM(CASE WHEN io.outcome_code = 'false_alarm' THEN 1 ELSE 0 END) / NULLIF(COUNT(ei.id),0) * 100, 2) AS false_alarm_rate_percent
FROM emergency_incidents ei
JOIN locations l ON l.id = ei.current_location_id
LEFT JOIN administrative_areas aa ON aa.id = l.admin_area_id
LEFT JOIN incident_outcomes io ON io.id = ei.final_outcome_id
GROUP BY aa.id, aa.name;

CREATE VIEW vw_emergency_call_heatmap AS
SELECT
    aa.id AS admin_area_id,
    aa.name AS area_name,
    rc.category_code,
    HOUR(ec.call_started_at) AS call_hour,
    COUNT(*) AS call_count
FROM emergency_calls ec
JOIN intake_reports ir ON ir.id = ec.intake_report_id
JOIN report_categories rc ON rc.id = ir.category_id
LEFT JOIN locations l ON l.id = ir.reported_location_id
LEFT JOIN administrative_areas aa ON aa.id = l.admin_area_id
GROUP BY aa.id, aa.name, rc.category_code, HOUR(ec.call_started_at);

CREATE VIEW vw_escalation_comparison AS
SELECT
    ei.origin_type,
    COUNT(*) AS incident_count,
    AVG(TIMESTAMPDIFF(MINUTE, ei.reported_at, ei.created_at)) AS avg_minutes_reported_to_created,
    AVG(TIMESTAMPDIFF(MINUTE, ei.created_at, ei.resolved_at)) AS avg_minutes_created_to_resolved
FROM emergency_incidents ei
GROUP BY ei.origin_type;

CREATE VIEW vw_response_pipeline_timing AS
SELECT
    ei.id AS incident_id,
    ei.incident_code,
    MIN(ec.call_started_at) AS first_call_started_at,
    ei.created_at AS incident_created_at,
    MIN(iap.joined_at) AS first_agency_joined_at,
    MIN(d.assigned_at) AS first_unit_assigned_at,
    MIN(d.dispatched_at) AS first_unit_dispatched_at,
    MIN(d.arrived_at) AS first_unit_arrived_at,
    TIMESTAMPDIFF(MINUTE, MIN(ec.call_started_at), ei.created_at) AS call_to_incident_minutes,
    TIMESTAMPDIFF(MINUTE, ei.created_at, MIN(iap.joined_at)) AS incident_to_agency_minutes,
    TIMESTAMPDIFF(MINUTE, MIN(iap.joined_at), MIN(d.dispatched_at)) AS agency_to_dispatch_minutes,
    TIMESTAMPDIFF(MINUTE, MIN(d.dispatched_at), MIN(d.arrived_at)) AS dispatch_to_arrival_minutes
FROM emergency_incidents ei
LEFT JOIN incident_report_links irl ON irl.incident_id = ei.id
LEFT JOIN emergency_calls ec ON ec.intake_report_id = irl.intake_report_id
LEFT JOIN incident_agency_participation iap ON iap.incident_id = ei.id
LEFT JOIN dispatches d ON d.incident_id = ei.id
GROUP BY ei.id, ei.incident_code, ei.created_at;

CREATE VIEW vw_agency_workload AS
SELECT
    a.id AS agency_id,
    a.name AS agency_name,
    COUNT(DISTINCT CASE WHEN iap.participation_status IN ('requested','active') THEN iap.incident_id END) AS active_incidents,
    COUNT(DISTINCT eu.id) AS total_units,
    SUM(CASE WHEN eu.current_status = 'available' THEN 1 ELSE 0 END) AS available_units,
    SUM(CASE WHEN eu.current_status = 'busy' THEN 1 ELSE 0 END) AS busy_units,
    COUNT(DISTINCT d.id) AS total_dispatches
FROM agencies a
LEFT JOIN incident_agency_participation iap ON iap.agency_id = a.id
LEFT JOIN emergency_units eu ON eu.agency_id = a.id
LEFT JOIN dispatches d ON d.unit_id = eu.id
GROUP BY a.id, a.name;

CREATE VIEW vw_facility_capacity_status AS
SELECT
    f.id AS facility_id,
    f.name AS facility_name,
    ft.type_code AS facility_type,
    fcs.capacity_type,
    fcs.total_capacity,
    fcs.available_capacity,
    fcs.occupied_capacity,
    ROUND(fcs.occupied_capacity / NULLIF(fcs.total_capacity,0) * 100, 2) AS occupancy_percent,
    fcs.recorded_at
FROM facilities f
JOIN facility_types ft ON ft.id = f.facility_type_id
JOIN facility_capacity_snapshots fcs ON fcs.facility_id = f.id
WHERE fcs.recorded_at = (
    SELECT MAX(fcs2.recorded_at)
      FROM facility_capacity_snapshots fcs2
     WHERE fcs2.facility_id = fcs.facility_id
       AND fcs2.capacity_type = fcs.capacity_type
);

CREATE VIEW vw_disaster_dashboard AS
SELECT
    de.id AS disaster_event_id,
    de.event_code,
    de.title,
    de.current_status,
    de.severity_level,
    COUNT(DISTINCT daa.admin_area_id) AS affected_area_count,
    COUNT(DISTINCT dap.agency_id) AS participating_agency_count,
    COUNT(DISTINCT ro.id) AS rescue_operation_count,
    COUNT(DISTINCT sa.id) AS active_shelter_count,
    COALESCE(SUM(sos.people_count),0) AS latest_reported_shelter_people
FROM disaster_events de
LEFT JOIN disaster_affected_areas daa ON daa.disaster_event_id = de.id
LEFT JOIN disaster_agency_participation dap ON dap.disaster_event_id = de.id
LEFT JOIN rescue_operations ro ON ro.disaster_event_id = de.id
LEFT JOIN shelter_activations sa ON sa.disaster_event_id = de.id AND sa.activation_status IN ('active','full')
LEFT JOIN shelter_occupancy_snapshots sos ON sos.shelter_activation_id = sa.id
GROUP BY de.id, de.event_code, de.title, de.current_status, de.severity_level;
