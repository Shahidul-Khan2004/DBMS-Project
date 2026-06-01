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
JOIN incident_report_links irl ON irl.incident_id = ei.id AND irl.unlinked_at IS NULL
JOIN emergency_calls ec ON ec.intake_report_id = irl.intake_report_id
GROUP BY ei.id, ei.incident_code, ei.title;

CREATE VIEW vw_dispatcher_performance AS
SELECT
    ec.dispatcher_id,
    up.full_name AS dispatcher_name,
    COUNT(ec.id) AS total_calls,
    AVG(TIMESTAMPDIFF(SECOND, ec.call_started_at, ei.created_at)) AS avg_seconds_call_to_incident
FROM emergency_calls ec
LEFT JOIN incident_report_links irl ON irl.intake_report_id = ec.intake_report_id AND irl.unlinked_at IS NULL
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
LEFT JOIN incident_report_links irl ON irl.incident_id = ei.id AND irl.unlinked_at IS NULL
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
    COUNT(DISTINCT CASE WHEN us.status_code = 'available' THEN eu.id END) AS available_units,
    COUNT(DISTINCT CASE WHEN us.status_code = 'busy' THEN eu.id END) AS busy_units,
    COUNT(DISTINCT d.id) AS total_dispatches
FROM agencies a
LEFT JOIN incident_agency_participation iap ON iap.agency_id = a.id
LEFT JOIN emergency_units eu ON eu.agency_id = a.id
LEFT JOIN unit_statuses us ON us.id = eu.current_status_id
LEFT JOIN dispatches d ON d.unit_id = eu.id
GROUP BY a.id, a.name;

CREATE VIEW vw_facility_capacity_status AS
SELECT
    f.id AS facility_id,
    f.name AS facility_name,
    ft.type_code AS facility_type,
    fcs.capacity_type,
    fcs.total_capacity,
    fcs.occupied_capacity,
    (fcs.total_capacity - fcs.occupied_capacity) AS available_capacity,
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

CREATE VIEW vw_disaster_affected_area_current AS
SELECT
    daa.id AS disaster_affected_area_id,
    daa.disaster_event_id,
    daa.admin_area_id,
    a.impact_level,
    a.estimated_affected_people,
    a.shelter_support_required,
    a.relief_support_required,
    a.assessment_note,
    a.recorded_by_user_id,
    a.recorded_at
FROM disaster_affected_areas daa
INNER JOIN disaster_affected_area_assessments a ON a.id = (
    SELECT a2.id
      FROM disaster_affected_area_assessments a2
     WHERE a2.disaster_affected_area_id = daa.id
     ORDER BY a2.recorded_at DESC, a2.id DESC
     LIMIT 1
);

CREATE VIEW vw_public_disaster_summary AS
SELECT
    de.public_uuid AS disaster_public_uuid,
    de.event_code,
    de.title,
    det.type_code AS disaster_type_code,
    det.name AS disaster_type_name,
    de.severity_level,
    des.status_code AS disaster_status,
    de.public_guidance,
    de.started_at,
    de.ended_at
FROM disaster_events de
JOIN disaster_event_types det ON det.id = de.event_type_id
JOIN disaster_event_statuses des ON des.id = de.current_status_id
WHERE des.status_code IN ('declared','resolved','closed');

CREATE VIEW vw_disaster_dashboard AS
SELECT
    de.id AS disaster_event_id,
    de.public_uuid AS disaster_public_uuid,
    de.event_code,
    de.title,
    des.status_code AS disaster_status,
    de.severity_level,
    COUNT(DISTINCT daa.id) AS affected_area_count,
    COUNT(DISTINCT dar.agency_id) AS participating_agency_count,
    COUNT(DISTINCT CASE WHEN sa.activation_status = 'active' THEN sa.id END) AS active_shelter_count,
    COALESCE(SUM(latest_occ.people_count), 0) AS latest_reported_shelter_people
FROM disaster_events de
JOIN disaster_event_statuses des ON des.id = de.current_status_id
LEFT JOIN disaster_affected_areas daa ON daa.disaster_event_id = de.id
LEFT JOIN disaster_agency_responsibilities dar ON dar.disaster_event_id = de.id AND dar.deactivated_at IS NULL
LEFT JOIN shelter_activations sa ON sa.disaster_event_id = de.id
LEFT JOIN (
    SELECT sos.shelter_activation_id, sos.people_count
      FROM shelter_occupancy_snapshots sos
     INNER JOIN (
        SELECT shelter_activation_id, MAX(recorded_at) AS max_recorded
          FROM shelter_occupancy_snapshots
         GROUP BY shelter_activation_id
     ) latest ON latest.shelter_activation_id = sos.shelter_activation_id
             AND latest.max_recorded = sos.recorded_at
) latest_occ ON latest_occ.shelter_activation_id = sa.id
GROUP BY de.id, de.public_uuid, de.event_code, de.title, des.status_code, de.severity_level;

CREATE VIEW vw_disaster_impact_by_upazila AS
SELECT
    de.id AS disaster_event_id,
    daa.id AS disaster_affected_area_id,
    aa.id AS admin_area_id,
    aa.name AS upazila_name,
    district.name AS district_name,
    division.name AS division_name,
    cur.impact_level,
    cur.estimated_affected_people,
    cur.shelter_support_required,
    cur.relief_support_required,
    cur.recorded_at AS assessment_recorded_at
FROM disaster_events de
JOIN disaster_affected_areas daa ON daa.disaster_event_id = de.id
JOIN administrative_areas aa ON aa.id = daa.admin_area_id
LEFT JOIN administrative_areas district ON district.id = aa.parent_area_id
LEFT JOIN administrative_areas division ON division.id = district.parent_area_id
LEFT JOIN vw_disaster_affected_area_current cur ON cur.disaster_affected_area_id = daa.id;

CREATE VIEW vw_disaster_linked_incidents AS
SELECT
    de.id AS disaster_event_id,
    ist.status_code AS incident_status,
    COUNT(DISTINCT ei.id) AS incident_count
FROM disaster_events de
JOIN disaster_incident_links dil ON dil.disaster_event_id = de.id AND dil.unlinked_at IS NULL
JOIN emergency_incidents ei ON ei.id = dil.incident_id
JOIN incident_statuses ist ON ist.id = ei.current_status_id
GROUP BY de.id, ist.status_code;

CREATE VIEW vw_disaster_shelter_capacity AS
SELECT
    sa.id AS shelter_activation_id,
    sa.public_uuid AS shelter_activation_public_uuid,
    sa.disaster_event_id,
    f.id AS facility_id,
    f.public_uuid AS facility_public_uuid,
    f.name AS facility_name,
    sa.activation_status,
    COALESCE(sa.usable_capacity_override, fdc.total_capacity) AS effective_capacity,
    latest_occ.people_count AS latest_occupancy,
    GREATEST(
        COALESCE(sa.usable_capacity_override, fdc.total_capacity, 0) - COALESCE(latest_occ.people_count, 0),
        0
    ) AS available_capacity,
    CASE
        WHEN latest_occ.people_count IS NOT NULL
         AND COALESCE(sa.usable_capacity_override, fdc.total_capacity) IS NOT NULL
         AND latest_occ.people_count > COALESCE(sa.usable_capacity_override, fdc.total_capacity)
        THEN TRUE ELSE FALSE
    END AS is_over_capacity,
    CASE
        WHEN latest_occ.people_count IS NOT NULL
         AND COALESCE(sa.usable_capacity_override, fdc.total_capacity) IS NOT NULL
         AND latest_occ.people_count > COALESCE(sa.usable_capacity_override, fdc.total_capacity)
        THEN latest_occ.people_count - COALESCE(sa.usable_capacity_override, fdc.total_capacity)
        ELSE 0
    END AS overflow_count
FROM shelter_activations sa
JOIN facilities f ON f.id = sa.facility_id
LEFT JOIN facility_default_capacities fdc ON fdc.facility_id = f.id AND fdc.capacity_type = 'shelter_people'
LEFT JOIN (
    SELECT sos.shelter_activation_id, sos.people_count
      FROM shelter_occupancy_snapshots sos
     INNER JOIN (
        SELECT shelter_activation_id, MAX(recorded_at) AS max_recorded
          FROM shelter_occupancy_snapshots
         GROUP BY shelter_activation_id
     ) latest ON latest.shelter_activation_id = sos.shelter_activation_id
             AND latest.max_recorded = sos.recorded_at
) latest_occ ON latest_occ.shelter_activation_id = sa.id;

CREATE VIEW vw_disaster_relief_inventory_balance AS
SELECT
    rha.disaster_event_id,
    rha.facility_id,
    COALESCE(rsr.relief_item_id, rdi.relief_item_id) AS relief_item_id,
    COALESCE(SUM(rsr.quantity_received), 0) AS total_received,
    COALESCE(SUM(rdi.quantity_delivered), 0) AS total_distributed,
    COALESCE(SUM(rsr.quantity_received), 0) - COALESCE(SUM(rdi.quantity_delivered), 0) AS quantity_on_hand
FROM relief_hub_activations rha
LEFT JOIN relief_stock_receipts rsr ON rsr.relief_hub_activation_id = rha.id
LEFT JOIN relief_distributions rd ON rd.source_hub_activation_id = rha.id
LEFT JOIN relief_distribution_items rdi ON rdi.relief_distribution_id = rd.id
GROUP BY rha.disaster_event_id, rha.facility_id, COALESCE(rsr.relief_item_id, rdi.relief_item_id);

CREATE VIEW vw_disaster_relief_shortage AS
SELECT
    rr.id AS relief_request_id,
    rr.disaster_event_id,
    rr.shelter_activation_id,
    ri.id AS relief_item_id,
    ri.item_code,
    ri.name AS item_name,
    rri.quantity_requested,
    COALESCE(delivered.total_delivered, 0) AS total_delivered,
    GREATEST(rri.quantity_requested - COALESCE(delivered.total_delivered, 0), 0) AS shortage_quantity
FROM relief_requests rr
JOIN relief_request_items rri ON rri.relief_request_id = rr.id
JOIN relief_items ri ON ri.id = rri.relief_item_id
LEFT JOIN (
    SELECT rd.relief_request_id, rdi.relief_item_id, SUM(rdi.quantity_delivered) AS total_delivered
      FROM relief_distributions rd
      JOIN relief_distribution_items rdi ON rdi.relief_distribution_id = rd.id
     GROUP BY rd.relief_request_id, rdi.relief_item_id
) delivered ON delivered.relief_request_id = rr.id AND delivered.relief_item_id = ri.id;

CREATE VIEW vw_disaster_relief_inventory_by_hub AS
SELECT
    rha.id AS relief_hub_activation_id,
    rha.public_uuid AS relief_hub_public_uuid,
    rha.disaster_event_id,
    f.id AS facility_id,
    f.name AS facility_name,
    inv.relief_item_id,
    ri.item_code,
    ri.name AS item_name,
    inv.quantity_on_hand
FROM relief_hub_activations rha
JOIN facilities f ON f.id = rha.facility_id
LEFT JOIN vw_disaster_relief_inventory_balance inv ON inv.disaster_event_id = rha.disaster_event_id
    AND inv.facility_id = rha.facility_id
LEFT JOIN relief_items ri ON ri.id = inv.relief_item_id
WHERE rha.activation_status = 'active';
