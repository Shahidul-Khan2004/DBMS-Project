-- from 21_seed_reference_data.sql
-- ============================================================
-- Seed data for lookup tables
-- ============================================================

INSERT INTO roles (role_code, name, description, is_system_role) VALUES
('citizen','Citizen','Registered public user', TRUE),
('dispatcher','Dispatcher','999 call intake, triage, incident coordination, and dispatch', TRUE),
('agency_representative','Agency Representative','Agency-side user', TRUE),
('system_admin','System Admin','Full system administrator', TRUE) ON CONFLICT DO NOTHING;

INSERT INTO permissions (permission_code, module_name, description) VALUES
('case.create','case','Create service cases'),
('case.respond','case','Respond to service cases'),
('case.assign','case','Assign service cases'),
('case.escalate','case','Escalate service case to emergency incident'),
('incident.create','incident','Create emergency incidents'),
('incident.update','incident','Update emergency incidents'),
('incident.dispatch_unit','dispatch','Dispatch emergency units'),
('agency.manage','agency','Manage agencies and units'),
('disaster.create','disaster','Create disaster events'),
('disaster.read','disaster','View disaster operations'),
('disaster.update_status','disaster','Update disaster lifecycle status'),
('disaster.declare','disaster','Declare disaster/national emergency'),
('disaster.manage_affected_areas','disaster','Manage disaster affected upazilas'),
('disaster.manage_responsibilities','disaster','Assign disaster agency responsibilities'),
('disaster.link_incidents','disaster','Link incidents to disasters'),
('facility.manage','facility','Manage facility master data'),
('facility.read','facility','View facilities and capacity'),
('shelter.manage','shelter','Manage shelter activations'),
('shelter.record_occupancy','shelter','Record shelter occupancy'),
('shelter.record_occupancy_own','shelter','Record occupancy for own managed shelter'),
('relief.manage_inventory','relief','Record verified relief stock'),
('relief.manage_inventory_own','relief','Record verified relief stock for own managed relief hub'),
('relief.manage_requests','relief','Approve or reject relief requests'),
('relief.request_own_shelter','relief','Create relief requests for own shelter'),
('relief.distribute','relief','Manage relief distribution'),
('blood.manage','blood','Manage blood requests and matches'),
('notification.send','notification','Send/queue notifications') ON CONFLICT DO NOTHING;

INSERT INTO report_channels (channel_code, name, description) VALUES
('web_portal','Web Portal','Logged-in web portal report'),
('emergency_call','999 Emergency Call','Emergency phone call intake'),
('admin_entry','Admin Entry','Created by admin/operator'),
('agency_report','Agency Report','Reported by an agency'),
('mobile_app','Mobile App','Mobile app report') ON CONFLICT DO NOTHING;

INSERT INTO report_categories (category_code, name, description) VALUES
('medical','Medical','Medical emergency or health-related issue'),
('crime_public_safety','Crime/Public Safety','Crime, assault, missing person, public safety'),
('fire','Fire','Fire, explosion, gas leak'),
('natural_disaster','Natural Disaster','Flood, cyclone, earthquake, landslide'),
('infrastructure_emergency','Infrastructure Emergency','Bridge collapse, power failure, road hazard'),
('relief_request','Relief Request','Food, water, medicine or shelter need'),
('blood_request','Blood Request','Blood donation or urgent blood request') ON CONFLICT DO NOTHING;

INSERT INTO case_statuses (status_code, name, sort_order, is_terminal) VALUES
('submitted','Submitted',1,FALSE),
('under_review','Under Review',2,FALSE),
('awaiting_user_response','Awaiting User Response',3,FALSE),
('resolved','Resolved',4,TRUE),
('escalated_to_emergency','Escalated to Emergency',5,TRUE),
('closed','Closed',6,TRUE),
('cancelled','Cancelled',7,TRUE) ON CONFLICT DO NOTHING;

INSERT INTO case_status_transitions (from_status_id, to_status_id, is_active, requires_note)
SELECT f.id, t.id, TRUE, FALSE
FROM case_statuses f
INNER JOIN case_statuses t ON (
    (f.status_code = 'submitted' AND t.status_code IN ('under_review', 'cancelled', 'resolved', 'escalated_to_emergency'))
    OR (f.status_code = 'under_review' AND t.status_code IN ('awaiting_user_response', 'closed', 'cancelled', 'resolved', 'escalated_to_emergency'))
    OR (f.status_code = 'awaiting_user_response' AND t.status_code IN ('under_review', 'closed', 'cancelled', 'resolved', 'escalated_to_emergency'))
) ON CONFLICT DO NOTHING;

INSERT INTO intake_statuses (status_code, name, sort_order, is_terminal) VALUES
('received','Received',1,FALSE),
('under_review','Under Review',2,FALSE),
('linked_to_case','Linked to Case',3,FALSE),
('linked_to_incident','Linked to Incident',4,FALSE),
('duplicate','Duplicate',5,TRUE),
('false_report','False Report',6,TRUE),
('closed','Closed',7,TRUE) ON CONFLICT DO NOTHING;

INSERT INTO intake_status_transitions (from_status_id, to_status_id, is_active, requires_note)
SELECT f.id, t.id, TRUE, FALSE
FROM intake_statuses f
INNER JOIN intake_statuses t ON (
    (f.status_code = 'received' AND t.status_code IN ('under_review', 'duplicate', 'false_report', 'closed'))
    OR (f.status_code = 'under_review' AND t.status_code IN ('linked_to_case', 'linked_to_incident', 'duplicate', 'false_report', 'closed'))
    OR (f.status_code = 'linked_to_case' AND t.status_code = 'linked_to_incident')
    OR (f.status_code = 'linked_to_incident' AND t.status_code = 'under_review')
) ON CONFLICT DO NOTHING;

INSERT INTO dispatch_statuses (status_code, name, sort_order, is_terminal) VALUES
('assigned','Assigned',1,FALSE),
('dispatched','Dispatched',2,FALSE),
('arrived','Arrived',3,FALSE),
('completed','Completed',4,TRUE),
('cancelled','Cancelled',5,TRUE) ON CONFLICT DO NOTHING;

INSERT INTO dispatch_status_transitions (from_status_id, to_status_id, is_active, requires_note)
SELECT f.id, t.id, TRUE, FALSE
FROM dispatch_statuses f
INNER JOIN dispatch_statuses t ON (
    (f.status_code = 'assigned' AND t.status_code IN ('dispatched', 'cancelled'))
    OR (f.status_code = 'dispatched' AND t.status_code IN ('arrived', 'cancelled'))
    OR (f.status_code = 'arrived' AND t.status_code IN ('completed', 'cancelled'))
) ON CONFLICT DO NOTHING;

INSERT INTO unit_statuses (status_code, name, sort_order, is_terminal) VALUES
('available','Available',1,FALSE),
('busy','Busy',2,FALSE),
('maintenance','Maintenance',3,FALSE),
('offline','Offline',4,FALSE) ON CONFLICT DO NOTHING;

INSERT INTO unit_status_transitions (from_status_id, to_status_id, is_active, requires_note)
SELECT f.id, t.id, TRUE, FALSE
FROM unit_statuses f
INNER JOIN unit_statuses t ON (
    (f.status_code = 'available' AND t.status_code IN ('busy', 'maintenance', 'offline'))
    OR (f.status_code = 'busy' AND t.status_code IN ('available', 'maintenance', 'offline'))
    OR (f.status_code = 'maintenance' AND t.status_code = 'available')
    OR (f.status_code = 'offline' AND t.status_code = 'available')
) ON CONFLICT DO NOTHING;

INSERT INTO incident_severity_levels (severity_code, name, priority_rank) VALUES
('low','Low',1),
('medium','Medium',2),
('high','High',3),
('critical','Critical',4) ON CONFLICT DO NOTHING;

INSERT INTO incident_statuses (status_code, name, sort_order, is_terminal) VALUES
('classified','Classified',1,FALSE),
('agency_assigned','Agency Assigned',2,FALSE),
('unit_assigned','Unit Assigned',3,FALSE),
('dispatched','Dispatched',4,FALSE),
('in_progress','In Progress',5,FALSE),
('resolved','Resolved',6,TRUE),
('closed','Closed',7,TRUE),
('cancelled','Cancelled',8,TRUE) ON CONFLICT DO NOTHING;

INSERT INTO incident_status_transitions (from_status_id, to_status_id, is_active, requires_note, requires_outcome)
SELECT f.id, t.id, TRUE, FALSE,
       CASE WHEN t.status_code IN ('resolved', 'closed', 'cancelled') THEN TRUE ELSE FALSE END
FROM incident_statuses f
INNER JOIN incident_statuses t ON (
    (f.status_code = 'classified' AND t.status_code IN ('agency_assigned', 'unit_assigned', 'dispatched', 'in_progress', 'resolved', 'closed', 'cancelled'))
    OR (f.status_code = 'agency_assigned' AND t.status_code IN ('unit_assigned', 'dispatched', 'in_progress', 'resolved', 'closed', 'cancelled'))
    OR (f.status_code = 'unit_assigned' AND t.status_code IN ('dispatched', 'in_progress', 'resolved', 'closed', 'cancelled'))
    OR (f.status_code = 'dispatched' AND t.status_code IN ('in_progress', 'resolved', 'closed', 'cancelled'))
    OR (f.status_code = 'in_progress' AND t.status_code IN ('resolved', 'closed', 'cancelled'))
) ON CONFLICT DO NOTHING;

INSERT INTO incident_outcomes (outcome_code, name, is_successful_resolution) VALUES
('resolved','Resolved',TRUE),
('false_alarm','False Alarm',FALSE),
('duplicate_incident','Duplicate Incident',FALSE),
('cancelled','Cancelled',FALSE),
('transferred','Transferred',TRUE),
('unresolved','Unresolved',FALSE) ON CONFLICT DO NOTHING;

INSERT INTO agency_types (type_code, name) VALUES
('police','Police'),
('fire_service','Fire Service'),
('medical_service','Medical Service'),
('disaster_management','Disaster Management'),
('infrastructure_emergency','Infrastructure Emergency'),
('army','Army'),
('ngo','NGO'),
('utility_provider','Utility Provider'),
('local_government','Local Government') ON CONFLICT DO NOTHING;

INSERT INTO capabilities (capability_code, name, capability_group) VALUES
('ambulance_service','Ambulance Service','medical'),
('fire_suppression','Fire Suppression','fire'),
('water_rescue','Water Rescue','rescue'),
('search_and_rescue','Search and Rescue','rescue'),
('crowd_control','Crowd Control','security'),
('medical_triage','Medical Triage','medical'),
('oxygen_support','Oxygen Support','medical'),
('power_line_repair','Power Line Repair','infrastructure'),
('road_clearance','Road Clearance','infrastructure'),
('food_distribution','Food Distribution','relief'),
('relief_distribution_hub','Relief Distribution Hub','relief'),
('temporary_shelter','Temporary Shelter','shelter'),
('blood_support','Blood Support','blood'),
('emergency_care','Emergency Care','medical'),
('icu','ICU','medical'),
('cardiology','Cardiology','medical'),
('burn_unit','Burn Unit','medical'),
('blood_storage','Blood Storage','blood') ON CONFLICT DO NOTHING;

INSERT INTO emergency_unit_types (type_code, name) VALUES
('ambulance','Ambulance'),
('fire_truck','Fire Truck'),
('police_vehicle','Police Vehicle'),
('rescue_boat','Rescue Boat'),
('medical_van','Medical Van'),
('utility_repair_vehicle','Utility Repair Vehicle'),
('relief_truck','Relief Truck'),
('command_vehicle','Command Vehicle'),
('helicopter','Helicopter') ON CONFLICT DO NOTHING;

INSERT INTO work_queues (queue_code, name, queue_type) VALUES
('non_emergency_case_queue','Non-Emergency Case Queue','service_case'),
('emergency_call_triage_queue','Emergency Call Triage Queue','emergency_call'),
('incident_dispatch_queue','Incident Dispatch Queue','dispatch'),
('disaster_relief_queue','Disaster Relief Queue','disaster_relief') ON CONFLICT DO NOTHING;

INSERT INTO disaster_event_statuses (status_code, name, sort_order, is_terminal) VALUES
('monitoring','Monitoring',1,FALSE),
('declared','Declared',2,FALSE),
('resolved','Resolved',3,FALSE),
('closed','Closed',4,TRUE),
('cancelled','Cancelled',5,TRUE) ON CONFLICT DO NOTHING;

INSERT INTO disaster_event_status_transitions (from_status_id, to_status_id, is_active, requires_note)
SELECT f.id, t.id, TRUE, FALSE
FROM disaster_event_statuses f
INNER JOIN disaster_event_statuses t ON (
    (f.status_code = 'monitoring' AND t.status_code IN ('declared','cancelled'))
    OR (f.status_code = 'declared' AND t.status_code IN ('resolved','cancelled'))
    OR (f.status_code = 'resolved' AND t.status_code = 'closed')
) ON CONFLICT DO NOTHING;

INSERT INTO relief_request_statuses (status_code, name, sort_order, is_terminal) VALUES
('submitted','Submitted',1,FALSE),
('approved','Approved',2,FALSE),
('rejected','Rejected',3,TRUE),
('partially_fulfilled','Partially Fulfilled',4,FALSE),
('fulfilled','Fulfilled',5,TRUE) ON CONFLICT DO NOTHING;

INSERT INTO relief_request_status_transitions (from_status_id, to_status_id, is_active, requires_note)
SELECT f.id, t.id, TRUE,
       CASE WHEN t.status_code = 'rejected' THEN TRUE ELSE FALSE END
FROM relief_request_statuses f
INNER JOIN relief_request_statuses t ON (
    (f.status_code = 'submitted' AND t.status_code IN ('approved','rejected','partially_fulfilled','fulfilled'))
    OR (f.status_code = 'approved' AND t.status_code IN ('partially_fulfilled','fulfilled','rejected'))
    OR (f.status_code = 'partially_fulfilled' AND t.status_code IN ('fulfilled','partially_fulfilled'))
) ON CONFLICT DO NOTHING;

INSERT INTO disaster_event_types (type_code, name) VALUES
('flood','Flood'),
('cyclone','Cyclone'),
('earthquake','Earthquake'),
('landslide','Landslide'),
('epidemic','Epidemic'),
('industrial_disaster','Industrial Disaster') ON CONFLICT DO NOTHING;

INSERT INTO facility_types (type_code, name) VALUES
('hospital','Hospital'),
('clinic','Clinic'),
('shelter','Shelter'),
('blood_bank','Blood Bank'),
('relief_center','Relief Center'),
('warehouse','Warehouse'),
('school_shelter_capable','School / Shelter Capable'),
('community_center','Community Center') ON CONFLICT DO NOTHING;

INSERT INTO relief_items (item_code, name, unit_of_measure) VALUES
('rice','Rice','kg'),
('bottled_water','Bottled Water','bottle'),
('dry_food_packet','Dry Food Packet','packet'),
('blanket','Blanket','piece'),
('medicine_kit','Medicine Kit','kit'),
('hygiene_kit','Hygiene Kit','kit') ON CONFLICT DO NOTHING;

INSERT INTO blood_groups (group_code, name) VALUES
('A+','A Positive'),
('A-','A Negative'),
('B+','B Positive'),
('B-','B Negative'),
('AB+','AB Positive'),
('AB-','AB Negative'),
('O+','O Positive'),
('O-','O Negative') ON CONFLICT DO NOTHING;
