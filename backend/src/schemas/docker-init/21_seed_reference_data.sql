-- ============================================================
-- Seed data for lookup tables
-- ============================================================

INSERT INTO roles (role_code, name, description, is_system_role) VALUES
('citizen','Citizen','Registered public user', TRUE),
('dispatcher','Dispatcher','999 call intake, triage, incident coordination, and dispatch', TRUE),
('agency_representative','Agency Representative','Agency-side user', TRUE),
('system_admin','System Admin','Full system administrator', TRUE);

INSERT INTO permissions (permission_code, module_name, description) VALUES
('case.create','case','Create service cases'),
('case.respond','case','Respond to service cases'),
('case.assign','case','Assign service cases'),
('case.escalate','case','Escalate service case to emergency incident'),
('incident.create','incident','Create emergency incidents'),
('incident.update','incident','Update emergency incidents'),
('incident.dispatch_unit','dispatch','Dispatch emergency units'),
('agency.manage','agency','Manage agencies and units'),
('disaster.declare','disaster','Declare disaster/national emergency'),
('relief.distribute','relief','Manage relief distribution'),
('blood.manage','blood','Manage blood requests and matches'),
('notification.send','notification','Send/queue notifications');

INSERT INTO report_channels (channel_code, name, description) VALUES
('web_portal','Web Portal','Logged-in web portal report'),
('emergency_call','999 Emergency Call','Emergency phone call intake'),
('admin_entry','Admin Entry','Created by admin/operator'),
('agency_report','Agency Report','Reported by an agency'),
('mobile_app','Mobile App','Mobile app report');

INSERT INTO report_categories (category_code, name, description, default_urgency) VALUES
('medical','Medical','Medical emergency or health-related issue','unknown'),
('crime_public_safety','Crime/Public Safety','Crime, assault, missing person, public safety','emergency'),
('fire','Fire','Fire, explosion, gas leak','emergency'),
('natural_disaster','Natural Disaster','Flood, cyclone, earthquake, landslide','emergency'),
('infrastructure_emergency','Infrastructure Emergency','Bridge collapse, power failure, road hazard','unknown'),
('relief_request','Relief Request','Food, water, medicine or shelter need','non_emergency'),
('blood_request','Blood Request','Blood donation or urgent blood request','unknown');

INSERT INTO case_statuses (status_code, name, sort_order, is_terminal) VALUES
('submitted','Submitted',1,FALSE),
('under_review','Under Review',2,FALSE),
('awaiting_user_response','Awaiting User Response',3,FALSE),
('resolved','Resolved',4,TRUE),
('escalated_to_emergency','Escalated to Emergency',5,TRUE),
('closed','Closed',6,TRUE),
('cancelled','Cancelled',7,TRUE);

INSERT INTO incident_severity_levels (severity_code, name, priority_rank) VALUES
('low','Low',1),
('medium','Medium',2),
('high','High',3),
('critical','Critical',4);

INSERT INTO incident_statuses (status_code, name, sort_order, is_terminal) VALUES
('reported','Reported',1,FALSE),
('classified','Classified',2,FALSE),
('agency_assigned','Agency Assigned',3,FALSE),
('unit_assigned','Unit Assigned',4,FALSE),
('dispatched','Dispatched',5,FALSE),
('in_progress','In Progress',6,FALSE),
('resolved','Resolved',7,TRUE),
('closed','Closed',8,TRUE),
('cancelled','Cancelled',9,TRUE);

INSERT INTO incident_outcomes (outcome_code, name, is_successful_resolution) VALUES
('resolved','Resolved',TRUE),
('false_alarm','False Alarm',FALSE),
('duplicate_incident','Duplicate Incident',FALSE),
('cancelled','Cancelled',FALSE),
('transferred','Transferred',TRUE),
('unresolved','Unresolved',FALSE);

INSERT INTO agency_types (type_code, name) VALUES
('police','Police'),
('fire_service','Fire Service'),
('medical_service','Medical Service'),
('disaster_management','Disaster Management'),
('infrastructure_emergency','Infrastructure Emergency'),
('army','Army'),
('ngo','NGO'),
('utility_provider','Utility Provider'),
('local_government','Local Government');

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
('temporary_shelter','Temporary Shelter','shelter'),
('blood_support','Blood Support','blood'),
('emergency_care','Emergency Care','medical'),
('icu','ICU','medical'),
('cardiology','Cardiology','medical'),
('burn_unit','Burn Unit','medical'),
('blood_storage','Blood Storage','blood');

INSERT INTO emergency_unit_types (type_code, name) VALUES
('ambulance','Ambulance'),
('fire_truck','Fire Truck'),
('police_vehicle','Police Vehicle'),
('rescue_boat','Rescue Boat'),
('medical_van','Medical Van'),
('utility_repair_vehicle','Utility Repair Vehicle'),
('relief_truck','Relief Truck'),
('command_vehicle','Command Vehicle'),
('helicopter','Helicopter');

INSERT INTO work_queues (queue_code, name, queue_type) VALUES
('non_emergency_case_queue','Non-Emergency Case Queue','service_case'),
('emergency_call_triage_queue','Emergency Call Triage Queue','emergency_call'),
('incident_dispatch_queue','Incident Dispatch Queue','dispatch'),
('disaster_relief_queue','Disaster Relief Queue','disaster_relief');

INSERT INTO disaster_event_types (type_code, name) VALUES
('flood','Flood'),
('cyclone','Cyclone'),
('earthquake','Earthquake'),
('landslide','Landslide'),
('epidemic','Epidemic'),
('industrial_disaster','Industrial Disaster');

INSERT INTO facility_types (type_code, name) VALUES
('hospital','Hospital'),
('clinic','Clinic'),
('shelter','Shelter'),
('blood_bank','Blood Bank'),
('relief_center','Relief Center'),
('warehouse','Warehouse'),
('school_shelter_capable','School / Shelter Capable'),
('community_center','Community Center');

INSERT INTO relief_items (item_code, name, unit_of_measure) VALUES
('rice','Rice','kg'),
('water_bottle','Water Bottle','bottle'),
('dry_food_packet','Dry Food Packet','packet'),
('blanket','Blanket','piece'),
('saline','Saline','packet'),
('medicine_box','Medicine Box','box'),
('baby_food','Baby Food','packet'),
('sanitary_pad','Sanitary Pad','packet');

INSERT INTO blood_groups (group_code, name) VALUES
('A+','A Positive'),
('A-','A Negative'),
('B+','B Positive'),
('B-','B Negative'),
('AB+','AB Positive'),
('AB-','AB Negative'),
('O+','O Positive'),
('O-','O Negative');

INSERT INTO notification_templates (template_code, channel, subject_template, body_template) VALUES
('case_resolved_email','email','Your NIERS case has been resolved','Your case {{case_code}} has been addressed. Please check your dashboard for details.'),
('case_reply_in_app','in_app',NULL,'An admin has replied to your case {{case_code}}.'),
('case_escalated_email','email','Your NIERS case has been escalated','Your case {{case_code}} has been escalated to emergency response.'),
('incident_update_in_app','in_app',NULL,'Emergency incident {{incident_code}} has been updated.');
