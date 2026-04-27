-- NIERS Full Project Schema Init Script
-- MySQL 8.0+
-- Fixed: moved service_cases self-parent rule from CHECK to triggers because MySQL disallows CHECK constraints referencing AUTO_INCREMENT columns.
-- Generated for a database-first NIERS design with intake reports, 999 calls,
-- service cases, emergency incidents, dispatch, disaster/national emergency,
-- facilities, relief, blood support, notifications, workload queues, and audit.

SET NAMES utf8mb4;
SET time_zone = '+00:00';
SET FOREIGN_KEY_CHECKS = 0;

-- Drop views first
DROP VIEW IF EXISTS vw_disaster_dashboard;
DROP VIEW IF EXISTS vw_facility_capacity_status;
DROP VIEW IF EXISTS vw_agency_workload;
DROP VIEW IF EXISTS vw_response_pipeline_timing;
DROP VIEW IF EXISTS vw_escalation_comparison;
DROP VIEW IF EXISTS vw_emergency_call_heatmap;
DROP VIEW IF EXISTS vw_false_alarm_by_area;
DROP VIEW IF EXISTS vw_call_taker_performance;
DROP VIEW IF EXISTS vw_duplicate_emergency_call_clusters;
DROP VIEW IF EXISTS vw_admin_case_queue;
DROP VIEW IF EXISTS vw_user_case_dashboard;

-- Drop triggers
DROP TRIGGER IF EXISTS trg_intake_report_status_history_after_insert;
DROP TRIGGER IF EXISTS trg_case_status_history_after_insert;
DROP TRIGGER IF EXISTS trg_service_cases_before_insert;
DROP TRIGGER IF EXISTS trg_service_cases_before_update;
DROP TRIGGER IF EXISTS trg_incident_status_history_after_insert;
DROP TRIGGER IF EXISTS trg_unit_status_history_after_insert;
DROP TRIGGER IF EXISTS trg_dispatches_before_insert;
DROP TRIGGER IF EXISTS trg_dispatches_before_update;
DROP TRIGGER IF EXISTS trg_dispatch_status_history_after_insert;
DROP TRIGGER IF EXISTS trg_incident_location_history_after_insert;

-- Drop tables in reverse dependency order
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS email_delivery_attempts;
DROP TABLE IF EXISTS email_outbox;
DROP TABLE IF EXISTS notification_recipients;
DROP TABLE IF EXISTS notifications;
DROP TABLE IF EXISTS notification_templates;
DROP TABLE IF EXISTS blood_request_matches;
DROP TABLE IF EXISTS blood_requests;
DROP TABLE IF EXISTS donor_availability;
DROP TABLE IF EXISTS blood_donors;
DROP TABLE IF EXISTS blood_groups;
DROP TABLE IF EXISTS relief_donation_items;
DROP TABLE IF EXISTS relief_donations;
DROP TABLE IF EXISTS relief_collection_points;
DROP TABLE IF EXISTS relief_collection_campaigns;
DROP TABLE IF EXISTS relief_distribution_items;
DROP TABLE IF EXISTS relief_distributions;
DROP TABLE IF EXISTS relief_request_items;
DROP TABLE IF EXISTS relief_requests;
DROP TABLE IF EXISTS facility_relief_inventory;
DROP TABLE IF EXISTS relief_items;
DROP TABLE IF EXISTS case_escalations;
DROP TABLE IF EXISTS case_resolutions;
DROP TABLE IF EXISTS incident_facility_referrals;
DROP TABLE IF EXISTS facility_capacity_snapshots;
DROP TABLE IF EXISTS facility_capabilities;
DROP TABLE IF EXISTS facility_contacts;
DROP TABLE IF EXISTS facilities;
DROP TABLE IF EXISTS facility_types;
DROP TABLE IF EXISTS shelter_occupancy_snapshots;
DROP TABLE IF EXISTS shelter_activations;
DROP TABLE IF EXISTS rescue_operation_units;
DROP TABLE IF EXISTS rescue_operation_areas;
DROP TABLE IF EXISTS rescue_operations;
DROP TABLE IF EXISTS declaration_agencies;
DROP TABLE IF EXISTS declaration_affected_areas;
DROP TABLE IF EXISTS emergency_declarations;
DROP TABLE IF EXISTS disaster_agency_participation;
DROP TABLE IF EXISTS disaster_affected_areas;
DROP TABLE IF EXISTS disaster_event_status_history;
DROP TABLE IF EXISTS disaster_events;
DROP TABLE IF EXISTS disaster_event_types;
DROP TABLE IF EXISTS queue_assignments;
DROP TABLE IF EXISTS queue_items;
DROP TABLE IF EXISTS work_queues;
DROP TABLE IF EXISTS operator_availability;
DROP TABLE IF EXISTS operator_shifts;
DROP TABLE IF EXISTS response_logs;
DROP TABLE IF EXISTS dispatch_status_history;
DROP TABLE IF EXISTS dispatches;
DROP TABLE IF EXISTS unit_status_history;
DROP TABLE IF EXISTS unit_capabilities;
DROP TABLE IF EXISTS emergency_units;
DROP TABLE IF EXISTS emergency_unit_types;
DROP TABLE IF EXISTS agency_service_areas;
DROP TABLE IF EXISTS agency_capabilities;
DROP TABLE IF EXISTS capabilities;
DROP TABLE IF EXISTS agency_memberships;
DROP TABLE IF EXISTS agency_contacts;
DROP TABLE IF EXISTS incident_timeline_events;
DROP TABLE IF EXISTS incident_location_history;
DROP TABLE IF EXISTS incident_agency_participation;
DROP TABLE IF EXISTS incident_report_links;
DROP TABLE IF EXISTS incident_status_history;
DROP TABLE IF EXISTS emergency_incidents;
DROP TABLE IF EXISTS incident_outcomes;
DROP TABLE IF EXISTS incident_statuses;
DROP TABLE IF EXISTS incident_severity_levels;
DROP TABLE IF EXISTS agencies;
DROP TABLE IF EXISTS agency_types;
DROP TABLE IF EXISTS case_feedback;
DROP TABLE IF EXISTS case_attachments;
DROP TABLE IF EXISTS case_messages;
DROP TABLE IF EXISTS case_assignments;
DROP TABLE IF EXISTS case_status_history;
DROP TABLE IF EXISTS service_cases;
DROP TABLE IF EXISTS case_statuses;
DROP TABLE IF EXISTS emergency_call_triage_answers;
DROP TABLE IF EXISTS emergency_call_notes;
DROP TABLE IF EXISTS emergency_calls;
DROP TABLE IF EXISTS intake_report_attachments;
DROP TABLE IF EXISTS intake_report_status_history;
DROP TABLE IF EXISTS intake_reports;
DROP TABLE IF EXISTS report_categories;
DROP TABLE IF EXISTS report_channels;
DROP TABLE IF EXISTS reporter_contacts;
DROP TABLE IF EXISTS service_zone_areas;
DROP TABLE IF EXISTS service_zones;
DROP TABLE IF EXISTS auth_tokens;
DROP TABLE IF EXISTS user_profiles;
DROP TABLE IF EXISTS locations;
DROP TABLE IF EXISTS administrative_areas;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS users;

SET FOREIGN_KEY_CHECKS = 1;

-- ============================================================
-- 1. Identity, Auth, RBAC
-- ============================================================

CREATE TABLE users (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_uuid CHAR(36) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    account_status ENUM('active','suspended','disabled','pending_verification') NOT NULL DEFAULT 'pending_verification',
    email_verified_at TIMESTAMP NULL,
    last_login_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_users_public_uuid (public_uuid),
    UNIQUE KEY uq_users_email (email),
    CONSTRAINT chk_users_email_not_blank CHECK (CHAR_LENGTH(TRIM(email)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE roles (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    role_code VARCHAR(100) NOT NULL,
    name VARCHAR(150) NOT NULL,
    description VARCHAR(500) NULL,
    is_system_role BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_roles_role_code (role_code),
    UNIQUE KEY uq_roles_name (name),
    CONSTRAINT chk_roles_role_code_not_blank CHECK (CHAR_LENGTH(TRIM(role_code)) > 0),
    CONSTRAINT chk_roles_name_not_blank CHECK (CHAR_LENGTH(TRIM(name)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE permissions (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    permission_code VARCHAR(150) NOT NULL,
    module_name VARCHAR(100) NOT NULL,
    description VARCHAR(500) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_permissions_permission_code (permission_code),
    KEY idx_permissions_module_name (module_name),
    CONSTRAINT chk_permissions_code_not_blank CHECK (CHAR_LENGTH(TRIM(permission_code)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE role_permissions (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    role_id BIGINT UNSIGNED NOT NULL,
    permission_id BIGINT UNSIGNED NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_role_permissions_role_permission (role_id, permission_id),
    KEY idx_role_permissions_permission_id (permission_id),
    CONSTRAINT fk_role_permissions_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_role_permissions_permission FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE user_roles (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    role_id BIGINT UNSIGNED NOT NULL,
    assigned_by_user_id BIGINT UNSIGNED NULL,
    assigned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_user_roles_user_role (user_id, role_id),
    KEY idx_user_roles_role_id (role_id),
    KEY idx_user_roles_assigned_by (assigned_by_user_id),
    CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_user_roles_assigned_by FOREIGN KEY (assigned_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Geography tables are created before user_profiles because profiles can reference locations.

-- ============================================================
-- 2. Geography and Locations
-- ============================================================

CREATE TABLE administrative_areas (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    parent_area_id BIGINT UNSIGNED NULL,
    area_type ENUM('division','district','upazila','union','ward','area') NOT NULL,
    name VARCHAR(150) NOT NULL,
    code VARCHAR(80) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_administrative_areas_code (code),
    UNIQUE KEY uq_administrative_areas_parent_type_name (parent_area_id, area_type, name),
    KEY idx_administrative_areas_parent (parent_area_id),
    KEY idx_administrative_areas_type (area_type),
    CONSTRAINT fk_administrative_areas_parent FOREIGN KEY (parent_area_id) REFERENCES administrative_areas(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_administrative_areas_name_not_blank CHECK (CHAR_LENGTH(TRIM(name)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE locations (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    admin_area_id BIGINT UNSIGNED NULL,
    latitude DECIMAL(9,6) NOT NULL,
    longitude DECIMAL(9,6) NOT NULL,
    address_text VARCHAR(255) NOT NULL,
    place_name VARCHAR(150) NULL,
    source ENUM('user_shared','dispatcher_selected','api_geocoded','manual_entry') NOT NULL,
    created_by_user_id BIGINT UNSIGNED NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_locations_admin_area (admin_area_id),
    KEY idx_locations_created_by (created_by_user_id),
    KEY idx_locations_lat_lng (latitude, longitude),
    CONSTRAINT fk_locations_admin_area FOREIGN KEY (admin_area_id) REFERENCES administrative_areas(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_locations_created_by_user FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_locations_latitude CHECK (latitude BETWEEN -90.000000 AND 90.000000),
    CONSTRAINT chk_locations_longitude CHECK (longitude BETWEEN -180.000000 AND 180.000000),
    CONSTRAINT chk_locations_address_not_blank CHECK (CHAR_LENGTH(TRIM(address_text)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE user_profiles (
    user_id BIGINT UNSIGNED NOT NULL,
    full_name VARCHAR(150) NOT NULL,
    phone_number VARCHAR(30) NULL,
    preferred_language ENUM('bn','en') NOT NULL DEFAULT 'bn',
    address_location_id BIGINT UNSIGNED NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id),
    KEY idx_user_profiles_address_location (address_location_id),
    CONSTRAINT fk_user_profiles_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_user_profiles_address_location FOREIGN KEY (address_location_id) REFERENCES locations(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_user_profiles_full_name_not_blank CHECK (CHAR_LENGTH(TRIM(full_name)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE auth_tokens (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    token_hash CHAR(64) NOT NULL,
    token_type ENUM('refresh','password_reset','email_verification') NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP NULL,
    revoked_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_auth_tokens_token_hash (token_hash),
    KEY idx_auth_tokens_user_type (user_id, token_type),
    CONSTRAINT fk_auth_tokens_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_auth_tokens_expires_after_created CHECK (expires_at > created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE service_zones (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    zone_code VARCHAR(100) NOT NULL,
    name VARCHAR(150) NOT NULL,
    description VARCHAR(500) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_service_zones_zone_code (zone_code),
    CONSTRAINT chk_service_zones_name_not_blank CHECK (CHAR_LENGTH(TRIM(name)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE service_zone_areas (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    service_zone_id BIGINT UNSIGNED NOT NULL,
    admin_area_id BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_service_zone_areas_zone_area (service_zone_id, admin_area_id),
    KEY idx_service_zone_areas_admin_area (admin_area_id),
    CONSTRAINT fk_service_zone_areas_zone FOREIGN KEY (service_zone_id) REFERENCES service_zones(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_service_zone_areas_admin_area FOREIGN KEY (admin_area_id) REFERENCES administrative_areas(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ============================================================
-- 3. Reporter, Intake, and 999 Calls
-- ============================================================

CREATE TABLE reporter_contacts (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    linked_user_id BIGINT UNSIGNED NULL,
    full_name VARCHAR(150) NULL,
    phone_number VARCHAR(30) NULL,
    email VARCHAR(255) NULL,
    is_anonymous BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_reporter_contacts_linked_user (linked_user_id),
    KEY idx_reporter_contacts_phone (phone_number),
    CONSTRAINT fk_reporter_contacts_linked_user FOREIGN KEY (linked_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE report_channels (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    channel_code VARCHAR(80) NOT NULL,
    name VARCHAR(120) NOT NULL,
    description VARCHAR(500) NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (id),
    UNIQUE KEY uq_report_channels_channel_code (channel_code),
    CONSTRAINT chk_report_channels_name_not_blank CHECK (CHAR_LENGTH(TRIM(name)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE report_categories (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    parent_category_id BIGINT UNSIGNED NULL,
    category_code VARCHAR(100) NOT NULL,
    name VARCHAR(150) NOT NULL,
    description VARCHAR(500) NULL,
    default_urgency ENUM('non_emergency','emergency','unknown') NOT NULL DEFAULT 'unknown',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (id),
    UNIQUE KEY uq_report_categories_category_code (category_code),
    KEY idx_report_categories_parent (parent_category_id),
    CONSTRAINT fk_report_categories_parent FOREIGN KEY (parent_category_id) REFERENCES report_categories(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_report_categories_name_not_blank CHECK (CHAR_LENGTH(TRIM(name)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE intake_reports (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_uuid CHAR(36) NOT NULL,
    report_code VARCHAR(60) NOT NULL,
    reporter_user_id BIGINT UNSIGNED NULL,
    reporter_contact_id BIGINT UNSIGNED NULL,
    channel_id BIGINT UNSIGNED NOT NULL,
    category_id BIGINT UNSIGNED NOT NULL,
    reported_location_id BIGINT UNSIGNED NULL,
    urgency_type ENUM('non_emergency','emergency','unknown') NOT NULL DEFAULT 'unknown',
    summary VARCHAR(255) NOT NULL,
    description TEXT NULL,
    intake_status ENUM('received','under_review','linked_to_case','linked_to_incident','duplicate','false_report','closed') NOT NULL DEFAULT 'received',
    final_disposition ENUM('valid','duplicate','false_report','prank','insufficient_info','closed_without_action') NULL,
    received_by_user_id BIGINT UNSIGNED NULL,
    reported_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_intake_reports_public_uuid (public_uuid),
    UNIQUE KEY uq_intake_reports_report_code (report_code),
    KEY idx_intake_reports_reporter_user (reporter_user_id),
    KEY idx_intake_reports_reporter_contact (reporter_contact_id),
    KEY idx_intake_reports_channel (channel_id),
    KEY idx_intake_reports_category (category_id),
    KEY idx_intake_reports_location (reported_location_id),
    KEY idx_intake_reports_status (intake_status),
    KEY idx_intake_reports_reported_at (reported_at),
    CONSTRAINT fk_intake_reports_reporter_user FOREIGN KEY (reporter_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_intake_reports_reporter_contact FOREIGN KEY (reporter_contact_id) REFERENCES reporter_contacts(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_intake_reports_channel FOREIGN KEY (channel_id) REFERENCES report_channels(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_intake_reports_category FOREIGN KEY (category_id) REFERENCES report_categories(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_intake_reports_location FOREIGN KEY (reported_location_id) REFERENCES locations(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_intake_reports_received_by FOREIGN KEY (received_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_intake_reports_summary_not_blank CHECK (CHAR_LENGTH(TRIM(summary)) > 0),
    CONSTRAINT chk_intake_reports_reported_before_created CHECK (reported_at <= created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE intake_report_status_history (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    intake_report_id BIGINT UNSIGNED NOT NULL,
    status ENUM('received','under_review','linked_to_case','linked_to_incident','duplicate','false_report','closed') NOT NULL,
    changed_by_user_id BIGINT UNSIGNED NULL,
    changed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    note VARCHAR(500) NULL,
    PRIMARY KEY (id),
    KEY idx_irsh_report_changed (intake_report_id, changed_at),
    KEY idx_irsh_changed_by (changed_by_user_id),
    CONSTRAINT fk_irsh_report FOREIGN KEY (intake_report_id) REFERENCES intake_reports(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_irsh_changed_by FOREIGN KEY (changed_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE intake_report_attachments (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    intake_report_id BIGINT UNSIGNED NOT NULL,
    uploaded_by_user_id BIGINT UNSIGNED NULL,
    file_name VARCHAR(255) NOT NULL,
    storage_key VARCHAR(500) NOT NULL,
    mime_type VARCHAR(120) NULL,
    size_bytes BIGINT UNSIGNED NOT NULL DEFAULT 0,
    uploaded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_intake_report_attachments_report (intake_report_id),
    KEY idx_intake_report_attachments_user (uploaded_by_user_id),
    CONSTRAINT fk_ira_report FOREIGN KEY (intake_report_id) REFERENCES intake_reports(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_ira_uploaded_by FOREIGN KEY (uploaded_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_ira_storage_key_not_blank CHECK (CHAR_LENGTH(TRIM(storage_key)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE emergency_calls (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    intake_report_id BIGINT UNSIGNED NOT NULL,
    call_taker_user_id BIGINT UNSIGNED NOT NULL,
    caller_phone_number VARCHAR(30) NULL,
    call_started_at TIMESTAMP NOT NULL,
    call_ended_at TIMESTAMP NULL,
    triaged_at TIMESTAMP NULL,
    call_status ENUM('received','triaged','linked_to_incident','transferred','closed','dropped','false_alarm') NOT NULL DEFAULT 'received',
    recording_url VARCHAR(500) NULL,
    transcript_text TEXT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_emergency_calls_intake_report (intake_report_id),
    KEY idx_emergency_calls_taker (call_taker_user_id),
    KEY idx_emergency_calls_started (call_started_at),
    KEY idx_emergency_calls_status (call_status),
    CONSTRAINT fk_emergency_calls_intake_report FOREIGN KEY (intake_report_id) REFERENCES intake_reports(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_emergency_calls_taker FOREIGN KEY (call_taker_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_emergency_calls_end_after_start CHECK (call_ended_at IS NULL OR call_ended_at >= call_started_at),
    CONSTRAINT chk_emergency_calls_triaged_after_start CHECK (triaged_at IS NULL OR triaged_at >= call_started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE emergency_call_notes (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    emergency_call_id BIGINT UNSIGNED NOT NULL,
    created_by_user_id BIGINT UNSIGNED NOT NULL,
    note_text TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_call_notes_call (emergency_call_id),
    KEY idx_call_notes_user (created_by_user_id),
    CONSTRAINT fk_call_notes_call FOREIGN KEY (emergency_call_id) REFERENCES emergency_calls(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_call_notes_user FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_call_notes_text_not_blank CHECK (CHAR_LENGTH(TRIM(note_text)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE emergency_call_triage_answers (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    emergency_call_id BIGINT UNSIGNED NOT NULL,
    question_text VARCHAR(500) NOT NULL,
    answer_text TEXT NULL,
    answered_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_triage_answers_call (emergency_call_id),
    CONSTRAINT fk_triage_answers_call FOREIGN KEY (emergency_call_id) REFERENCES emergency_calls(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_triage_question_not_blank CHECK (CHAR_LENGTH(TRIM(question_text)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ============================================================
-- 4. Non-Emergency Service Cases
-- ============================================================

CREATE TABLE case_statuses (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    status_code VARCHAR(100) NOT NULL,
    name VARCHAR(150) NOT NULL,
    description VARCHAR(500) NULL,
    sort_order INT NOT NULL DEFAULT 0,
    is_terminal BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (id),
    UNIQUE KEY uq_case_statuses_status_code (status_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE service_cases (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_uuid CHAR(36) NOT NULL,
    case_code VARCHAR(60) NOT NULL,
    intake_report_id BIGINT UNSIGNED NOT NULL,
    reporter_user_id BIGINT UNSIGNED NOT NULL,
    parent_case_id BIGINT UNSIGNED NULL,
    category_id BIGINT UNSIGNED NOT NULL,
    current_status_id BIGINT UNSIGNED NOT NULL,
    current_location_id BIGINT UNSIGNED NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NULL,
    priority_level ENUM('low','medium','high','urgent') NOT NULL DEFAULT 'medium',
    source_channel_id BIGINT UNSIGNED NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_service_cases_public_uuid (public_uuid),
    UNIQUE KEY uq_service_cases_case_code (case_code),
    UNIQUE KEY uq_service_cases_intake_report (intake_report_id),
    KEY idx_service_cases_reporter (reporter_user_id),
    KEY idx_service_cases_parent (parent_case_id),
    KEY idx_service_cases_category (category_id),
    KEY idx_service_cases_status (current_status_id),
    KEY idx_service_cases_location (current_location_id),
    KEY idx_service_cases_priority (priority_level),
    CONSTRAINT fk_service_cases_intake_report FOREIGN KEY (intake_report_id) REFERENCES intake_reports(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_service_cases_reporter FOREIGN KEY (reporter_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_service_cases_parent FOREIGN KEY (parent_case_id) REFERENCES service_cases(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_service_cases_category FOREIGN KEY (category_id) REFERENCES report_categories(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_service_cases_status FOREIGN KEY (current_status_id) REFERENCES case_statuses(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_service_cases_location FOREIGN KEY (current_location_id) REFERENCES locations(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_service_cases_channel FOREIGN KEY (source_channel_id) REFERENCES report_channels(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_service_cases_title_not_blank CHECK (CHAR_LENGTH(TRIM(title)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE case_status_history (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    case_id BIGINT UNSIGNED NOT NULL,
    status_id BIGINT UNSIGNED NOT NULL,
    changed_by_user_id BIGINT UNSIGNED NULL,
    changed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    note VARCHAR(500) NULL,
    PRIMARY KEY (id),
    KEY idx_case_status_history_case_changed (case_id, changed_at),
    KEY idx_case_status_history_status (status_id),
    KEY idx_case_status_history_user (changed_by_user_id),
    CONSTRAINT fk_case_status_history_case FOREIGN KEY (case_id) REFERENCES service_cases(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_case_status_history_status FOREIGN KEY (status_id) REFERENCES case_statuses(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_case_status_history_user FOREIGN KEY (changed_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE case_assignments (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    case_id BIGINT UNSIGNED NOT NULL,
    assigned_admin_id BIGINT UNSIGNED NOT NULL,
    assigned_by_user_id BIGINT UNSIGNED NULL,
    assignment_status ENUM('active','completed','reassigned','cancelled') NOT NULL DEFAULT 'active',
    assigned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ended_at TIMESTAMP NULL,
    note VARCHAR(500) NULL,
    active_case_id BIGINT UNSIGNED GENERATED ALWAYS AS (CASE WHEN assignment_status = 'active' AND ended_at IS NULL THEN case_id ELSE NULL END) STORED,
    PRIMARY KEY (id),
    UNIQUE KEY uq_case_assignments_one_active (active_case_id),
    KEY idx_case_assignments_case (case_id),
    KEY idx_case_assignments_admin (assigned_admin_id),
    KEY idx_case_assignments_assigned_by (assigned_by_user_id),
    CONSTRAINT fk_case_assignments_case FOREIGN KEY (case_id) REFERENCES service_cases(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_case_assignments_admin FOREIGN KEY (assigned_admin_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_case_assignments_assigned_by FOREIGN KEY (assigned_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_case_assignments_end_after_assigned CHECK (ended_at IS NULL OR ended_at >= assigned_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE case_messages (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    case_id BIGINT UNSIGNED NOT NULL,
    sender_user_id BIGINT UNSIGNED NULL,
    message_type ENUM('user_message','admin_reply','system_note') NOT NULL,
    message_body TEXT NOT NULL,
    is_internal BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_case_messages_case_created (case_id, created_at),
    KEY idx_case_messages_sender (sender_user_id),
    CONSTRAINT fk_case_messages_case FOREIGN KEY (case_id) REFERENCES service_cases(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_case_messages_sender FOREIGN KEY (sender_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_case_messages_body_not_blank CHECK (CHAR_LENGTH(TRIM(message_body)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE case_attachments (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    case_id BIGINT UNSIGNED NOT NULL,
    message_id BIGINT UNSIGNED NULL,
    uploaded_by_user_id BIGINT UNSIGNED NULL,
    file_name VARCHAR(255) NOT NULL,
    storage_key VARCHAR(500) NOT NULL,
    mime_type VARCHAR(120) NULL,
    size_bytes BIGINT UNSIGNED NOT NULL DEFAULT 0,
    uploaded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_case_attachments_case (case_id),
    KEY idx_case_attachments_message (message_id),
    KEY idx_case_attachments_user (uploaded_by_user_id),
    CONSTRAINT fk_case_attachments_case FOREIGN KEY (case_id) REFERENCES service_cases(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_case_attachments_message FOREIGN KEY (message_id) REFERENCES case_messages(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_case_attachments_user FOREIGN KEY (uploaded_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_case_attachments_storage_key_not_blank CHECK (CHAR_LENGTH(TRIM(storage_key)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE case_feedback (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    case_id BIGINT UNSIGNED NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    rating TINYINT UNSIGNED NOT NULL,
    comment VARCHAR(1000) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_case_feedback_case_user (case_id, user_id),
    KEY idx_case_feedback_user (user_id),
    CONSTRAINT fk_case_feedback_case FOREIGN KEY (case_id) REFERENCES service_cases(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_case_feedback_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_case_feedback_rating CHECK (rating BETWEEN 1 AND 5)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ============================================================
-- 5. Agencies and Units lookup foundations
-- ============================================================

CREATE TABLE agency_types (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    type_code VARCHAR(100) NOT NULL,
    name VARCHAR(150) NOT NULL,
    description VARCHAR(500) NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (id),
    UNIQUE KEY uq_agency_types_type_code (type_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE agencies (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_uuid CHAR(36) NOT NULL,
    agency_type_id BIGINT UNSIGNED NOT NULL,
    agency_code VARCHAR(80) NOT NULL,
    name VARCHAR(180) NOT NULL,
    description VARCHAR(1000) NULL,
    head_office_location_id BIGINT UNSIGNED NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_agencies_public_uuid (public_uuid),
    UNIQUE KEY uq_agencies_agency_code (agency_code),
    KEY idx_agencies_type (agency_type_id),
    KEY idx_agencies_head_office_location (head_office_location_id),
    CONSTRAINT fk_agencies_type FOREIGN KEY (agency_type_id) REFERENCES agency_types(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_agencies_head_office_location FOREIGN KEY (head_office_location_id) REFERENCES locations(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_agencies_name_not_blank CHECK (CHAR_LENGTH(TRIM(name)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE agency_contacts (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    agency_id BIGINT UNSIGNED NOT NULL,
    contact_type ENUM('phone','email','hotline','fax','website') NOT NULL,
    contact_value VARCHAR(255) NOT NULL,
    label VARCHAR(120) NULL,
    is_primary BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_agency_contacts_unique_value (agency_id, contact_type, contact_value),
    KEY idx_agency_contacts_agency (agency_id),
    CONSTRAINT fk_agency_contacts_agency FOREIGN KEY (agency_id) REFERENCES agencies(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_agency_contacts_value_not_blank CHECK (CHAR_LENGTH(TRIM(contact_value)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE agency_memberships (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    agency_id BIGINT UNSIGNED NOT NULL,
    membership_role ENUM('representative','coordinator','operator','viewer') NOT NULL,
    membership_status ENUM('active','inactive','suspended','left') NOT NULL DEFAULT 'active',
    joined_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    left_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_agency_memberships_user_agency (user_id, agency_id),
    KEY idx_agency_memberships_agency (agency_id),
    KEY idx_agency_memberships_role (membership_role),
    CONSTRAINT fk_agency_memberships_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_agency_memberships_agency FOREIGN KEY (agency_id) REFERENCES agencies(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_agency_memberships_left_after_joined CHECK (left_at IS NULL OR left_at >= joined_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE capabilities (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    capability_code VARCHAR(120) NOT NULL,
    name VARCHAR(150) NOT NULL,
    capability_group ENUM('medical','fire','rescue','relief','infrastructure','security','shelter','blood','other') NOT NULL DEFAULT 'other',
    description VARCHAR(500) NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (id),
    UNIQUE KEY uq_capabilities_code (capability_code),
    KEY idx_capabilities_group (capability_group)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE agency_capabilities (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    agency_id BIGINT UNSIGNED NOT NULL,
    capability_id BIGINT UNSIGNED NOT NULL,
    capacity_note VARCHAR(500) NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_agency_capabilities_agency_capability (agency_id, capability_id),
    KEY idx_agency_capabilities_capability (capability_id),
    CONSTRAINT fk_agency_capabilities_agency FOREIGN KEY (agency_id) REFERENCES agencies(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_agency_capabilities_capability FOREIGN KEY (capability_id) REFERENCES capabilities(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE agency_service_areas (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    agency_id BIGINT UNSIGNED NOT NULL,
    admin_area_id BIGINT UNSIGNED NOT NULL,
    coverage_type ENUM('primary','secondary','emergency_only') NOT NULL DEFAULT 'primary',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_agency_service_areas_agency_area (agency_id, admin_area_id),
    KEY idx_agency_service_areas_area (admin_area_id),
    CONSTRAINT fk_agency_service_areas_agency FOREIGN KEY (agency_id) REFERENCES agencies(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_agency_service_areas_area FOREIGN KEY (admin_area_id) REFERENCES administrative_areas(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE emergency_unit_types (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    type_code VARCHAR(100) NOT NULL,
    name VARCHAR(150) NOT NULL,
    description VARCHAR(500) NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (id),
    UNIQUE KEY uq_emergency_unit_types_code (type_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE emergency_units (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_uuid CHAR(36) NOT NULL,
    agency_id BIGINT UNSIGNED NOT NULL,
    unit_type_id BIGINT UNSIGNED NOT NULL,
    unit_code VARCHAR(80) NOT NULL,
    unit_name VARCHAR(150) NOT NULL,
    base_location_id BIGINT UNSIGNED NOT NULL,
    current_status ENUM('available','busy','maintenance','offline') NOT NULL DEFAULT 'available',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_emergency_units_public_uuid (public_uuid),
    UNIQUE KEY uq_emergency_units_agency_unit_code (agency_id, unit_code),
    KEY idx_emergency_units_agency_status (agency_id, current_status),
    KEY idx_emergency_units_type (unit_type_id),
    KEY idx_emergency_units_base_location (base_location_id),
    CONSTRAINT fk_emergency_units_agency FOREIGN KEY (agency_id) REFERENCES agencies(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_emergency_units_type FOREIGN KEY (unit_type_id) REFERENCES emergency_unit_types(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_emergency_units_base_location FOREIGN KEY (base_location_id) REFERENCES locations(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_emergency_units_code_not_blank CHECK (CHAR_LENGTH(TRIM(unit_code)) > 0),
    CONSTRAINT chk_emergency_units_name_not_blank CHECK (CHAR_LENGTH(TRIM(unit_name)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE unit_capabilities (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    unit_id BIGINT UNSIGNED NOT NULL,
    capability_id BIGINT UNSIGNED NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_unit_capabilities_unit_capability (unit_id, capability_id),
    KEY idx_unit_capabilities_capability (capability_id),
    CONSTRAINT fk_unit_capabilities_unit FOREIGN KEY (unit_id) REFERENCES emergency_units(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_unit_capabilities_capability FOREIGN KEY (capability_id) REFERENCES capabilities(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE unit_status_history (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    unit_id BIGINT UNSIGNED NOT NULL,
    status ENUM('available','busy','maintenance','offline') NOT NULL,
    changed_by_user_id BIGINT UNSIGNED NULL,
    changed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    note VARCHAR(500) NULL,
    PRIMARY KEY (id),
    KEY idx_unit_status_history_unit_changed (unit_id, changed_at),
    KEY idx_unit_status_history_user (changed_by_user_id),
    CONSTRAINT fk_unit_status_history_unit FOREIGN KEY (unit_id) REFERENCES emergency_units(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_unit_status_history_user FOREIGN KEY (changed_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ============================================================
-- 6. Emergency Incident Operations
-- ============================================================

CREATE TABLE incident_severity_levels (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    severity_code VARCHAR(80) NOT NULL,
    name VARCHAR(100) NOT NULL,
    description VARCHAR(500) NULL,
    priority_rank INT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (id),
    UNIQUE KEY uq_incident_severity_levels_code (severity_code),
    UNIQUE KEY uq_incident_severity_levels_rank (priority_rank)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE incident_statuses (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    status_code VARCHAR(100) NOT NULL,
    name VARCHAR(150) NOT NULL,
    description VARCHAR(500) NULL,
    sort_order INT NOT NULL DEFAULT 0,
    is_terminal BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (id),
    UNIQUE KEY uq_incident_statuses_code (status_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE incident_outcomes (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    outcome_code VARCHAR(100) NOT NULL,
    name VARCHAR(150) NOT NULL,
    description VARCHAR(500) NULL,
    is_successful_resolution BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (id),
    UNIQUE KEY uq_incident_outcomes_code (outcome_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE emergency_incidents (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_uuid CHAR(36) NOT NULL,
    incident_code VARCHAR(60) NOT NULL,
    category_id BIGINT UNSIGNED NOT NULL,
    severity_level_id BIGINT UNSIGNED NOT NULL,
    current_status_id BIGINT UNSIGNED NOT NULL,
    current_location_id BIGINT UNSIGNED NOT NULL,
    final_outcome_id BIGINT UNSIGNED NULL,
    origin_type ENUM('emergency_call','service_case_escalation','admin_created','agency_report','disaster_event') NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NULL,
    created_by_user_id BIGINT UNSIGNED NOT NULL,
    reported_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP NULL,
    closed_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_emergency_incidents_public_uuid (public_uuid),
    UNIQUE KEY uq_emergency_incidents_incident_code (incident_code),
    KEY idx_emergency_incidents_category (category_id),
    KEY idx_emergency_incidents_severity (severity_level_id),
    KEY idx_emergency_incidents_status (current_status_id),
    KEY idx_emergency_incidents_location (current_location_id),
    KEY idx_emergency_incidents_outcome (final_outcome_id),
    KEY idx_emergency_incidents_origin (origin_type),
    KEY idx_emergency_incidents_reported_at (reported_at),
    CONSTRAINT fk_emergency_incidents_category FOREIGN KEY (category_id) REFERENCES report_categories(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_emergency_incidents_severity FOREIGN KEY (severity_level_id) REFERENCES incident_severity_levels(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_emergency_incidents_status FOREIGN KEY (current_status_id) REFERENCES incident_statuses(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_emergency_incidents_location FOREIGN KEY (current_location_id) REFERENCES locations(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_emergency_incidents_outcome FOREIGN KEY (final_outcome_id) REFERENCES incident_outcomes(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_emergency_incidents_created_by FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_emergency_incidents_title_not_blank CHECK (CHAR_LENGTH(TRIM(title)) > 0),
    CONSTRAINT chk_emergency_incidents_reported_before_created CHECK (reported_at <= created_at),
    CONSTRAINT chk_emergency_incidents_resolved_after_report CHECK (resolved_at IS NULL OR resolved_at >= reported_at),
    CONSTRAINT chk_emergency_incidents_closed_after_report CHECK (closed_at IS NULL OR closed_at >= reported_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE incident_status_history (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    incident_id BIGINT UNSIGNED NOT NULL,
    status_id BIGINT UNSIGNED NOT NULL,
    changed_by_user_id BIGINT UNSIGNED NULL,
    changed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    note VARCHAR(500) NULL,
    PRIMARY KEY (id),
    KEY idx_incident_status_history_incident_changed (incident_id, changed_at),
    KEY idx_incident_status_history_status (status_id),
    KEY idx_incident_status_history_user (changed_by_user_id),
    CONSTRAINT fk_incident_status_history_incident FOREIGN KEY (incident_id) REFERENCES emergency_incidents(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_incident_status_history_status FOREIGN KEY (status_id) REFERENCES incident_statuses(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_incident_status_history_user FOREIGN KEY (changed_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE incident_report_links (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    incident_id BIGINT UNSIGNED NOT NULL,
    intake_report_id BIGINT UNSIGNED NOT NULL,
    link_type ENUM('primary_report','duplicate_report','supporting_report','follow_up_report') NOT NULL,
    linked_by_user_id BIGINT UNSIGNED NULL,
    linked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    note VARCHAR(500) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_incident_report_links_incident_report (incident_id, intake_report_id),
    UNIQUE KEY uq_incident_report_links_one_incident_per_report (intake_report_id),
    KEY idx_incident_report_links_user (linked_by_user_id),
    CONSTRAINT fk_incident_report_links_incident FOREIGN KEY (incident_id) REFERENCES emergency_incidents(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_incident_report_links_report FOREIGN KEY (intake_report_id) REFERENCES intake_reports(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_incident_report_links_user FOREIGN KEY (linked_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE incident_agency_participation (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    incident_id BIGINT UNSIGNED NOT NULL,
    agency_id BIGINT UNSIGNED NOT NULL,
    is_lead_agency BOOLEAN NOT NULL DEFAULT FALSE,
    participation_status ENUM('requested','active','completed','withdrawn') NOT NULL DEFAULT 'active',
    joined_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    left_at TIMESTAMP NULL,
    assigned_by_user_id BIGINT UNSIGNED NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lead_incident_id BIGINT UNSIGNED GENERATED ALWAYS AS (CASE WHEN is_lead_agency THEN incident_id ELSE NULL END) STORED,
    PRIMARY KEY (id),
    UNIQUE KEY uq_iap_incident_agency (incident_id, agency_id),
    UNIQUE KEY uq_iap_one_lead_per_incident (lead_incident_id),
    KEY idx_iap_agency (agency_id),
    KEY idx_iap_assigned_by (assigned_by_user_id),
    KEY idx_iap_status (participation_status),
    CONSTRAINT fk_iap_incident FOREIGN KEY (incident_id) REFERENCES emergency_incidents(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_iap_agency FOREIGN KEY (agency_id) REFERENCES agencies(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_iap_assigned_by FOREIGN KEY (assigned_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_iap_left_after_joined CHECK (left_at IS NULL OR left_at >= joined_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE incident_location_history (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    incident_id BIGINT UNSIGNED NOT NULL,
    location_id BIGINT UNSIGNED NOT NULL,
    changed_by_user_id BIGINT UNSIGNED NULL,
    change_reason VARCHAR(500) NULL,
    is_current BOOLEAN NOT NULL DEFAULT FALSE,
    changed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    current_incident_id BIGINT UNSIGNED GENERATED ALWAYS AS (CASE WHEN is_current THEN incident_id ELSE NULL END) STORED,
    PRIMARY KEY (id),
    UNIQUE KEY uq_incident_location_history_one_current (current_incident_id),
    KEY idx_incident_location_history_incident_changed (incident_id, changed_at),
    KEY idx_incident_location_history_location (location_id),
    KEY idx_incident_location_history_user (changed_by_user_id),
    CONSTRAINT fk_incident_location_history_incident FOREIGN KEY (incident_id) REFERENCES emergency_incidents(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_incident_location_history_location FOREIGN KEY (location_id) REFERENCES locations(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_incident_location_history_user FOREIGN KEY (changed_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE incident_timeline_events (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    incident_id BIGINT UNSIGNED NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    event_title VARCHAR(255) NOT NULL,
    event_description TEXT NULL,
    created_by_user_id BIGINT UNSIGNED NULL,
    event_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_incident_timeline_incident_time (incident_id, event_time),
    KEY idx_incident_timeline_user (created_by_user_id),
    KEY idx_incident_timeline_event_type (event_type),
    CONSTRAINT fk_incident_timeline_incident FOREIGN KEY (incident_id) REFERENCES emergency_incidents(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_incident_timeline_user FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_incident_timeline_title_not_blank CHECK (CHAR_LENGTH(TRIM(event_title)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ============================================================
-- 7. Dispatch and Response
-- ============================================================

CREATE TABLE dispatches (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    incident_id BIGINT UNSIGNED NOT NULL,
    unit_id BIGINT UNSIGNED NOT NULL,
    assigned_by_user_id BIGINT UNSIGNED NOT NULL,
    dispatch_status ENUM('assigned','dispatched','arrived','completed','cancelled') NOT NULL DEFAULT 'assigned',
    priority_level ENUM('low','medium','high','critical') NOT NULL DEFAULT 'medium',
    assigned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    dispatched_at TIMESTAMP NULL,
    arrived_at TIMESTAMP NULL,
    completed_at TIMESTAMP NULL,
    cancelled_at TIMESTAMP NULL,
    cancellation_reason VARCHAR(500) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_dispatches_incident_unit (incident_id, unit_id),
    KEY idx_dispatches_unit (unit_id),
    KEY idx_dispatches_user (assigned_by_user_id),
    KEY idx_dispatches_status (dispatch_status),
    KEY idx_dispatches_incident_status (incident_id, dispatch_status),
    CONSTRAINT fk_dispatches_incident FOREIGN KEY (incident_id) REFERENCES emergency_incidents(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_dispatches_unit FOREIGN KEY (unit_id) REFERENCES emergency_units(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_dispatches_assigned_by FOREIGN KEY (assigned_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_dispatches_dispatched_after_assigned CHECK (dispatched_at IS NULL OR dispatched_at >= assigned_at),
    CONSTRAINT chk_dispatches_arrived_after_dispatched CHECK (arrived_at IS NULL OR (dispatched_at IS NOT NULL AND arrived_at >= dispatched_at)),
    CONSTRAINT chk_dispatches_completed_after_arrived CHECK (completed_at IS NULL OR (arrived_at IS NOT NULL AND completed_at >= arrived_at)),
    CONSTRAINT chk_dispatches_cancelled_after_assigned CHECK (cancelled_at IS NULL OR cancelled_at >= assigned_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE dispatch_status_history (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    dispatch_id BIGINT UNSIGNED NOT NULL,
    status ENUM('assigned','dispatched','arrived','completed','cancelled') NOT NULL,
    changed_by_user_id BIGINT UNSIGNED NULL,
    changed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    note VARCHAR(500) NULL,
    PRIMARY KEY (id),
    KEY idx_dispatch_status_history_dispatch_changed (dispatch_id, changed_at),
    KEY idx_dispatch_status_history_user (changed_by_user_id),
    CONSTRAINT fk_dispatch_status_history_dispatch FOREIGN KEY (dispatch_id) REFERENCES dispatches(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_dispatch_status_history_user FOREIGN KEY (changed_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE response_logs (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    incident_id BIGINT UNSIGNED NOT NULL,
    dispatch_id BIGINT UNSIGNED NULL,
    agency_id BIGINT UNSIGNED NOT NULL,
    created_by_user_id BIGINT UNSIGNED NULL,
    log_type ENUM('update','hazard','casualty','resource_need','completion_note') NOT NULL DEFAULT 'update',
    message TEXT NOT NULL,
    logged_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_response_logs_incident_logged (incident_id, logged_at),
    KEY idx_response_logs_dispatch (dispatch_id),
    KEY idx_response_logs_agency (agency_id),
    KEY idx_response_logs_user (created_by_user_id),
    CONSTRAINT fk_response_logs_incident FOREIGN KEY (incident_id) REFERENCES emergency_incidents(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_response_logs_dispatch FOREIGN KEY (dispatch_id) REFERENCES dispatches(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_response_logs_agency FOREIGN KEY (agency_id) REFERENCES agencies(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_response_logs_user FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_response_logs_message_not_blank CHECK (CHAR_LENGTH(TRIM(message)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ============================================================
-- 8. Operator Workload Balancing
-- ============================================================

CREATE TABLE operator_shifts (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    shift_role ENUM('call_taker','case_admin','dispatcher','disaster_coordinator') NOT NULL,
    starts_at TIMESTAMP NOT NULL,
    ends_at TIMESTAMP NOT NULL,
    shift_status ENUM('scheduled','active','completed','cancelled') NOT NULL DEFAULT 'scheduled',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_operator_shifts_user_time (user_id, starts_at, ends_at),
    KEY idx_operator_shifts_role_status (shift_role, shift_status),
    CONSTRAINT fk_operator_shifts_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_operator_shifts_end_after_start CHECK (ends_at > starts_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE operator_availability (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    availability_status ENUM('available','busy','offline','on_break') NOT NULL,
    status_reason VARCHAR(500) NULL,
    changed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_operator_availability_user_changed (user_id, changed_at),
    KEY idx_operator_availability_status (availability_status),
    CONSTRAINT fk_operator_availability_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE work_queues (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    queue_code VARCHAR(100) NOT NULL,
    name VARCHAR(150) NOT NULL,
    queue_type ENUM('service_case','emergency_call','dispatch','disaster_relief') NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_work_queues_queue_code (queue_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE queue_items (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    queue_id BIGINT UNSIGNED NOT NULL,
    entity_type ENUM('service_case','intake_report','emergency_call','emergency_incident','relief_request') NOT NULL,
    entity_id BIGINT UNSIGNED NOT NULL,
    priority_level ENUM('low','medium','high','critical') NOT NULL DEFAULT 'medium',
    queue_status ENUM('waiting','assigned','in_progress','completed','cancelled') NOT NULL DEFAULT 'waiting',
    available_from TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_queue_items_queue_status_priority (queue_id, queue_status, priority_level),
    KEY idx_queue_items_entity (entity_type, entity_id),
    CONSTRAINT fk_queue_items_queue FOREIGN KEY (queue_id) REFERENCES work_queues(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE queue_assignments (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    queue_item_id BIGINT UNSIGNED NOT NULL,
    assigned_to_user_id BIGINT UNSIGNED NOT NULL,
    assigned_by_user_id BIGINT UNSIGNED NULL,
    assignment_status ENUM('assigned','accepted','completed','reassigned','expired','cancelled') NOT NULL DEFAULT 'assigned',
    assigned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    accepted_at TIMESTAMP NULL,
    completed_at TIMESTAMP NULL,
    ended_at TIMESTAMP NULL,
    active_queue_item_id BIGINT UNSIGNED GENERATED ALWAYS AS (CASE WHEN ended_at IS NULL AND assignment_status IN ('assigned','accepted') THEN queue_item_id ELSE NULL END) STORED,
    PRIMARY KEY (id),
    UNIQUE KEY uq_queue_assignments_one_active (active_queue_item_id),
    KEY idx_queue_assignments_item (queue_item_id),
    KEY idx_queue_assignments_assigned_to (assigned_to_user_id),
    KEY idx_queue_assignments_assigned_by (assigned_by_user_id),
    CONSTRAINT fk_queue_assignments_item FOREIGN KEY (queue_item_id) REFERENCES queue_items(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_queue_assignments_assigned_to FOREIGN KEY (assigned_to_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_queue_assignments_assigned_by FOREIGN KEY (assigned_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_queue_assignments_accept_after_assigned CHECK (accepted_at IS NULL OR accepted_at >= assigned_at),
    CONSTRAINT chk_queue_assignments_complete_after_assigned CHECK (completed_at IS NULL OR completed_at >= assigned_at),
    CONSTRAINT chk_queue_assignments_end_after_assigned CHECK (ended_at IS NULL OR ended_at >= assigned_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ============================================================
-- 9. Disaster / National Emergency Management
-- ============================================================

CREATE TABLE disaster_event_types (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    type_code VARCHAR(100) NOT NULL,
    name VARCHAR(150) NOT NULL,
    description VARCHAR(500) NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (id),
    UNIQUE KEY uq_disaster_event_types_code (type_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE disaster_events (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_uuid CHAR(36) NOT NULL,
    event_code VARCHAR(60) NOT NULL,
    event_type_id BIGINT UNSIGNED NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NULL,
    current_status ENUM('monitoring','active','contained','resolved','closed') NOT NULL DEFAULT 'monitoring',
    severity_level ENUM('low','medium','high','critical','national') NOT NULL DEFAULT 'medium',
    started_at TIMESTAMP NOT NULL,
    ended_at TIMESTAMP NULL,
    created_by_user_id BIGINT UNSIGNED NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_disaster_events_public_uuid (public_uuid),
    UNIQUE KEY uq_disaster_events_event_code (event_code),
    KEY idx_disaster_events_type (event_type_id),
    KEY idx_disaster_events_status (current_status),
    KEY idx_disaster_events_started (started_at),
    CONSTRAINT fk_disaster_events_type FOREIGN KEY (event_type_id) REFERENCES disaster_event_types(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_disaster_events_created_by FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_disaster_events_title_not_blank CHECK (CHAR_LENGTH(TRIM(title)) > 0),
    CONSTRAINT chk_disaster_events_end_after_start CHECK (ended_at IS NULL OR ended_at >= started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE disaster_event_status_history (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    disaster_event_id BIGINT UNSIGNED NOT NULL,
    status ENUM('monitoring','active','contained','resolved','closed') NOT NULL,
    changed_by_user_id BIGINT UNSIGNED NULL,
    changed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    note VARCHAR(500) NULL,
    PRIMARY KEY (id),
    KEY idx_desh_event_changed (disaster_event_id, changed_at),
    KEY idx_desh_user (changed_by_user_id),
    CONSTRAINT fk_desh_event FOREIGN KEY (disaster_event_id) REFERENCES disaster_events(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_desh_user FOREIGN KEY (changed_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE disaster_affected_areas (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    disaster_event_id BIGINT UNSIGNED NOT NULL,
    admin_area_id BIGINT UNSIGNED NOT NULL,
    impact_level ENUM('low','medium','high','severe') NOT NULL DEFAULT 'medium',
    population_affected_estimate INT UNSIGNED NULL,
    reported_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_disaster_affected_areas_event_area (disaster_event_id, admin_area_id),
    KEY idx_disaster_affected_areas_area (admin_area_id),
    CONSTRAINT fk_disaster_affected_areas_event FOREIGN KEY (disaster_event_id) REFERENCES disaster_events(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_disaster_affected_areas_area FOREIGN KEY (admin_area_id) REFERENCES administrative_areas(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE disaster_agency_participation (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    disaster_event_id BIGINT UNSIGNED NOT NULL,
    agency_id BIGINT UNSIGNED NOT NULL,
    participation_role ENUM('lead','support','logistics','medical','rescue','security') NOT NULL DEFAULT 'support',
    participation_status ENUM('requested','active','completed','withdrawn') NOT NULL DEFAULT 'active',
    joined_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    left_at TIMESTAMP NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_disaster_agency_event_agency (disaster_event_id, agency_id),
    KEY idx_disaster_agency_agency (agency_id),
    CONSTRAINT fk_disaster_agency_event FOREIGN KEY (disaster_event_id) REFERENCES disaster_events(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_disaster_agency_agency FOREIGN KEY (agency_id) REFERENCES agencies(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_disaster_agency_left_after_joined CHECK (left_at IS NULL OR left_at >= joined_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE emergency_declarations (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    disaster_event_id BIGINT UNSIGNED NOT NULL,
    declaration_code VARCHAR(80) NOT NULL,
    declaration_level ENUM('local','district','divisional','national') NOT NULL,
    declared_by_user_id BIGINT UNSIGNED NOT NULL,
    declared_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ended_at TIMESTAMP NULL,
    legal_reference VARCHAR(255) NULL,
    reason VARCHAR(1000) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    active_disaster_event_id BIGINT UNSIGNED GENERATED ALWAYS AS (CASE WHEN ended_at IS NULL THEN disaster_event_id ELSE NULL END) STORED,
    PRIMARY KEY (id),
    UNIQUE KEY uq_emergency_declarations_code (declaration_code),
    UNIQUE KEY uq_emergency_declarations_one_active_per_disaster (active_disaster_event_id),
    KEY idx_emergency_declarations_disaster (disaster_event_id),
    KEY idx_emergency_declarations_declared_by (declared_by_user_id),
    CONSTRAINT fk_emergency_declarations_disaster FOREIGN KEY (disaster_event_id) REFERENCES disaster_events(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_emergency_declarations_user FOREIGN KEY (declared_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_emergency_declarations_end_after_declared CHECK (ended_at IS NULL OR ended_at >= declared_at),
    CONSTRAINT chk_emergency_declarations_reason_not_blank CHECK (CHAR_LENGTH(TRIM(reason)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE declaration_affected_areas (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    declaration_id BIGINT UNSIGNED NOT NULL,
    admin_area_id BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_declaration_areas_declaration_area (declaration_id, admin_area_id),
    KEY idx_declaration_areas_area (admin_area_id),
    CONSTRAINT fk_declaration_areas_declaration FOREIGN KEY (declaration_id) REFERENCES emergency_declarations(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_declaration_areas_area FOREIGN KEY (admin_area_id) REFERENCES administrative_areas(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE declaration_agencies (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    declaration_id BIGINT UNSIGNED NOT NULL,
    agency_id BIGINT UNSIGNED NOT NULL,
    assigned_role ENUM('lead','rescue','relief','medical','security','logistics') NOT NULL,
    assigned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_declaration_agencies_declaration_agency (declaration_id, agency_id),
    KEY idx_declaration_agencies_agency (agency_id),
    CONSTRAINT fk_declaration_agencies_declaration FOREIGN KEY (declaration_id) REFERENCES emergency_declarations(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_declaration_agencies_agency FOREIGN KEY (agency_id) REFERENCES agencies(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE rescue_operations (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    disaster_event_id BIGINT UNSIGNED NOT NULL,
    operation_code VARCHAR(80) NOT NULL,
    title VARCHAR(255) NOT NULL,
    operation_status ENUM('planned','active','paused','completed','cancelled') NOT NULL DEFAULT 'planned',
    lead_agency_id BIGINT UNSIGNED NULL,
    started_at TIMESTAMP NULL,
    ended_at TIMESTAMP NULL,
    created_by_user_id BIGINT UNSIGNED NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_rescue_operations_code (operation_code),
    KEY idx_rescue_operations_disaster (disaster_event_id),
    KEY idx_rescue_operations_lead_agency (lead_agency_id),
    CONSTRAINT fk_rescue_operations_disaster FOREIGN KEY (disaster_event_id) REFERENCES disaster_events(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_rescue_operations_lead_agency FOREIGN KEY (lead_agency_id) REFERENCES agencies(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_rescue_operations_created_by FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_rescue_operations_title_not_blank CHECK (CHAR_LENGTH(TRIM(title)) > 0),
    CONSTRAINT chk_rescue_operations_end_after_start CHECK (ended_at IS NULL OR started_at IS NULL OR ended_at >= started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE rescue_operation_areas (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    rescue_operation_id BIGINT UNSIGNED NOT NULL,
    admin_area_id BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_rescue_operation_areas_operation_area (rescue_operation_id, admin_area_id),
    KEY idx_rescue_operation_areas_area (admin_area_id),
    CONSTRAINT fk_rescue_operation_areas_operation FOREIGN KEY (rescue_operation_id) REFERENCES rescue_operations(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_rescue_operation_areas_area FOREIGN KEY (admin_area_id) REFERENCES administrative_areas(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE rescue_operation_units (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    rescue_operation_id BIGINT UNSIGNED NOT NULL,
    unit_id BIGINT UNSIGNED NOT NULL,
    assigned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    released_at TIMESTAMP NULL,
    assignment_status ENUM('assigned','active','released','cancelled') NOT NULL DEFAULT 'assigned',
    PRIMARY KEY (id),
    UNIQUE KEY uq_rescue_operation_units_operation_unit (rescue_operation_id, unit_id),
    KEY idx_rescue_operation_units_unit (unit_id),
    CONSTRAINT fk_rescue_operation_units_operation FOREIGN KEY (rescue_operation_id) REFERENCES rescue_operations(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_rescue_operation_units_unit FOREIGN KEY (unit_id) REFERENCES emergency_units(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_rescue_operation_units_release_after_assigned CHECK (released_at IS NULL OR released_at >= assigned_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ============================================================
-- 10. Facilities and Healthcare
-- ============================================================

CREATE TABLE facility_types (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    type_code VARCHAR(100) NOT NULL,
    name VARCHAR(150) NOT NULL,
    description VARCHAR(500) NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (id),
    UNIQUE KEY uq_facility_types_code (type_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE facilities (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_uuid CHAR(36) NOT NULL,
    facility_type_id BIGINT UNSIGNED NOT NULL,
    facility_code VARCHAR(80) NOT NULL,
    name VARCHAR(180) NOT NULL,
    location_id BIGINT UNSIGNED NOT NULL,
    owning_agency_id BIGINT UNSIGNED NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_facilities_public_uuid (public_uuid),
    UNIQUE KEY uq_facilities_facility_code (facility_code),
    KEY idx_facilities_type (facility_type_id),
    KEY idx_facilities_location (location_id),
    KEY idx_facilities_agency (owning_agency_id),
    CONSTRAINT fk_facilities_type FOREIGN KEY (facility_type_id) REFERENCES facility_types(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_facilities_location FOREIGN KEY (location_id) REFERENCES locations(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_facilities_agency FOREIGN KEY (owning_agency_id) REFERENCES agencies(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_facilities_name_not_blank CHECK (CHAR_LENGTH(TRIM(name)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE facility_contacts (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    facility_id BIGINT UNSIGNED NOT NULL,
    contact_type ENUM('phone','email','hotline','website') NOT NULL,
    contact_value VARCHAR(255) NOT NULL,
    label VARCHAR(120) NULL,
    is_primary BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_facility_contacts_unique_value (facility_id, contact_type, contact_value),
    CONSTRAINT fk_facility_contacts_facility FOREIGN KEY (facility_id) REFERENCES facilities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_facility_contacts_value_not_blank CHECK (CHAR_LENGTH(TRIM(contact_value)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE facility_capabilities (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    facility_id BIGINT UNSIGNED NOT NULL,
    capability_id BIGINT UNSIGNED NOT NULL,
    capacity_note VARCHAR(500) NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_facility_capabilities_facility_capability (facility_id, capability_id),
    KEY idx_facility_capabilities_capability (capability_id),
    CONSTRAINT fk_facility_capabilities_facility FOREIGN KEY (facility_id) REFERENCES facilities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_facility_capabilities_capability FOREIGN KEY (capability_id) REFERENCES capabilities(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE facility_capacity_snapshots (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    facility_id BIGINT UNSIGNED NOT NULL,
    capacity_type ENUM('beds','icu_beds','shelter_people','blood_units','storage_units') NOT NULL,
    total_capacity INT UNSIGNED NOT NULL,
    available_capacity INT UNSIGNED NOT NULL,
    occupied_capacity INT UNSIGNED NOT NULL,
    recorded_by_user_id BIGINT UNSIGNED NULL,
    recorded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    note VARCHAR(500) NULL,
    PRIMARY KEY (id),
    KEY idx_facility_capacity_facility_type_recorded (facility_id, capacity_type, recorded_at),
    KEY idx_facility_capacity_user (recorded_by_user_id),
    CONSTRAINT fk_facility_capacity_facility FOREIGN KEY (facility_id) REFERENCES facilities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_facility_capacity_user FOREIGN KEY (recorded_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_facility_capacity_available_le_total CHECK (available_capacity <= total_capacity),
    CONSTRAINT chk_facility_capacity_occupied_le_total CHECK (occupied_capacity <= total_capacity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE incident_facility_referrals (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    incident_id BIGINT UNSIGNED NOT NULL,
    facility_id BIGINT UNSIGNED NOT NULL,
    referred_by_user_id BIGINT UNSIGNED NOT NULL,
    referral_type ENUM('hospital_transfer','shelter_referral','blood_bank_referral','relief_center') NOT NULL,
    referral_status ENUM('recommended','accepted','rejected','completed','cancelled') NOT NULL DEFAULT 'recommended',
    reason VARCHAR(1000) NULL,
    referred_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_incident_facility_referrals_unique (incident_id, facility_id, referral_type),
    KEY idx_incident_facility_referrals_facility (facility_id),
    KEY idx_incident_facility_referrals_user (referred_by_user_id),
    CONSTRAINT fk_incident_facility_referrals_incident FOREIGN KEY (incident_id) REFERENCES emergency_incidents(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_incident_facility_referrals_facility FOREIGN KEY (facility_id) REFERENCES facilities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_incident_facility_referrals_user FOREIGN KEY (referred_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_incident_facility_referrals_completed_after_referred CHECK (completed_at IS NULL OR completed_at >= referred_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE shelter_activations (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    disaster_event_id BIGINT UNSIGNED NOT NULL,
    facility_id BIGINT UNSIGNED NOT NULL,
    activated_by_user_id BIGINT UNSIGNED NOT NULL,
    activation_status ENUM('planned','active','full','closed') NOT NULL DEFAULT 'planned',
    activated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    closed_at TIMESTAMP NULL,
    notes VARCHAR(1000) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_shelter_activations_disaster_facility (disaster_event_id, facility_id),
    KEY idx_shelter_activations_facility (facility_id),
    KEY idx_shelter_activations_user (activated_by_user_id),
    CONSTRAINT fk_shelter_activations_disaster FOREIGN KEY (disaster_event_id) REFERENCES disaster_events(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_shelter_activations_facility FOREIGN KEY (facility_id) REFERENCES facilities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_shelter_activations_user FOREIGN KEY (activated_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_shelter_activations_closed_after_activated CHECK (closed_at IS NULL OR closed_at >= activated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE shelter_occupancy_snapshots (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    shelter_activation_id BIGINT UNSIGNED NOT NULL,
    people_count INT UNSIGNED NOT NULL DEFAULT 0,
    families_count INT UNSIGNED NULL,
    capacity_limit INT UNSIGNED NOT NULL DEFAULT 0,
    overflow_flag BOOLEAN NOT NULL DEFAULT FALSE,
    recorded_by_user_id BIGINT UNSIGNED NULL,
    recorded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_shelter_occupancy_activation_recorded (shelter_activation_id, recorded_at),
    KEY idx_shelter_occupancy_user (recorded_by_user_id),
    CONSTRAINT fk_shelter_occupancy_activation FOREIGN KEY (shelter_activation_id) REFERENCES shelter_activations(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_shelter_occupancy_user FOREIGN KEY (recorded_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_shelter_occupancy_capacity CHECK (people_count <= capacity_limit OR overflow_flag = TRUE)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- case_resolutions and case_escalations depend on facilities/emergency_incidents.
CREATE TABLE case_resolutions (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    case_id BIGINT UNSIGNED NOT NULL,
    resolved_by_user_id BIGINT UNSIGNED NOT NULL,
    resolution_type ENUM('advice_given','referred_to_facility','escalated','no_action_needed','duplicate') NOT NULL,
    resolution_text TEXT NOT NULL,
    recommended_facility_id BIGINT UNSIGNED NULL,
    resolved_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_case_resolutions_case (case_id),
    KEY idx_case_resolutions_user (resolved_by_user_id),
    KEY idx_case_resolutions_facility (recommended_facility_id),
    CONSTRAINT fk_case_resolutions_case FOREIGN KEY (case_id) REFERENCES service_cases(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_case_resolutions_user FOREIGN KEY (resolved_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_case_resolutions_facility FOREIGN KEY (recommended_facility_id) REFERENCES facilities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_case_resolutions_text_not_blank CHECK (CHAR_LENGTH(TRIM(resolution_text)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE case_escalations (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    case_id BIGINT UNSIGNED NOT NULL,
    emergency_incident_id BIGINT UNSIGNED NOT NULL,
    escalated_by_user_id BIGINT UNSIGNED NOT NULL,
    escalation_reason VARCHAR(1000) NOT NULL,
    escalated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_case_escalations_case (case_id),
    UNIQUE KEY uq_case_escalations_case_incident (case_id, emergency_incident_id),
    KEY idx_case_escalations_incident (emergency_incident_id),
    KEY idx_case_escalations_user (escalated_by_user_id),
    CONSTRAINT fk_case_escalations_case FOREIGN KEY (case_id) REFERENCES service_cases(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_case_escalations_incident FOREIGN KEY (emergency_incident_id) REFERENCES emergency_incidents(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_case_escalations_user FOREIGN KEY (escalated_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_case_escalations_reason_not_blank CHECK (CHAR_LENGTH(TRIM(escalation_reason)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ============================================================
-- 11. Relief Collection and Distribution
-- ============================================================

CREATE TABLE relief_items (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    item_code VARCHAR(100) NOT NULL,
    name VARCHAR(150) NOT NULL,
    unit_of_measure VARCHAR(50) NOT NULL,
    description VARCHAR(500) NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (id),
    UNIQUE KEY uq_relief_items_code (item_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE facility_relief_inventory (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    facility_id BIGINT UNSIGNED NOT NULL,
    relief_item_id BIGINT UNSIGNED NOT NULL,
    quantity_available DECIMAL(12,2) NOT NULL DEFAULT 0,
    last_updated_by_user_id BIGINT UNSIGNED NULL,
    last_updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_facility_relief_inventory_facility_item (facility_id, relief_item_id),
    KEY idx_facility_relief_inventory_item (relief_item_id),
    KEY idx_facility_relief_inventory_user (last_updated_by_user_id),
    CONSTRAINT fk_fri_facility FOREIGN KEY (facility_id) REFERENCES facilities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_fri_item FOREIGN KEY (relief_item_id) REFERENCES relief_items(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_fri_user FOREIGN KEY (last_updated_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_fri_quantity_nonnegative CHECK (quantity_available >= 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE relief_requests (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    request_code VARCHAR(80) NOT NULL,
    disaster_event_id BIGINT UNSIGNED NULL,
    incident_id BIGINT UNSIGNED NULL,
    requested_by_user_id BIGINT UNSIGNED NOT NULL,
    requesting_agency_id BIGINT UNSIGNED NULL,
    target_location_id BIGINT UNSIGNED NOT NULL,
    priority_level ENUM('low','medium','high','critical') NOT NULL DEFAULT 'medium',
    request_status ENUM('submitted','approved','partially_fulfilled','fulfilled','cancelled') NOT NULL DEFAULT 'submitted',
    needed_by TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_relief_requests_code (request_code),
    KEY idx_relief_requests_disaster (disaster_event_id),
    KEY idx_relief_requests_incident (incident_id),
    KEY idx_relief_requests_location (target_location_id),
    KEY idx_relief_requests_status_priority (request_status, priority_level),
    CONSTRAINT fk_relief_requests_disaster FOREIGN KEY (disaster_event_id) REFERENCES disaster_events(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_requests_incident FOREIGN KEY (incident_id) REFERENCES emergency_incidents(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_requests_user FOREIGN KEY (requested_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_requests_agency FOREIGN KEY (requesting_agency_id) REFERENCES agencies(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_requests_location FOREIGN KEY (target_location_id) REFERENCES locations(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_relief_requests_has_context CHECK (disaster_event_id IS NOT NULL OR incident_id IS NOT NULL)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE relief_request_items (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    relief_request_id BIGINT UNSIGNED NOT NULL,
    relief_item_id BIGINT UNSIGNED NOT NULL,
    quantity_requested DECIMAL(12,2) NOT NULL,
    note VARCHAR(500) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_relief_request_items_request_item (relief_request_id, relief_item_id),
    KEY idx_relief_request_items_item (relief_item_id),
    CONSTRAINT fk_rri_request FOREIGN KEY (relief_request_id) REFERENCES relief_requests(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_rri_item FOREIGN KEY (relief_item_id) REFERENCES relief_items(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_rri_quantity_positive CHECK (quantity_requested > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE relief_distributions (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    distribution_code VARCHAR(80) NOT NULL,
    relief_request_id BIGINT UNSIGNED NULL,
    source_facility_id BIGINT UNSIGNED NOT NULL,
    target_location_id BIGINT UNSIGNED NOT NULL,
    distributed_by_agency_id BIGINT UNSIGNED NULL,
    distributed_by_user_id BIGINT UNSIGNED NULL,
    distribution_status ENUM('planned','in_transit','delivered','cancelled') NOT NULL DEFAULT 'planned',
    distributed_at TIMESTAMP NULL,
    delivered_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_relief_distributions_code (distribution_code),
    KEY idx_relief_distributions_request (relief_request_id),
    KEY idx_relief_distributions_source (source_facility_id),
    KEY idx_relief_distributions_target (target_location_id),
    CONSTRAINT fk_relief_distributions_request FOREIGN KEY (relief_request_id) REFERENCES relief_requests(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_distributions_source FOREIGN KEY (source_facility_id) REFERENCES facilities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_distributions_target FOREIGN KEY (target_location_id) REFERENCES locations(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_distributions_agency FOREIGN KEY (distributed_by_agency_id) REFERENCES agencies(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_distributions_user FOREIGN KEY (distributed_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_relief_distributions_delivered_after_distributed CHECK (delivered_at IS NULL OR distributed_at IS NULL OR delivered_at >= distributed_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE relief_distribution_items (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    relief_distribution_id BIGINT UNSIGNED NOT NULL,
    relief_item_id BIGINT UNSIGNED NOT NULL,
    quantity_distributed DECIMAL(12,2) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_relief_distribution_items_distribution_item (relief_distribution_id, relief_item_id),
    KEY idx_relief_distribution_items_item (relief_item_id),
    CONSTRAINT fk_rdi_distribution FOREIGN KEY (relief_distribution_id) REFERENCES relief_distributions(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_rdi_item FOREIGN KEY (relief_item_id) REFERENCES relief_items(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_rdi_quantity_positive CHECK (quantity_distributed > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE relief_collection_campaigns (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    campaign_code VARCHAR(80) NOT NULL,
    disaster_event_id BIGINT UNSIGNED NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NULL,
    campaign_status ENUM('planned','active','paused','completed','cancelled') NOT NULL DEFAULT 'planned',
    starts_at TIMESTAMP NOT NULL,
    ends_at TIMESTAMP NULL,
    created_by_user_id BIGINT UNSIGNED NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_relief_campaigns_code (campaign_code),
    KEY idx_relief_campaigns_disaster (disaster_event_id),
    KEY idx_relief_campaigns_user (created_by_user_id),
    CONSTRAINT fk_relief_campaigns_disaster FOREIGN KEY (disaster_event_id) REFERENCES disaster_events(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_campaigns_user FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_relief_campaigns_title_not_blank CHECK (CHAR_LENGTH(TRIM(title)) > 0),
    CONSTRAINT chk_relief_campaigns_end_after_start CHECK (ends_at IS NULL OR ends_at >= starts_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE relief_collection_points (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    campaign_id BIGINT UNSIGNED NOT NULL,
    facility_id BIGINT UNSIGNED NULL,
    location_id BIGINT UNSIGNED NOT NULL,
    name VARCHAR(180) NOT NULL,
    contact_phone VARCHAR(30) NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_relief_collection_points_campaign (campaign_id),
    KEY idx_relief_collection_points_facility (facility_id),
    KEY idx_relief_collection_points_location (location_id),
    CONSTRAINT fk_relief_collection_points_campaign FOREIGN KEY (campaign_id) REFERENCES relief_collection_campaigns(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_collection_points_facility FOREIGN KEY (facility_id) REFERENCES facilities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_collection_points_location FOREIGN KEY (location_id) REFERENCES locations(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_relief_collection_points_name_not_blank CHECK (CHAR_LENGTH(TRIM(name)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE relief_donations (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    donation_code VARCHAR(80) NOT NULL,
    campaign_id BIGINT UNSIGNED NULL,
    collection_point_id BIGINT UNSIGNED NULL,
    donor_user_id BIGINT UNSIGNED NULL,
    donor_contact_id BIGINT UNSIGNED NULL,
    received_by_user_id BIGINT UNSIGNED NULL,
    donation_status ENUM('pledged','received','verified','rejected') NOT NULL DEFAULT 'pledged',
    received_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_relief_donations_code (donation_code),
    KEY idx_relief_donations_campaign (campaign_id),
    KEY idx_relief_donations_point (collection_point_id),
    KEY idx_relief_donations_donor_user (donor_user_id),
    KEY idx_relief_donations_donor_contact (donor_contact_id),
    CONSTRAINT fk_relief_donations_campaign FOREIGN KEY (campaign_id) REFERENCES relief_collection_campaigns(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_donations_point FOREIGN KEY (collection_point_id) REFERENCES relief_collection_points(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_donations_donor_user FOREIGN KEY (donor_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_donations_donor_contact FOREIGN KEY (donor_contact_id) REFERENCES reporter_contacts(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_donations_received_by FOREIGN KEY (received_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE relief_donation_items (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    donation_id BIGINT UNSIGNED NOT NULL,
    relief_item_id BIGINT UNSIGNED NOT NULL,
    quantity_donated DECIMAL(12,2) NOT NULL,
    condition_note VARCHAR(500) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_relief_donation_items_donation_item (donation_id, relief_item_id),
    KEY idx_relief_donation_items_item (relief_item_id),
    CONSTRAINT fk_relief_donation_items_donation FOREIGN KEY (donation_id) REFERENCES relief_donations(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_donation_items_item FOREIGN KEY (relief_item_id) REFERENCES relief_items(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_relief_donation_items_quantity_positive CHECK (quantity_donated > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ============================================================
-- 12. Blood Support
-- ============================================================

CREATE TABLE blood_groups (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    group_code VARCHAR(5) NOT NULL,
    name VARCHAR(20) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (id),
    UNIQUE KEY uq_blood_groups_code (group_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE blood_donors (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NULL,
    reporter_contact_id BIGINT UNSIGNED NULL,
    blood_group_id BIGINT UNSIGNED NOT NULL,
    preferred_location_id BIGINT UNSIGNED NULL,
    consent_to_contact BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_blood_donors_user (user_id),
    KEY idx_blood_donors_contact (reporter_contact_id),
    KEY idx_blood_donors_group (blood_group_id),
    KEY idx_blood_donors_location (preferred_location_id),
    CONSTRAINT fk_blood_donors_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_blood_donors_contact FOREIGN KEY (reporter_contact_id) REFERENCES reporter_contacts(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_blood_donors_group FOREIGN KEY (blood_group_id) REFERENCES blood_groups(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_blood_donors_location FOREIGN KEY (preferred_location_id) REFERENCES locations(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_blood_donors_has_identity CHECK (user_id IS NOT NULL OR reporter_contact_id IS NOT NULL)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE donor_availability (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    blood_donor_id BIGINT UNSIGNED NOT NULL,
    availability_status ENUM('available','unavailable','temporarily_unavailable') NOT NULL DEFAULT 'available',
    available_from TIMESTAMP NULL,
    available_until TIMESTAMP NULL,
    last_donated_at TIMESTAMP NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    note VARCHAR(500) NULL,
    PRIMARY KEY (id),
    KEY idx_donor_availability_donor_updated (blood_donor_id, updated_at),
    KEY idx_donor_availability_status (availability_status),
    CONSTRAINT fk_donor_availability_donor FOREIGN KEY (blood_donor_id) REFERENCES blood_donors(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_donor_availability_until_after_from CHECK (available_until IS NULL OR available_from IS NULL OR available_until >= available_from)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE blood_requests (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    request_code VARCHAR(80) NOT NULL,
    incident_id BIGINT UNSIGNED NULL,
    service_case_id BIGINT UNSIGNED NULL,
    requesting_facility_id BIGINT UNSIGNED NULL,
    blood_group_id BIGINT UNSIGNED NOT NULL,
    units_required INT UNSIGNED NOT NULL,
    urgency_level ENUM('normal','urgent','critical') NOT NULL DEFAULT 'normal',
    request_status ENUM('open','partially_matched','fulfilled','cancelled') NOT NULL DEFAULT 'open',
    needed_by TIMESTAMP NULL,
    created_by_user_id BIGINT UNSIGNED NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_blood_requests_code (request_code),
    KEY idx_blood_requests_incident (incident_id),
    KEY idx_blood_requests_case (service_case_id),
    KEY idx_blood_requests_facility (requesting_facility_id),
    KEY idx_blood_requests_group_status (blood_group_id, request_status),
    CONSTRAINT fk_blood_requests_incident FOREIGN KEY (incident_id) REFERENCES emergency_incidents(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_blood_requests_case FOREIGN KEY (service_case_id) REFERENCES service_cases(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_blood_requests_facility FOREIGN KEY (requesting_facility_id) REFERENCES facilities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_blood_requests_group FOREIGN KEY (blood_group_id) REFERENCES blood_groups(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_blood_requests_user FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_blood_requests_units_positive CHECK (units_required > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE blood_request_matches (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    blood_request_id BIGINT UNSIGNED NOT NULL,
    blood_donor_id BIGINT UNSIGNED NOT NULL,
    match_status ENUM('proposed','contacted','accepted','declined','donated','cancelled') NOT NULL DEFAULT 'proposed',
    matched_by_user_id BIGINT UNSIGNED NULL,
    matched_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    contacted_at TIMESTAMP NULL,
    completed_at TIMESTAMP NULL,
    note VARCHAR(500) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_blood_matches_request_donor (blood_request_id, blood_donor_id),
    KEY idx_blood_matches_donor (blood_donor_id),
    KEY idx_blood_matches_user (matched_by_user_id),
    CONSTRAINT fk_blood_matches_request FOREIGN KEY (blood_request_id) REFERENCES blood_requests(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_blood_matches_donor FOREIGN KEY (blood_donor_id) REFERENCES blood_donors(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_blood_matches_user FOREIGN KEY (matched_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_blood_matches_contacted_after_matched CHECK (contacted_at IS NULL OR contacted_at >= matched_at),
    CONSTRAINT chk_blood_matches_completed_after_matched CHECK (completed_at IS NULL OR completed_at >= matched_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ============================================================
-- 13. Notifications and Email
-- ============================================================

CREATE TABLE notification_templates (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    template_code VARCHAR(120) NOT NULL,
    channel ENUM('in_app','email') NOT NULL,
    subject_template VARCHAR(255) NULL,
    body_template TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_notification_templates_code (template_code),
    CONSTRAINT chk_notification_templates_body_not_blank CHECK (CHAR_LENGTH(TRIM(body_template)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE notifications (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    template_id BIGINT UNSIGNED NULL,
    notification_type ENUM('case_reply','case_resolved','case_escalated','incident_update','dispatch_update','relief_update','blood_request_update') NOT NULL,
    title VARCHAR(255) NOT NULL,
    body TEXT NOT NULL,
    entity_type VARCHAR(100) NULL,
    entity_id BIGINT UNSIGNED NULL,
    created_by_user_id BIGINT UNSIGNED NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_notifications_template (template_id),
    KEY idx_notifications_entity (entity_type, entity_id),
    KEY idx_notifications_created_by (created_by_user_id),
    CONSTRAINT fk_notifications_template FOREIGN KEY (template_id) REFERENCES notification_templates(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_notifications_created_by FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_notifications_title_not_blank CHECK (CHAR_LENGTH(TRIM(title)) > 0),
    CONSTRAINT chk_notifications_body_not_blank CHECK (CHAR_LENGTH(TRIM(body)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE notification_recipients (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    notification_id BIGINT UNSIGNED NOT NULL,
    recipient_user_id BIGINT UNSIGNED NOT NULL,
    delivery_channel ENUM('in_app','email') NOT NULL,
    read_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_notification_recipients_unique (notification_id, recipient_user_id, delivery_channel),
    KEY idx_notification_recipients_user_read (recipient_user_id, read_at),
    CONSTRAINT fk_notification_recipients_notification FOREIGN KEY (notification_id) REFERENCES notifications(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_notification_recipients_user FOREIGN KEY (recipient_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE email_outbox (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    notification_id BIGINT UNSIGNED NULL,
    recipient_user_id BIGINT UNSIGNED NULL,
    to_email VARCHAR(255) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    body TEXT NOT NULL,
    email_status ENUM('pending','sending','sent','failed','cancelled') NOT NULL DEFAULT 'pending',
    available_to_send_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    sent_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_email_outbox_status_available (email_status, available_to_send_at),
    KEY idx_email_outbox_notification (notification_id),
    KEY idx_email_outbox_user (recipient_user_id),
    CONSTRAINT fk_email_outbox_notification FOREIGN KEY (notification_id) REFERENCES notifications(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_email_outbox_user FOREIGN KEY (recipient_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_email_outbox_to_not_blank CHECK (CHAR_LENGTH(TRIM(to_email)) > 0),
    CONSTRAINT chk_email_outbox_subject_not_blank CHECK (CHAR_LENGTH(TRIM(subject)) > 0),
    CONSTRAINT chk_email_outbox_body_not_blank CHECK (CHAR_LENGTH(TRIM(body)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE email_delivery_attempts (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    email_outbox_id BIGINT UNSIGNED NOT NULL,
    attempt_number INT UNSIGNED NOT NULL,
    attempt_status ENUM('success','failed') NOT NULL,
    provider_response TEXT NULL,
    error_message TEXT NULL,
    attempted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_email_attempts_email_attempt (email_outbox_id, attempt_number),
    CONSTRAINT fk_email_attempts_outbox FOREIGN KEY (email_outbox_id) REFERENCES email_outbox(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_email_attempts_attempt_positive CHECK (attempt_number > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ============================================================
-- 14. Audit
-- ============================================================

CREATE TABLE audit_logs (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    actor_user_id BIGINT UNSIGNED NULL,
    action VARCHAR(120) NOT NULL,
    entity_type VARCHAR(120) NOT NULL,
    entity_id BIGINT UNSIGNED NOT NULL,
    related_incident_id BIGINT UNSIGNED NULL,
    related_case_id BIGINT UNSIGNED NULL,
    details_json JSON NULL,
    ip_address VARCHAR(45) NULL,
    user_agent VARCHAR(500) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_audit_actor_created (actor_user_id, created_at),
    KEY idx_audit_entity (entity_type, entity_id),
    KEY idx_audit_related_incident (related_incident_id),
    KEY idx_audit_related_case (related_case_id),
    KEY idx_audit_action (action),
    CONSTRAINT fk_audit_actor FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_audit_related_incident FOREIGN KEY (related_incident_id) REFERENCES emergency_incidents(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_audit_related_case FOREIGN KEY (related_case_id) REFERENCES service_cases(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_audit_action_not_blank CHECK (CHAR_LENGTH(TRIM(action)) > 0),
    CONSTRAINT chk_audit_entity_type_not_blank CHECK (CHAR_LENGTH(TRIM(entity_type)) > 0),
    CONSTRAINT chk_audit_details_json_valid CHECK (details_json IS NULL OR JSON_VALID(details_json))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ============================================================
-- Seed data for lookup tables
-- ============================================================

INSERT INTO roles (role_code, name, description, is_system_role) VALUES
('citizen','Citizen','Registered public user', TRUE),
('admin','Admin','Case and system admin', TRUE),
('call_taker','Call Taker','999/emergency call intake operator', TRUE),
('dispatcher','Dispatcher','Emergency dispatch operator', TRUE),
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

-- ============================================================
-- Triggers
-- ============================================================

DELIMITER $$

CREATE TRIGGER trg_intake_report_status_history_after_insert
AFTER INSERT ON intake_report_status_history
FOR EACH ROW
BEGIN
    UPDATE intake_reports
       SET intake_status = NEW.status
     WHERE id = NEW.intake_report_id;
END$$

CREATE TRIGGER trg_service_cases_before_insert
BEFORE INSERT ON service_cases
FOR EACH ROW
BEGIN
    IF NEW.parent_case_id IS NOT NULL AND NEW.id IS NOT NULL AND NEW.parent_case_id = NEW.id THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Service case cannot be its own parent.';
    END IF;
END$$

CREATE TRIGGER trg_service_cases_before_update
BEFORE UPDATE ON service_cases
FOR EACH ROW
BEGIN
    IF NEW.parent_case_id IS NOT NULL AND NEW.parent_case_id = NEW.id THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Service case cannot be its own parent.';
    END IF;
END$$

CREATE TRIGGER trg_case_status_history_after_insert
AFTER INSERT ON case_status_history
FOR EACH ROW
BEGIN
    UPDATE service_cases
       SET current_status_id = NEW.status_id
     WHERE id = NEW.case_id;
END$$

CREATE TRIGGER trg_incident_status_history_after_insert
AFTER INSERT ON incident_status_history
FOR EACH ROW
BEGIN
    UPDATE emergency_incidents
       SET current_status_id = NEW.status_id
     WHERE id = NEW.incident_id;
END$$

CREATE TRIGGER trg_unit_status_history_after_insert
AFTER INSERT ON unit_status_history
FOR EACH ROW
BEGIN
    UPDATE emergency_units
       SET current_status = NEW.status
     WHERE id = NEW.unit_id;
END$$

CREATE TRIGGER trg_dispatches_before_insert
BEFORE INSERT ON dispatches
FOR EACH ROW
BEGIN
    DECLARE v_agency_id BIGINT UNSIGNED;

    SELECT agency_id INTO v_agency_id
      FROM emergency_units
     WHERE id = NEW.unit_id;

    IF v_agency_id IS NULL THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Dispatch failed: unit_id does not reference a valid emergency unit.';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM incident_agency_participation iap
         WHERE iap.incident_id = NEW.incident_id
           AND iap.agency_id = v_agency_id
           AND iap.participation_status IN ('requested','active')
    ) THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Dispatch failed: unit agency is not participating in this incident.';
    END IF;
END$$

CREATE TRIGGER trg_dispatches_before_update
BEFORE UPDATE ON dispatches
FOR EACH ROW
BEGIN
    DECLARE v_agency_id BIGINT UNSIGNED;

    SELECT agency_id INTO v_agency_id
      FROM emergency_units
     WHERE id = NEW.unit_id;

    IF v_agency_id IS NULL THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Dispatch update failed: unit_id does not reference a valid emergency unit.';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM incident_agency_participation iap
         WHERE iap.incident_id = NEW.incident_id
           AND iap.agency_id = v_agency_id
           AND iap.participation_status IN ('requested','active')
    ) THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Dispatch update failed: unit agency is not participating in this incident.';
    END IF;
END$$

CREATE TRIGGER trg_dispatch_status_history_after_insert
AFTER INSERT ON dispatch_status_history
FOR EACH ROW
BEGIN
    UPDATE dispatches
       SET dispatch_status = NEW.status,
           dispatched_at = CASE WHEN NEW.status = 'dispatched' AND dispatched_at IS NULL THEN NEW.changed_at ELSE dispatched_at END,
           arrived_at = CASE WHEN NEW.status = 'arrived' AND arrived_at IS NULL THEN NEW.changed_at ELSE arrived_at END,
           completed_at = CASE WHEN NEW.status = 'completed' AND completed_at IS NULL THEN NEW.changed_at ELSE completed_at END,
           cancelled_at = CASE WHEN NEW.status = 'cancelled' AND cancelled_at IS NULL THEN NEW.changed_at ELSE cancelled_at END
     WHERE id = NEW.dispatch_id;
END$$

CREATE TRIGGER trg_incident_location_history_after_insert
AFTER INSERT ON incident_location_history
FOR EACH ROW
BEGIN
    IF NEW.is_current THEN
        UPDATE incident_location_history
           SET is_current = FALSE
         WHERE incident_id = NEW.incident_id
           AND id <> NEW.id
           AND is_current = TRUE;

        UPDATE emergency_incidents
           SET current_location_id = NEW.location_id
         WHERE id = NEW.incident_id;
    END IF;
END$$

DELIMITER ;

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

CREATE VIEW vw_call_taker_performance AS
SELECT
    ec.call_taker_user_id,
    up.full_name AS call_taker_name,
    COUNT(ec.id) AS total_calls,
    AVG(TIMESTAMPDIFF(SECOND, ec.call_started_at, ei.created_at)) AS avg_seconds_call_to_incident
FROM emergency_calls ec
LEFT JOIN incident_report_links irl ON irl.intake_report_id = ec.intake_report_id
LEFT JOIN emergency_incidents ei ON ei.id = irl.incident_id
LEFT JOIN user_profiles up ON up.user_id = ec.call_taker_user_id
GROUP BY ec.call_taker_user_id, up.full_name;

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
