-- NIERS init schema for MySQL 8.0+


SET NAMES utf8mb4;
SET time_zone = '+00:00';

-- Optional: start clean in development
DROP TRIGGER IF EXISTS trg_dispatches_before_insert;
DROP TRIGGER IF EXISTS trg_dispatches_before_update;
DROP TRIGGER IF EXISTS trg_incident_status_history_after_insert;

DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS incident_status_history;
DROP TABLE IF EXISTS dispatches;
DROP TABLE IF EXISTS incident_agency_participation;
DROP TABLE IF EXISTS emergency_units;
DROP TABLE IF EXISTS incidents;
DROP TABLE IF EXISTS agency_memberships;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS agencies;
DROP TABLE IF EXISTS locations;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_uuid CHAR(36) NOT NULL,
    full_name VARCHAR(150) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    phone_number VARCHAR(30) NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_users_public_uuid (public_uuid),
    UNIQUE KEY uq_users_email (email),
    CONSTRAINT chk_users_full_name_not_blank CHECK (CHAR_LENGTH(TRIM(full_name)) > 0),
    CONSTRAINT chk_users_email_not_blank CHECK (CHAR_LENGTH(TRIM(email)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE roles (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    role_code VARCHAR(100) NOT NULL,
    description VARCHAR(500) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_roles_name (name),
    UNIQUE KEY uq_roles_role_code (role_code),
    CONSTRAINT chk_roles_name_not_blank CHECK (CHAR_LENGTH(TRIM(name)) > 0),
    CONSTRAINT chk_roles_role_code_not_blank CHECK (CHAR_LENGTH(TRIM(role_code)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE agencies (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_uuid CHAR(36) NOT NULL,
    name VARCHAR(150) NOT NULL,
    code VARCHAR(50) NOT NULL,
    agency_type ENUM(
        'medical',
        'law_enforcement',
        'fire_response',
        'disaster_management',
        'infrastructure_emergency'
    ) NOT NULL,
    contact_phone VARCHAR(30) NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_agencies_public_uuid (public_uuid),
    UNIQUE KEY uq_agencies_name (name),
    UNIQUE KEY uq_agencies_code (code),
    CONSTRAINT chk_agencies_name_not_blank CHECK (CHAR_LENGTH(TRIM(name)) > 0),
    CONSTRAINT chk_agencies_code_not_blank CHECK (CHAR_LENGTH(TRIM(code)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE locations (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    latitude DECIMAL(9,6) NOT NULL,
    longitude DECIMAL(9,6) NOT NULL,
    address_text VARCHAR(255) NOT NULL,
    city VARCHAR(100) NULL,
    area VARCHAR(100) NULL,
    source ENUM('user_shared', 'dispatcher_selected', 'api_geocoded', 'manual_entry') NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_locations_city (city),
    KEY idx_locations_area (area),
    CONSTRAINT chk_locations_latitude_range CHECK (latitude BETWEEN -90.000000 AND 90.000000),
    CONSTRAINT chk_locations_longitude_range CHECK (longitude BETWEEN -180.000000 AND 180.000000),
    CONSTRAINT chk_locations_address_not_blank CHECK (CHAR_LENGTH(TRIM(address_text)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE agency_memberships (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    agency_id BIGINT UNSIGNED NOT NULL,
    membership_role ENUM('representative', 'coordinator', 'operator', 'member') NOT NULL,
    membership_status ENUM('active', 'inactive', 'suspended', 'left') NOT NULL DEFAULT 'active',
    joined_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_agency_memberships_user_agency (user_id, agency_id),
    KEY idx_agency_memberships_agency_id (agency_id),
    KEY idx_agency_memberships_role (membership_role),
    KEY idx_agency_memberships_status (membership_status),
    CONSTRAINT fk_agency_memberships_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_agency_memberships_agency
        FOREIGN KEY (agency_id) REFERENCES agencies(id)
        ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE incidents (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_uuid CHAR(36) NOT NULL,
    incident_code VARCHAR(50) NOT NULL,
    title VARCHAR(200) NOT NULL,
    description TEXT NULL,
    category_code ENUM(
        'medical',
        'crime_public_safety',
        'fire',
        'natural_disaster',
        'infrastructure_emergency'
    ) NOT NULL,
    current_status ENUM(
        'reported',
        'classified',
        'agency_assigned',
        'unit_assigned',
        'dispatched',
        'in_progress',
        'resolved',
        'closed',
        'cancelled'
    ) NOT NULL DEFAULT 'reported',
    current_location_id BIGINT UNSIGNED NOT NULL,
    reported_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by_user_id BIGINT UNSIGNED NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_incidents_public_uuid (public_uuid),
    UNIQUE KEY uq_incidents_incident_code (incident_code),
    KEY idx_incidents_category_code (category_code),
    KEY idx_incidents_current_status (current_status),
    KEY idx_incidents_reported_at (reported_at),
    KEY idx_incidents_current_location_id (current_location_id),
    KEY idx_incidents_created_by_user_id (created_by_user_id),
    CONSTRAINT fk_incidents_current_location
        FOREIGN KEY (current_location_id) REFERENCES locations(id)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_incidents_created_by_user
        FOREIGN KEY (created_by_user_id) REFERENCES users(id)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_incidents_title_not_blank CHECK (CHAR_LENGTH(TRIM(title)) > 0),
    CONSTRAINT chk_incidents_incident_code_not_blank CHECK (CHAR_LENGTH(TRIM(incident_code)) > 0),
    CONSTRAINT chk_incidents_reported_before_or_at_created CHECK (reported_at <= created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE emergency_units (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_uuid CHAR(36) NOT NULL,
    agency_id BIGINT UNSIGNED NOT NULL,
    unit_code VARCHAR(50) NOT NULL,
    unit_name VARCHAR(150) NOT NULL,
    unit_type ENUM(
        'ambulance',
        'police_vehicle',
        'fire_truck',
        'rescue_boat',
        'rescue_team',
        'utility_repair_unit',
        'other'
    ) NOT NULL,
    current_status ENUM('available', 'busy', 'maintenance', 'offline') NOT NULL DEFAULT 'available',
    base_location_id BIGINT UNSIGNED NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_emergency_units_public_uuid (public_uuid),
    UNIQUE KEY uq_emergency_units_agency_unit_code (agency_id, unit_code),
    KEY idx_emergency_units_base_location_id (base_location_id),
    KEY idx_emergency_units_current_status (current_status),
    KEY idx_emergency_units_agency_status (agency_id, current_status),
    CONSTRAINT fk_emergency_units_agency
        FOREIGN KEY (agency_id) REFERENCES agencies(id)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_emergency_units_base_location
        FOREIGN KEY (base_location_id) REFERENCES locations(id)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_emergency_units_unit_code_not_blank CHECK (CHAR_LENGTH(TRIM(unit_code)) > 0),
    CONSTRAINT chk_emergency_units_unit_name_not_blank CHECK (CHAR_LENGTH(TRIM(unit_name)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE incident_agency_participation (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    incident_id BIGINT UNSIGNED NOT NULL,
    agency_id BIGINT UNSIGNED NOT NULL,
    is_lead_agency BOOLEAN NOT NULL DEFAULT FALSE,
    participation_status ENUM('requested', 'active', 'completed', 'withdrawn') NOT NULL DEFAULT 'active',
    joined_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lead_incident_id BIGINT UNSIGNED
        GENERATED ALWAYS AS (CASE WHEN is_lead_agency THEN incident_id ELSE NULL END) STORED,
    PRIMARY KEY (id),
    UNIQUE KEY uq_iap_incident_agency (incident_id, agency_id),
    UNIQUE KEY uq_iap_one_lead_per_incident (lead_incident_id),
    KEY idx_iap_agency_id (agency_id),
    KEY idx_iap_participation_status (participation_status),
    CONSTRAINT fk_iap_incident
        FOREIGN KEY (incident_id) REFERENCES incidents(id)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_iap_agency
        FOREIGN KEY (agency_id) REFERENCES agencies(id)
        ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE dispatches (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    incident_id BIGINT UNSIGNED NOT NULL,
    unit_id BIGINT UNSIGNED NOT NULL,
    dispatch_status ENUM('assigned', 'dispatched', 'arrived', 'completed', 'cancelled') NOT NULL DEFAULT 'assigned',
    assigned_by_user_id BIGINT UNSIGNED NOT NULL,
    assigned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    dispatched_at TIMESTAMP NULL,
    arrived_at TIMESTAMP NULL,
    completed_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_dispatches_incident_unit (incident_id, unit_id),
    KEY idx_dispatches_unit_id (unit_id),
    KEY idx_dispatches_assigned_by_user_id (assigned_by_user_id),
    KEY idx_dispatches_status (dispatch_status),
    KEY idx_dispatches_incident_status (incident_id, dispatch_status),
    CONSTRAINT fk_dispatches_incident
        FOREIGN KEY (incident_id) REFERENCES incidents(id)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_dispatches_unit
        FOREIGN KEY (unit_id) REFERENCES emergency_units(id)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_dispatches_assigned_by_user
        FOREIGN KEY (assigned_by_user_id) REFERENCES users(id)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_dispatches_time_order_1 CHECK (dispatched_at IS NULL OR dispatched_at >= assigned_at),
    CONSTRAINT chk_dispatches_time_order_2 CHECK (arrived_at IS NULL OR (dispatched_at IS NOT NULL AND arrived_at >= dispatched_at)),
    CONSTRAINT chk_dispatches_time_order_3 CHECK (completed_at IS NULL OR (arrived_at IS NOT NULL AND completed_at >= arrived_at))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE incident_status_history (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    incident_id BIGINT UNSIGNED NOT NULL,
    status ENUM(
        'reported',
        'classified',
        'agency_assigned',
        'unit_assigned',
        'dispatched',
        'in_progress',
        'resolved',
        'closed',
        'cancelled'
    ) NOT NULL,
    changed_by_user_id BIGINT UNSIGNED NOT NULL,
    changed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    note VARCHAR(500) NULL,
    PRIMARY KEY (id),
    KEY idx_incident_status_history_incident_changed_at (incident_id, changed_at),
    KEY idx_incident_status_history_changed_by (changed_by_user_id),
    KEY idx_incident_status_history_status (status),
    CONSTRAINT fk_ish_incident
        FOREIGN KEY (incident_id) REFERENCES incidents(id)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_ish_changed_by_user
        FOREIGN KEY (changed_by_user_id) REFERENCES users(id)
        ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE audit_logs (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    incident_id BIGINT UNSIGNED NULL,
    action VARCHAR(100) NOT NULL,
    entity_type VARCHAR(100) NOT NULL,
    entity_id BIGINT UNSIGNED NOT NULL,
    details_json JSON NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_audit_logs_user_id (user_id),
    KEY idx_audit_logs_incident_id (incident_id),
    KEY idx_audit_logs_entity (entity_type, entity_id),
    KEY idx_audit_logs_action (action),
    KEY idx_audit_logs_created_at (created_at),
    CONSTRAINT fk_audit_logs_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_audit_logs_incident
        FOREIGN KEY (incident_id) REFERENCES incidents(id)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_audit_logs_action_not_blank CHECK (CHAR_LENGTH(TRIM(action)) > 0),
    CONSTRAINT chk_audit_logs_entity_type_not_blank CHECK (CHAR_LENGTH(TRIM(entity_type)) > 0),
    CONSTRAINT chk_audit_logs_details_json_valid CHECK (details_json IS NULL OR JSON_VALID(details_json))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE user_roles (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    role_id BIGINT UNSIGNED NOT NULL,
    assigned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_user_roles_user_role (user_id, role_id),
    KEY idx_user_roles_role_id (role_id),
    CONSTRAINT fk_user_roles_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_user_roles_role
        FOREIGN KEY (role_id) REFERENCES roles(id)
        ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DELIMITER $$

CREATE TRIGGER trg_dispatches_before_insert
BEFORE INSERT ON dispatches
FOR EACH ROW
BEGIN
    DECLARE v_agency_id BIGINT UNSIGNED;

    SELECT agency_id
      INTO v_agency_id
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
    ) THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Dispatch failed: the unit''s agency is not participating in this incident.';
    END IF;
END$$

CREATE TRIGGER trg_dispatches_before_update
BEFORE UPDATE ON dispatches
FOR EACH ROW
BEGIN
    DECLARE v_agency_id BIGINT UNSIGNED;

    SELECT agency_id
      INTO v_agency_id
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
    ) THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Dispatch update failed: the unit''s agency is not participating in this incident.';
    END IF;
END$$

CREATE TRIGGER trg_incident_status_history_after_insert
AFTER INSERT ON incident_status_history
FOR EACH ROW
BEGIN
    UPDATE incidents
       SET current_status = NEW.status
     WHERE id = NEW.incident_id;
END$$

DELIMITER ;
