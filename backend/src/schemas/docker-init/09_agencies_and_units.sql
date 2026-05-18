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

CREATE TABLE unit_statuses (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    status_code VARCHAR(100) NOT NULL,
    name VARCHAR(150) NOT NULL,
    description VARCHAR(500) NULL,
    sort_order INT NOT NULL DEFAULT 0,
    is_terminal BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (id),
    UNIQUE KEY uq_unit_statuses_status_code (status_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE unit_status_transitions (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    from_status_id BIGINT UNSIGNED NOT NULL,
    to_status_id BIGINT UNSIGNED NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    requires_note BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (id),
    UNIQUE KEY uq_unit_status_transitions_from_to (from_status_id, to_status_id),
    KEY idx_unit_status_transitions_to (to_status_id),
    CONSTRAINT fk_unit_status_transitions_from FOREIGN KEY (from_status_id) REFERENCES unit_statuses(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_unit_status_transitions_to FOREIGN KEY (to_status_id) REFERENCES unit_statuses(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE emergency_units (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_uuid CHAR(36) NOT NULL,
    agency_id BIGINT UNSIGNED NOT NULL,
    unit_type_id BIGINT UNSIGNED NOT NULL,
    unit_code VARCHAR(80) NOT NULL,
    unit_name VARCHAR(150) NOT NULL,
    base_location_id BIGINT UNSIGNED NOT NULL,
    current_status_id BIGINT UNSIGNED NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_emergency_units_public_uuid (public_uuid),
    UNIQUE KEY uq_emergency_units_agency_unit_code (agency_id, unit_code),
    KEY idx_emergency_units_agency_status (agency_id, current_status_id),
    KEY idx_emergency_units_current_status (current_status_id),
    KEY idx_emergency_units_type (unit_type_id),
    KEY idx_emergency_units_base_location (base_location_id),
    CONSTRAINT fk_emergency_units_agency FOREIGN KEY (agency_id) REFERENCES agencies(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_emergency_units_type FOREIGN KEY (unit_type_id) REFERENCES emergency_unit_types(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_emergency_units_base_location FOREIGN KEY (base_location_id) REFERENCES locations(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_emergency_units_current_status FOREIGN KEY (current_status_id) REFERENCES unit_statuses(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
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
    status_id BIGINT UNSIGNED NOT NULL,
    changed_by_user_id BIGINT UNSIGNED NULL,
    changed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    note VARCHAR(500) NULL,
    PRIMARY KEY (id),
    KEY idx_unit_status_history_unit_changed (unit_id, changed_at),
    KEY idx_unit_status_history_status (status_id),
    KEY idx_unit_status_history_user (changed_by_user_id),
    CONSTRAINT fk_unit_status_history_unit FOREIGN KEY (unit_id) REFERENCES emergency_units(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_unit_status_history_status FOREIGN KEY (status_id) REFERENCES unit_statuses(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_unit_status_history_user FOREIGN KEY (changed_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
