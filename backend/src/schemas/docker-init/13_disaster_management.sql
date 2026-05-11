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
