-- ============================================================
-- 9. Disaster / National Emergency Management (BCNF)
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

CREATE TABLE disaster_event_statuses (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    status_code VARCHAR(100) NOT NULL,
    name VARCHAR(150) NOT NULL,
    description VARCHAR(500) NULL,
    sort_order INT NOT NULL DEFAULT 0,
    is_terminal BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (id),
    UNIQUE KEY uq_disaster_event_statuses_code (status_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE disaster_event_status_transitions (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    from_status_id BIGINT UNSIGNED NOT NULL,
    to_status_id BIGINT UNSIGNED NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    requires_note BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (id),
    UNIQUE KEY uq_disaster_event_status_transitions_from_to (from_status_id, to_status_id),
    KEY idx_disaster_event_status_transitions_to (to_status_id),
    CONSTRAINT fk_dest_trans_from FOREIGN KEY (from_status_id) REFERENCES disaster_event_statuses(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_dest_trans_to FOREIGN KEY (to_status_id) REFERENCES disaster_event_statuses(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE disaster_events (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_uuid CHAR(36) NOT NULL,
    event_code VARCHAR(60) NOT NULL,
    event_type_id BIGINT UNSIGNED NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NULL,
    public_guidance TEXT NULL,
    current_status_id BIGINT UNSIGNED NOT NULL,
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
    KEY idx_disaster_events_status (current_status_id),
    KEY idx_disaster_events_started (started_at),
    CONSTRAINT fk_disaster_events_type FOREIGN KEY (event_type_id) REFERENCES disaster_event_types(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_disaster_events_status FOREIGN KEY (current_status_id) REFERENCES disaster_event_statuses(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_disaster_events_created_by FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_disaster_events_title_not_blank CHECK (CHAR_LENGTH(TRIM(title)) > 0),
    CONSTRAINT chk_disaster_events_end_after_start CHECK (ended_at IS NULL OR ended_at >= started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE disaster_event_status_history (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    disaster_event_id BIGINT UNSIGNED NOT NULL,
    status_id BIGINT UNSIGNED NOT NULL,
    changed_by_user_id BIGINT UNSIGNED NULL,
    changed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    note VARCHAR(500) NULL,
    PRIMARY KEY (id),
    KEY idx_desh_event_changed (disaster_event_id, changed_at),
    KEY idx_desh_status (status_id),
    KEY idx_desh_user (changed_by_user_id),
    CONSTRAINT fk_desh_event FOREIGN KEY (disaster_event_id) REFERENCES disaster_events(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_desh_status FOREIGN KEY (status_id) REFERENCES disaster_event_statuses(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_desh_user FOREIGN KEY (changed_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE disaster_affected_areas (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_uuid CHAR(36) NOT NULL,
    disaster_event_id BIGINT UNSIGNED NOT NULL,
    admin_area_id BIGINT UNSIGNED NOT NULL,
    added_by_user_id BIGINT UNSIGNED NOT NULL,
    added_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_disaster_affected_areas_event_area (disaster_event_id, admin_area_id),
    UNIQUE KEY uq_disaster_affected_areas_public_uuid (public_uuid),
    KEY idx_disaster_affected_areas_area (admin_area_id),
    CONSTRAINT fk_disaster_affected_areas_event FOREIGN KEY (disaster_event_id) REFERENCES disaster_events(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_disaster_affected_areas_area FOREIGN KEY (admin_area_id) REFERENCES administrative_areas(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_disaster_affected_areas_user FOREIGN KEY (added_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE disaster_affected_area_assessments (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    disaster_affected_area_id BIGINT UNSIGNED NOT NULL,
    impact_level ENUM('low','medium','high','severe') NOT NULL DEFAULT 'medium',
    estimated_affected_people INT UNSIGNED NULL,
    shelter_support_required BOOLEAN NOT NULL DEFAULT FALSE,
    relief_support_required BOOLEAN NOT NULL DEFAULT FALSE,
    assessment_note VARCHAR(1000) NULL,
    recorded_by_user_id BIGINT UNSIGNED NOT NULL,
    recorded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_daaa_area_recorded (disaster_affected_area_id, recorded_at),
    KEY idx_daaa_user (recorded_by_user_id),
    CONSTRAINT fk_daaa_area FOREIGN KEY (disaster_affected_area_id) REFERENCES disaster_affected_areas(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_daaa_user FOREIGN KEY (recorded_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE disaster_agency_responsibilities (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    disaster_event_id BIGINT UNSIGNED NOT NULL,
    agency_id BIGINT UNSIGNED NOT NULL,
    responsibility_type ENUM(
        'coordination',
        'shelter_management',
        'relief_management',
        'medical_support',
        'security_support',
        'rescue_support'
    ) NOT NULL,
    is_lead BOOLEAN NOT NULL DEFAULT FALSE,
    assigned_by_user_id BIGINT UNSIGNED NOT NULL,
    assigned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deactivated_at TIMESTAMP NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_disaster_agency_resp_event_agency_type (disaster_event_id, agency_id, responsibility_type),
    KEY idx_disaster_agency_resp_agency (agency_id),
    KEY idx_disaster_agency_resp_type (disaster_event_id, responsibility_type),
    CONSTRAINT fk_disaster_agency_resp_event FOREIGN KEY (disaster_event_id) REFERENCES disaster_events(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_disaster_agency_resp_agency FOREIGN KEY (agency_id) REFERENCES agencies(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_disaster_agency_resp_user FOREIGN KEY (assigned_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE disaster_declarations (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_uuid CHAR(36) NOT NULL,
    disaster_event_id BIGINT UNSIGNED NOT NULL,
    declaration_code VARCHAR(80) NOT NULL,
    declaration_kind ENUM('initial','amendment') NOT NULL,
    title VARCHAR(255) NOT NULL,
    public_guidance TEXT NULL,
    legal_reference VARCHAR(255) NULL,
    reason VARCHAR(1000) NOT NULL,
    issued_by_user_id BIGINT UNSIGNED NOT NULL,
    issued_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    initial_disaster_event_id BIGINT UNSIGNED GENERATED ALWAYS AS (
        CASE WHEN declaration_kind = 'initial' THEN disaster_event_id ELSE NULL END
    ) STORED,
    PRIMARY KEY (id),
    UNIQUE KEY uq_disaster_declarations_code (declaration_code),
    UNIQUE KEY uq_disaster_declarations_public_uuid (public_uuid),
    UNIQUE KEY uq_disaster_declarations_one_initial_per_disaster (initial_disaster_event_id),
    KEY idx_disaster_declarations_disaster (disaster_event_id),
    KEY idx_disaster_declarations_issued_by (issued_by_user_id),
    CONSTRAINT fk_disaster_declarations_disaster FOREIGN KEY (disaster_event_id) REFERENCES disaster_events(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_disaster_declarations_user FOREIGN KEY (issued_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_disaster_declarations_title_not_blank CHECK (CHAR_LENGTH(TRIM(title)) > 0),
    CONSTRAINT chk_disaster_declarations_reason_not_blank CHECK (CHAR_LENGTH(TRIM(reason)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE disaster_incident_links (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    disaster_event_id BIGINT UNSIGNED NOT NULL,
    incident_id BIGINT UNSIGNED NOT NULL,
    linked_by_user_id BIGINT UNSIGNED NOT NULL,
    linked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    link_note VARCHAR(500) NULL,
    unlinked_at TIMESTAMP NULL,
    unlinked_by_user_id BIGINT UNSIGNED NULL,
    unlink_reason VARCHAR(500) NULL,
    active_incident_id BIGINT UNSIGNED GENERATED ALWAYS AS (
        CASE WHEN unlinked_at IS NULL THEN incident_id ELSE NULL END
    ) STORED,
    PRIMARY KEY (id),
    UNIQUE KEY uq_disaster_incident_links_active_incident (active_incident_id),
    KEY idx_disaster_incident_links_disaster (disaster_event_id),
    KEY idx_disaster_incident_links_incident (incident_id),
    CONSTRAINT fk_disaster_incident_links_disaster FOREIGN KEY (disaster_event_id) REFERENCES disaster_events(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_disaster_incident_links_incident FOREIGN KEY (incident_id) REFERENCES emergency_incidents(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_disaster_incident_links_linked_by FOREIGN KEY (linked_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_disaster_incident_links_unlinked_by FOREIGN KEY (unlinked_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_disaster_incident_links_unlink_reason CHECK (
        unlinked_at IS NULL OR (unlink_reason IS NOT NULL AND CHAR_LENGTH(TRIM(unlink_reason)) > 0)
    )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
