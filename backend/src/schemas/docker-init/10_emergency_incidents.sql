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

CREATE TABLE incident_status_transitions (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    from_status_id BIGINT UNSIGNED NOT NULL,
    to_status_id BIGINT UNSIGNED NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    requires_note BOOLEAN NOT NULL DEFAULT FALSE,
    requires_outcome BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (id),
    UNIQUE KEY uq_incident_status_transitions_from_to (from_status_id, to_status_id),
    KEY idx_incident_status_transitions_to (to_status_id),
    CONSTRAINT fk_incident_status_transitions_from FOREIGN KEY (from_status_id) REFERENCES incident_statuses(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_incident_status_transitions_to FOREIGN KEY (to_status_id) REFERENCES incident_statuses(id) ON DELETE RESTRICT ON UPDATE RESTRICT
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
    outcome_id BIGINT UNSIGNED NULL,
    changed_by_user_id BIGINT UNSIGNED NULL,
    changed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    note VARCHAR(500) NULL,
    PRIMARY KEY (id),
    KEY idx_incident_status_history_incident_changed (incident_id, changed_at),
    KEY idx_incident_status_history_status (status_id),
    KEY idx_incident_status_history_outcome (outcome_id),
    KEY idx_incident_status_history_user (changed_by_user_id),
    CONSTRAINT fk_incident_status_history_incident FOREIGN KEY (incident_id) REFERENCES emergency_incidents(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_incident_status_history_status FOREIGN KEY (status_id) REFERENCES incident_statuses(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_incident_status_history_outcome FOREIGN KEY (outcome_id) REFERENCES incident_outcomes(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
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
