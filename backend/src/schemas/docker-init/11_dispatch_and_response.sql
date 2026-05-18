-- ============================================================
-- 7. Dispatch and Response
-- ============================================================

CREATE TABLE dispatch_statuses (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    status_code VARCHAR(100) NOT NULL,
    name VARCHAR(150) NOT NULL,
    description VARCHAR(500) NULL,
    sort_order INT NOT NULL DEFAULT 0,
    is_terminal BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (id),
    UNIQUE KEY uq_dispatch_statuses_status_code (status_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE dispatch_status_transitions (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    from_status_id BIGINT UNSIGNED NOT NULL,
    to_status_id BIGINT UNSIGNED NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    requires_note BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (id),
    UNIQUE KEY uq_dispatch_status_transitions_from_to (from_status_id, to_status_id),
    KEY idx_dispatch_status_transitions_to (to_status_id),
    CONSTRAINT fk_dispatch_status_transitions_from FOREIGN KEY (from_status_id) REFERENCES dispatch_statuses(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_dispatch_status_transitions_to FOREIGN KEY (to_status_id) REFERENCES dispatch_statuses(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE dispatches (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    incident_id BIGINT UNSIGNED NOT NULL,
    unit_id BIGINT UNSIGNED NOT NULL,
    assigned_by_user_id BIGINT UNSIGNED NOT NULL,
    current_status_id BIGINT UNSIGNED NOT NULL,
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
    KEY idx_dispatches_status (current_status_id),
    KEY idx_dispatches_incident_status (incident_id, current_status_id),
    CONSTRAINT fk_dispatches_incident FOREIGN KEY (incident_id) REFERENCES emergency_incidents(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_dispatches_unit FOREIGN KEY (unit_id) REFERENCES emergency_units(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_dispatches_assigned_by FOREIGN KEY (assigned_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_dispatches_current_status FOREIGN KEY (current_status_id) REFERENCES dispatch_statuses(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_dispatches_dispatched_after_assigned CHECK (dispatched_at IS NULL OR dispatched_at >= assigned_at),
    CONSTRAINT chk_dispatches_arrived_after_dispatched CHECK (arrived_at IS NULL OR (dispatched_at IS NOT NULL AND arrived_at >= dispatched_at)),
    CONSTRAINT chk_dispatches_completed_after_arrived CHECK (completed_at IS NULL OR (arrived_at IS NOT NULL AND completed_at >= arrived_at)),
    CONSTRAINT chk_dispatches_cancelled_after_assigned CHECK (cancelled_at IS NULL OR cancelled_at >= assigned_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE dispatch_status_history (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    dispatch_id BIGINT UNSIGNED NOT NULL,
    status_id BIGINT UNSIGNED NOT NULL,
    changed_by_user_id BIGINT UNSIGNED NULL,
    changed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    note VARCHAR(500) NULL,
    PRIMARY KEY (id),
    KEY idx_dispatch_status_history_dispatch_changed (dispatch_id, changed_at),
    KEY idx_dispatch_status_history_status (status_id),
    KEY idx_dispatch_status_history_user (changed_by_user_id),
    CONSTRAINT fk_dispatch_status_history_dispatch FOREIGN KEY (dispatch_id) REFERENCES dispatches(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_dispatch_status_history_status FOREIGN KEY (status_id) REFERENCES dispatch_statuses(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
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
