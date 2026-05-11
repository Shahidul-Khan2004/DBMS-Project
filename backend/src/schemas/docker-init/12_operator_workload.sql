-- ============================================================
-- 8. Operator Workload Balancing
-- ============================================================

CREATE TABLE operator_shifts (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    shift_role ENUM('case_admin','dispatcher','disaster_coordinator') NOT NULL,
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
