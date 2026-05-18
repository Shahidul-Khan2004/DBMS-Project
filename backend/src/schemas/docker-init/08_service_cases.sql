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

CREATE TABLE case_status_transitions (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    from_status_id BIGINT UNSIGNED NOT NULL,
    to_status_id BIGINT UNSIGNED NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    requires_note BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (id),
    UNIQUE KEY uq_case_status_transitions_from_to (from_status_id, to_status_id),
    KEY idx_case_status_transitions_to (to_status_id),
    CONSTRAINT fk_case_status_transitions_from FOREIGN KEY (from_status_id) REFERENCES case_statuses(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_case_status_transitions_to FOREIGN KEY (to_status_id) REFERENCES case_statuses(id) ON DELETE RESTRICT ON UPDATE RESTRICT
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
    KEY idx_service_cases_created_at (created_at),
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
    subject VARCHAR(255) NOT NULL,
    body TEXT NULL,
    is_internal BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_case_messages_case_created (case_id, created_at),
    KEY idx_case_messages_sender (sender_user_id),
    CONSTRAINT fk_case_messages_case FOREIGN KEY (case_id) REFERENCES service_cases(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_case_messages_sender FOREIGN KEY (sender_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_case_messages_subject_not_blank CHECK (CHAR_LENGTH(TRIM(subject)) > 0)
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
