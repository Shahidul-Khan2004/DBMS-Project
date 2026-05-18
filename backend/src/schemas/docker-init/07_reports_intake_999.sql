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

CREATE TABLE intake_statuses (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    status_code VARCHAR(100) NOT NULL,
    name VARCHAR(150) NOT NULL,
    description VARCHAR(500) NULL,
    sort_order INT NOT NULL DEFAULT 0,
    is_terminal BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (id),
    UNIQUE KEY uq_intake_statuses_status_code (status_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE intake_status_transitions (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    from_status_id BIGINT UNSIGNED NOT NULL,
    to_status_id BIGINT UNSIGNED NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    requires_note BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (id),
    UNIQUE KEY uq_intake_status_transitions_from_to (from_status_id, to_status_id),
    KEY idx_intake_status_transitions_to (to_status_id),
    CONSTRAINT fk_intake_status_transitions_from FOREIGN KEY (from_status_id) REFERENCES intake_statuses(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_intake_status_transitions_to FOREIGN KEY (to_status_id) REFERENCES intake_statuses(id) ON DELETE RESTRICT ON UPDATE RESTRICT
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
    current_status_id BIGINT UNSIGNED NOT NULL,
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
    KEY idx_intake_reports_current_status (current_status_id),
    KEY idx_intake_reports_reported_at (reported_at),
    CONSTRAINT fk_intake_reports_reporter_user FOREIGN KEY (reporter_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_intake_reports_reporter_contact FOREIGN KEY (reporter_contact_id) REFERENCES reporter_contacts(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_intake_reports_channel FOREIGN KEY (channel_id) REFERENCES report_channels(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_intake_reports_category FOREIGN KEY (category_id) REFERENCES report_categories(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_intake_reports_location FOREIGN KEY (reported_location_id) REFERENCES locations(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_intake_reports_received_by FOREIGN KEY (received_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_intake_reports_current_status FOREIGN KEY (current_status_id) REFERENCES intake_statuses(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_intake_reports_summary_not_blank CHECK (CHAR_LENGTH(TRIM(summary)) > 0),
    CONSTRAINT chk_intake_reports_reported_before_created CHECK (reported_at <= created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE intake_report_status_history (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    intake_report_id BIGINT UNSIGNED NOT NULL,
    status_id BIGINT UNSIGNED NOT NULL,
    changed_by_user_id BIGINT UNSIGNED NULL,
    changed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    note VARCHAR(500) NULL,
    PRIMARY KEY (id),
    KEY idx_irsh_report_changed (intake_report_id, changed_at),
    KEY idx_irsh_status (status_id),
    KEY idx_irsh_changed_by (changed_by_user_id),
    CONSTRAINT fk_irsh_report FOREIGN KEY (intake_report_id) REFERENCES intake_reports(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_irsh_status FOREIGN KEY (status_id) REFERENCES intake_statuses(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_irsh_changed_by FOREIGN KEY (changed_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE intake_report_location_history (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    intake_report_id BIGINT UNSIGNED NOT NULL,
    location_id BIGINT UNSIGNED NOT NULL,
    previous_location_id BIGINT UNSIGNED NULL,
    change_kind ENUM('initial_create','location_patch') NOT NULL,
    changed_by_user_id BIGINT UNSIGNED NULL,
    changed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    change_reason VARCHAR(500) NULL,
    PRIMARY KEY (id),
    KEY idx_irlh_report_changed (intake_report_id, changed_at),
    KEY idx_irlh_location (location_id),
    KEY idx_irlh_previous_location (previous_location_id),
    KEY idx_irlh_changed_by (changed_by_user_id),
    CONSTRAINT fk_irlh_report FOREIGN KEY (intake_report_id) REFERENCES intake_reports(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_irlh_location FOREIGN KEY (location_id) REFERENCES locations(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_irlh_previous_location FOREIGN KEY (previous_location_id) REFERENCES locations(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_irlh_changed_by FOREIGN KEY (changed_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
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
    dispatcher_id BIGINT UNSIGNED NOT NULL,
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
    KEY idx_emergency_calls_dispatcher (dispatcher_id),
    KEY idx_emergency_calls_started (call_started_at),
    KEY idx_emergency_calls_status (call_status),
    CONSTRAINT fk_emergency_calls_intake_report FOREIGN KEY (intake_report_id) REFERENCES intake_reports(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_emergency_calls_dispatcher FOREIGN KEY (dispatcher_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
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
