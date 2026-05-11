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
