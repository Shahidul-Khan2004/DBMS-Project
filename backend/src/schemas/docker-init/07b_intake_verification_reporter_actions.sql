-- ============================================================
-- Intake report verification reviews and reporter account actions
-- ============================================================

CREATE TABLE intake_report_verification_reviews (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_uuid CHAR(36) NOT NULL,
    intake_report_id BIGINT UNSIGNED NOT NULL,
    reviewed_by_user_id BIGINT UNSIGNED NOT NULL,
    verdict VARCHAR(40) NOT NULL,
    reason VARCHAR(255) NULL,
    evidence_note TEXT NULL,
    confidence_level VARCHAR(20) NOT NULL DEFAULT 'medium',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_intake_report_verification_reviews_public_uuid (public_uuid),
    KEY idx_intake_report_verification_reviews_intake_report (intake_report_id),
    KEY idx_intake_report_verification_reviews_reviewed_by (reviewed_by_user_id),
    KEY idx_intake_report_verification_reviews_verdict (verdict),
    KEY idx_intake_report_verification_reviews_created_at (created_at),
    CONSTRAINT fk_intake_report_verification_reviews_intake_report
        FOREIGN KEY (intake_report_id) REFERENCES intake_reports(id)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_intake_report_verification_reviews_reviewed_by
        FOREIGN KEY (reviewed_by_user_id) REFERENCES users(id)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_intake_report_verification_reviews_verdict CHECK (
        verdict IN (
            'genuine',
            'duplicate',
            'mistaken',
            'unverified',
            'false_alarm',
            'malicious_false_report'
        )
    ),
    CONSTRAINT chk_intake_report_verification_reviews_confidence CHECK (
        confidence_level IN ('low', 'medium', 'high')
    )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE reporter_account_actions (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_uuid CHAR(36) NOT NULL,
    target_user_id BIGINT UNSIGNED NOT NULL,
    action_by_user_id BIGINT UNSIGNED NOT NULL,
    action_type VARCHAR(40) NOT NULL,
    previous_account_status VARCHAR(40) NULL,
    new_account_status VARCHAR(40) NULL,
    reason VARCHAR(500) NOT NULL,
    suspension_ends_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_reporter_account_actions_public_uuid (public_uuid),
    KEY idx_reporter_account_actions_target_user (target_user_id),
    KEY idx_reporter_account_actions_action_by (action_by_user_id),
    KEY idx_reporter_account_actions_action_type (action_type),
    KEY idx_reporter_account_actions_created_at (created_at),
    CONSTRAINT fk_reporter_account_actions_target_user
        FOREIGN KEY (target_user_id) REFERENCES users(id)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_reporter_account_actions_action_by
        FOREIGN KEY (action_by_user_id) REFERENCES users(id)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_reporter_account_actions_action_type CHECK (
        action_type IN ('warning', 'suspension', 'disable', 'reactivate', 'note')
    )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
