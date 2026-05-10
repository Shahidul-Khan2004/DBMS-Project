-- ============================================================
-- 14. Audit
-- ============================================================

CREATE TABLE audit_logs (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    actor_user_id BIGINT UNSIGNED NULL,
    action VARCHAR(120) NOT NULL,
    entity_type VARCHAR(120) NOT NULL,
    entity_id BIGINT UNSIGNED NOT NULL,
    related_incident_id BIGINT UNSIGNED NULL,
    related_case_id BIGINT UNSIGNED NULL,
    details_json JSON NULL,
    ip_address VARCHAR(45) NULL,
    user_agent VARCHAR(500) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_audit_actor_created (actor_user_id, created_at),
    KEY idx_audit_entity (entity_type, entity_id),
    KEY idx_audit_related_incident (related_incident_id),
    KEY idx_audit_related_case (related_case_id),
    KEY idx_audit_action (action),
    CONSTRAINT fk_audit_actor FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_audit_related_incident FOREIGN KEY (related_incident_id) REFERENCES emergency_incidents(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_audit_related_case FOREIGN KEY (related_case_id) REFERENCES service_cases(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_audit_action_not_blank CHECK (CHAR_LENGTH(TRIM(action)) > 0),
    CONSTRAINT chk_audit_entity_type_not_blank CHECK (CHAR_LENGTH(TRIM(entity_type)) > 0),
    CONSTRAINT chk_audit_details_json_valid CHECK (details_json IS NULL OR JSON_VALID(details_json))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
