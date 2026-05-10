-- ============================================================
-- 12. Blood Support
-- ============================================================

CREATE TABLE blood_groups (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    group_code VARCHAR(5) NOT NULL,
    name VARCHAR(20) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (id),
    UNIQUE KEY uq_blood_groups_code (group_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE blood_donors (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NULL,
    reporter_contact_id BIGINT UNSIGNED NULL,
    blood_group_id BIGINT UNSIGNED NOT NULL,
    preferred_location_id BIGINT UNSIGNED NULL,
    consent_to_contact BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_blood_donors_user (user_id),
    KEY idx_blood_donors_contact (reporter_contact_id),
    KEY idx_blood_donors_group (blood_group_id),
    KEY idx_blood_donors_location (preferred_location_id),
    CONSTRAINT fk_blood_donors_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_blood_donors_contact FOREIGN KEY (reporter_contact_id) REFERENCES reporter_contacts(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_blood_donors_group FOREIGN KEY (blood_group_id) REFERENCES blood_groups(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_blood_donors_location FOREIGN KEY (preferred_location_id) REFERENCES locations(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_blood_donors_has_identity CHECK (user_id IS NOT NULL OR reporter_contact_id IS NOT NULL)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE donor_availability (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    blood_donor_id BIGINT UNSIGNED NOT NULL,
    availability_status ENUM('available','unavailable','temporarily_unavailable') NOT NULL DEFAULT 'available',
    available_from TIMESTAMP NULL,
    available_until TIMESTAMP NULL,
    last_donated_at TIMESTAMP NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    note VARCHAR(500) NULL,
    PRIMARY KEY (id),
    KEY idx_donor_availability_donor_updated (blood_donor_id, updated_at),
    KEY idx_donor_availability_status (availability_status),
    CONSTRAINT fk_donor_availability_donor FOREIGN KEY (blood_donor_id) REFERENCES blood_donors(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_donor_availability_until_after_from CHECK (available_until IS NULL OR available_from IS NULL OR available_until >= available_from)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE blood_requests (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    request_code VARCHAR(80) NOT NULL,
    incident_id BIGINT UNSIGNED NULL,
    service_case_id BIGINT UNSIGNED NULL,
    requesting_facility_id BIGINT UNSIGNED NULL,
    blood_group_id BIGINT UNSIGNED NOT NULL,
    units_required INT UNSIGNED NOT NULL,
    urgency_level ENUM('normal','urgent','critical') NOT NULL DEFAULT 'normal',
    request_status ENUM('open','partially_matched','fulfilled','cancelled') NOT NULL DEFAULT 'open',
    needed_by TIMESTAMP NULL,
    created_by_user_id BIGINT UNSIGNED NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_blood_requests_code (request_code),
    KEY idx_blood_requests_incident (incident_id),
    KEY idx_blood_requests_case (service_case_id),
    KEY idx_blood_requests_facility (requesting_facility_id),
    KEY idx_blood_requests_group_status (blood_group_id, request_status),
    CONSTRAINT fk_blood_requests_incident FOREIGN KEY (incident_id) REFERENCES emergency_incidents(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_blood_requests_case FOREIGN KEY (service_case_id) REFERENCES service_cases(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_blood_requests_facility FOREIGN KEY (requesting_facility_id) REFERENCES facilities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_blood_requests_group FOREIGN KEY (blood_group_id) REFERENCES blood_groups(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_blood_requests_user FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_blood_requests_units_positive CHECK (units_required > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE blood_request_matches (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    blood_request_id BIGINT UNSIGNED NOT NULL,
    blood_donor_id BIGINT UNSIGNED NOT NULL,
    match_status ENUM('proposed','contacted','accepted','declined','donated','cancelled') NOT NULL DEFAULT 'proposed',
    matched_by_user_id BIGINT UNSIGNED NULL,
    matched_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    contacted_at TIMESTAMP NULL,
    completed_at TIMESTAMP NULL,
    note VARCHAR(500) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_blood_matches_request_donor (blood_request_id, blood_donor_id),
    KEY idx_blood_matches_donor (blood_donor_id),
    KEY idx_blood_matches_user (matched_by_user_id),
    CONSTRAINT fk_blood_matches_request FOREIGN KEY (blood_request_id) REFERENCES blood_requests(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_blood_matches_donor FOREIGN KEY (blood_donor_id) REFERENCES blood_donors(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_blood_matches_user FOREIGN KEY (matched_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_blood_matches_contacted_after_matched CHECK (contacted_at IS NULL OR contacted_at >= matched_at),
    CONSTRAINT chk_blood_matches_completed_after_matched CHECK (completed_at IS NULL OR completed_at >= matched_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
