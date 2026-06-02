-- ============================================================
-- 10. Facilities and Healthcare
-- ============================================================

CREATE TABLE facility_types (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    type_code VARCHAR(100) NOT NULL,
    name VARCHAR(150) NOT NULL,
    description VARCHAR(500) NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (id),
    UNIQUE KEY uq_facility_types_code (type_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE facilities (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_uuid CHAR(36) NOT NULL,
    facility_type_id BIGINT UNSIGNED NOT NULL,
    facility_code VARCHAR(80) NOT NULL,
    name VARCHAR(180) NOT NULL,
    location_id BIGINT UNSIGNED NOT NULL,
    owning_agency_id BIGINT UNSIGNED NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_facilities_public_uuid (public_uuid),
    UNIQUE KEY uq_facilities_facility_code (facility_code),
    KEY idx_facilities_type (facility_type_id),
    KEY idx_facilities_location (location_id),
    KEY idx_facilities_agency (owning_agency_id),
    CONSTRAINT fk_facilities_type FOREIGN KEY (facility_type_id) REFERENCES facility_types(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_facilities_location FOREIGN KEY (location_id) REFERENCES locations(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_facilities_agency FOREIGN KEY (owning_agency_id) REFERENCES agencies(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_facilities_name_not_blank CHECK (CHAR_LENGTH(TRIM(name)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE facility_contacts (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    facility_id BIGINT UNSIGNED NOT NULL,
    contact_type ENUM('phone','email','hotline','website') NOT NULL,
    contact_value VARCHAR(255) NOT NULL,
    label VARCHAR(120) NULL,
    is_primary BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_facility_contacts_unique_value (facility_id, contact_type, contact_value),
    CONSTRAINT fk_facility_contacts_facility FOREIGN KEY (facility_id) REFERENCES facilities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_facility_contacts_value_not_blank CHECK (CHAR_LENGTH(TRIM(contact_value)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE facility_capabilities (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    facility_id BIGINT UNSIGNED NOT NULL,
    capability_id BIGINT UNSIGNED NOT NULL,
    capacity_note VARCHAR(500) NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_facility_capabilities_facility_capability (facility_id, capability_id),
    KEY idx_facility_capabilities_capability (capability_id),
    CONSTRAINT fk_facility_capabilities_facility FOREIGN KEY (facility_id) REFERENCES facilities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_facility_capabilities_capability FOREIGN KEY (capability_id) REFERENCES capabilities(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE facility_default_capacities (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    facility_id BIGINT UNSIGNED NOT NULL,
    capacity_type ENUM('shelter_people','hospital_beds','emergency_beds') NOT NULL,
    total_capacity INT UNSIGNED NOT NULL,
    effective_from TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    note VARCHAR(500) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_facility_default_capacities_facility_type (facility_id, capacity_type),
    CONSTRAINT fk_facility_default_capacities_facility FOREIGN KEY (facility_id) REFERENCES facilities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_facility_default_capacities_positive CHECK (total_capacity > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE facility_capacity_snapshots (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    facility_id BIGINT UNSIGNED NOT NULL,
    capacity_type ENUM('hospital_beds','emergency_beds','icu_beds') NOT NULL,
    total_capacity INT UNSIGNED NOT NULL,
    occupied_capacity INT UNSIGNED NOT NULL DEFAULT 0,
    recorded_by_user_id BIGINT UNSIGNED NULL,
    recorded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    note VARCHAR(500) NULL,
    PRIMARY KEY (id),
    KEY idx_facility_capacity_facility_type_recorded (facility_id, capacity_type, recorded_at),
    KEY idx_facility_capacity_user (recorded_by_user_id),
    CONSTRAINT fk_facility_capacity_facility FOREIGN KEY (facility_id) REFERENCES facilities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_facility_capacity_user FOREIGN KEY (recorded_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_facility_capacity_occupied_le_total CHECK (occupied_capacity <= total_capacity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE incident_facility_referrals (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    incident_id BIGINT UNSIGNED NOT NULL,
    facility_id BIGINT UNSIGNED NOT NULL,
    referred_by_user_id BIGINT UNSIGNED NOT NULL,
    referral_type ENUM('hospital_transfer','shelter_referral','blood_bank_referral','relief_center') NOT NULL,
    referral_status ENUM('recommended','accepted','rejected','completed','cancelled') NOT NULL DEFAULT 'recommended',
    reason VARCHAR(1000) NULL,
    referred_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_incident_facility_referrals_unique (incident_id, facility_id, referral_type),
    KEY idx_incident_facility_referrals_facility (facility_id),
    KEY idx_incident_facility_referrals_user (referred_by_user_id),
    CONSTRAINT fk_incident_facility_referrals_incident FOREIGN KEY (incident_id) REFERENCES emergency_incidents(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_incident_facility_referrals_facility FOREIGN KEY (facility_id) REFERENCES facilities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_incident_facility_referrals_user FOREIGN KEY (referred_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_incident_facility_referrals_completed_after_referred CHECK (completed_at IS NULL OR completed_at >= referred_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE shelter_activations (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_uuid CHAR(36) NOT NULL,
    disaster_event_id BIGINT UNSIGNED NOT NULL,
    facility_id BIGINT UNSIGNED NOT NULL,
    activated_by_user_id BIGINT UNSIGNED NOT NULL,
    activation_status ENUM('active','finalized') NOT NULL DEFAULT 'active',
    activation_source ENUM('auto','manual') NOT NULL DEFAULT 'auto',
    manual_override_note VARCHAR(1000) NULL,
    usable_capacity_override INT UNSIGNED NULL,
    managing_agency_id BIGINT UNSIGNED NULL,
    activated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finalized_at TIMESTAMP NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_shelter_activations_disaster_facility (disaster_event_id, facility_id),
    UNIQUE KEY uq_shelter_activations_public_uuid (public_uuid),
    KEY idx_shelter_activations_facility (facility_id),
    KEY idx_shelter_activations_managing_agency (managing_agency_id),
    CONSTRAINT fk_shelter_activations_disaster FOREIGN KEY (disaster_event_id) REFERENCES disaster_events(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_shelter_activations_facility FOREIGN KEY (facility_id) REFERENCES facilities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_shelter_activations_user FOREIGN KEY (activated_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_shelter_activations_agency FOREIGN KEY (managing_agency_id) REFERENCES agencies(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_shelter_activations_finalized_after_activated CHECK (finalized_at IS NULL OR finalized_at >= activated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE relief_hub_activations (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_uuid CHAR(36) NOT NULL,
    disaster_event_id BIGINT UNSIGNED NOT NULL,
    facility_id BIGINT UNSIGNED NOT NULL,
    activated_by_user_id BIGINT UNSIGNED NOT NULL,
    activation_status ENUM('active','finalized') NOT NULL DEFAULT 'active',
    activation_source ENUM('auto','manual') NOT NULL DEFAULT 'auto',
    manual_override_note VARCHAR(1000) NULL,
    managing_agency_id BIGINT UNSIGNED NULL,
    activated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finalized_at TIMESTAMP NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_relief_hub_activations_disaster_facility (disaster_event_id, facility_id),
    UNIQUE KEY uq_relief_hub_activations_public_uuid (public_uuid),
    KEY idx_relief_hub_activations_facility (facility_id),
    KEY idx_relief_hub_activations_managing_agency (managing_agency_id),
    CONSTRAINT fk_relief_hub_activations_disaster FOREIGN KEY (disaster_event_id) REFERENCES disaster_events(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_hub_activations_facility FOREIGN KEY (facility_id) REFERENCES facilities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_hub_activations_user FOREIGN KEY (activated_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_hub_activations_agency FOREIGN KEY (managing_agency_id) REFERENCES agencies(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_relief_hub_activations_finalized_after_activated CHECK (finalized_at IS NULL OR finalized_at >= activated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE shelter_occupancy_snapshots (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    shelter_activation_id BIGINT UNSIGNED NOT NULL,
    people_count INT UNSIGNED NOT NULL DEFAULT 0,
    recorded_by_user_id BIGINT UNSIGNED NULL,
    recorded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_shelter_occupancy_activation_recorded (shelter_activation_id, recorded_at),
    KEY idx_shelter_occupancy_user (recorded_by_user_id),
    CONSTRAINT fk_shelter_occupancy_activation FOREIGN KEY (shelter_activation_id) REFERENCES shelter_activations(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_shelter_occupancy_user FOREIGN KEY (recorded_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE case_resolutions (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    case_id BIGINT UNSIGNED NOT NULL,
    resolved_by_user_id BIGINT UNSIGNED NOT NULL,
    resolution_type ENUM('advice_given','referred_to_facility','escalated','no_action_needed','duplicate') NOT NULL,
    resolution_text TEXT NOT NULL,
    recommended_facility_id BIGINT UNSIGNED NULL,
    resolved_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_case_resolutions_case (case_id),
    KEY idx_case_resolutions_user (resolved_by_user_id),
    KEY idx_case_resolutions_facility (recommended_facility_id),
    CONSTRAINT fk_case_resolutions_case FOREIGN KEY (case_id) REFERENCES service_cases(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_case_resolutions_user FOREIGN KEY (resolved_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_case_resolutions_facility FOREIGN KEY (recommended_facility_id) REFERENCES facilities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_case_resolutions_text_not_blank CHECK (CHAR_LENGTH(TRIM(resolution_text)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE case_escalations (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    case_id BIGINT UNSIGNED NOT NULL,
    emergency_incident_id BIGINT UNSIGNED NOT NULL,
    escalated_by_user_id BIGINT UNSIGNED NOT NULL,
    escalation_reason VARCHAR(1000) NOT NULL,
    escalated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_case_escalations_case (case_id),
    UNIQUE KEY uq_case_escalations_case_incident (case_id, emergency_incident_id),
    KEY idx_case_escalations_incident (emergency_incident_id),
    KEY idx_case_escalations_user (escalated_by_user_id),
    CONSTRAINT fk_case_escalations_case FOREIGN KEY (case_id) REFERENCES service_cases(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_case_escalations_incident FOREIGN KEY (emergency_incident_id) REFERENCES emergency_incidents(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_case_escalations_user FOREIGN KEY (escalated_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_case_escalations_reason_not_blank CHECK (CHAR_LENGTH(TRIM(escalation_reason)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
