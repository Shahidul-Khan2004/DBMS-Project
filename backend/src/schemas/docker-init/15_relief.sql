-- ============================================================
-- 11. Relief Collection and Distribution
-- ============================================================

CREATE TABLE relief_items (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    item_code VARCHAR(100) NOT NULL,
    name VARCHAR(150) NOT NULL,
    unit_of_measure VARCHAR(50) NOT NULL,
    description VARCHAR(500) NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (id),
    UNIQUE KEY uq_relief_items_code (item_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE facility_relief_inventory (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    facility_id BIGINT UNSIGNED NOT NULL,
    relief_item_id BIGINT UNSIGNED NOT NULL,
    quantity_available DECIMAL(12,2) NOT NULL DEFAULT 0,
    last_updated_by_user_id BIGINT UNSIGNED NULL,
    last_updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_facility_relief_inventory_facility_item (facility_id, relief_item_id),
    KEY idx_facility_relief_inventory_item (relief_item_id),
    KEY idx_facility_relief_inventory_user (last_updated_by_user_id),
    CONSTRAINT fk_fri_facility FOREIGN KEY (facility_id) REFERENCES facilities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_fri_item FOREIGN KEY (relief_item_id) REFERENCES relief_items(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_fri_user FOREIGN KEY (last_updated_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_fri_quantity_nonnegative CHECK (quantity_available >= 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE relief_requests (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    request_code VARCHAR(80) NOT NULL,
    disaster_event_id BIGINT UNSIGNED NULL,
    incident_id BIGINT UNSIGNED NULL,
    requested_by_user_id BIGINT UNSIGNED NOT NULL,
    requesting_agency_id BIGINT UNSIGNED NULL,
    target_location_id BIGINT UNSIGNED NOT NULL,
    priority_level ENUM('low','medium','high','critical') NOT NULL DEFAULT 'medium',
    request_status ENUM('submitted','approved','partially_fulfilled','fulfilled','cancelled') NOT NULL DEFAULT 'submitted',
    needed_by TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_relief_requests_code (request_code),
    KEY idx_relief_requests_disaster (disaster_event_id),
    KEY idx_relief_requests_incident (incident_id),
    KEY idx_relief_requests_location (target_location_id),
    KEY idx_relief_requests_status_priority (request_status, priority_level),
    CONSTRAINT fk_relief_requests_disaster FOREIGN KEY (disaster_event_id) REFERENCES disaster_events(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_requests_incident FOREIGN KEY (incident_id) REFERENCES emergency_incidents(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_requests_user FOREIGN KEY (requested_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_requests_agency FOREIGN KEY (requesting_agency_id) REFERENCES agencies(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_requests_location FOREIGN KEY (target_location_id) REFERENCES locations(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_relief_requests_has_context CHECK (disaster_event_id IS NOT NULL OR incident_id IS NOT NULL)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE relief_request_items (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    relief_request_id BIGINT UNSIGNED NOT NULL,
    relief_item_id BIGINT UNSIGNED NOT NULL,
    quantity_requested DECIMAL(12,2) NOT NULL,
    note VARCHAR(500) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_relief_request_items_request_item (relief_request_id, relief_item_id),
    KEY idx_relief_request_items_item (relief_item_id),
    CONSTRAINT fk_rri_request FOREIGN KEY (relief_request_id) REFERENCES relief_requests(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_rri_item FOREIGN KEY (relief_item_id) REFERENCES relief_items(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_rri_quantity_positive CHECK (quantity_requested > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE relief_distributions (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    distribution_code VARCHAR(80) NOT NULL,
    relief_request_id BIGINT UNSIGNED NULL,
    source_facility_id BIGINT UNSIGNED NOT NULL,
    target_location_id BIGINT UNSIGNED NOT NULL,
    distributed_by_agency_id BIGINT UNSIGNED NULL,
    distributed_by_user_id BIGINT UNSIGNED NULL,
    distribution_status ENUM('planned','in_transit','delivered','cancelled') NOT NULL DEFAULT 'planned',
    distributed_at TIMESTAMP NULL,
    delivered_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_relief_distributions_code (distribution_code),
    KEY idx_relief_distributions_request (relief_request_id),
    KEY idx_relief_distributions_source (source_facility_id),
    KEY idx_relief_distributions_target (target_location_id),
    CONSTRAINT fk_relief_distributions_request FOREIGN KEY (relief_request_id) REFERENCES relief_requests(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_distributions_source FOREIGN KEY (source_facility_id) REFERENCES facilities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_distributions_target FOREIGN KEY (target_location_id) REFERENCES locations(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_distributions_agency FOREIGN KEY (distributed_by_agency_id) REFERENCES agencies(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_distributions_user FOREIGN KEY (distributed_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_relief_distributions_delivered_after_distributed CHECK (delivered_at IS NULL OR distributed_at IS NULL OR delivered_at >= distributed_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE relief_distribution_items (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    relief_distribution_id BIGINT UNSIGNED NOT NULL,
    relief_item_id BIGINT UNSIGNED NOT NULL,
    quantity_distributed DECIMAL(12,2) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_relief_distribution_items_distribution_item (relief_distribution_id, relief_item_id),
    KEY idx_relief_distribution_items_item (relief_item_id),
    CONSTRAINT fk_rdi_distribution FOREIGN KEY (relief_distribution_id) REFERENCES relief_distributions(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_rdi_item FOREIGN KEY (relief_item_id) REFERENCES relief_items(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_rdi_quantity_positive CHECK (quantity_distributed > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE relief_collection_campaigns (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    campaign_code VARCHAR(80) NOT NULL,
    disaster_event_id BIGINT UNSIGNED NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NULL,
    campaign_status ENUM('planned','active','paused','completed','cancelled') NOT NULL DEFAULT 'planned',
    starts_at TIMESTAMP NOT NULL,
    ends_at TIMESTAMP NULL,
    created_by_user_id BIGINT UNSIGNED NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_relief_campaigns_code (campaign_code),
    KEY idx_relief_campaigns_disaster (disaster_event_id),
    KEY idx_relief_campaigns_user (created_by_user_id),
    CONSTRAINT fk_relief_campaigns_disaster FOREIGN KEY (disaster_event_id) REFERENCES disaster_events(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_campaigns_user FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_relief_campaigns_title_not_blank CHECK (CHAR_LENGTH(TRIM(title)) > 0),
    CONSTRAINT chk_relief_campaigns_end_after_start CHECK (ends_at IS NULL OR ends_at >= starts_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE relief_collection_points (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    campaign_id BIGINT UNSIGNED NOT NULL,
    facility_id BIGINT UNSIGNED NULL,
    location_id BIGINT UNSIGNED NOT NULL,
    name VARCHAR(180) NOT NULL,
    contact_phone VARCHAR(30) NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_relief_collection_points_campaign (campaign_id),
    KEY idx_relief_collection_points_facility (facility_id),
    KEY idx_relief_collection_points_location (location_id),
    CONSTRAINT fk_relief_collection_points_campaign FOREIGN KEY (campaign_id) REFERENCES relief_collection_campaigns(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_collection_points_facility FOREIGN KEY (facility_id) REFERENCES facilities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_collection_points_location FOREIGN KEY (location_id) REFERENCES locations(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_relief_collection_points_name_not_blank CHECK (CHAR_LENGTH(TRIM(name)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE relief_donations (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    donation_code VARCHAR(80) NOT NULL,
    campaign_id BIGINT UNSIGNED NULL,
    collection_point_id BIGINT UNSIGNED NULL,
    donor_user_id BIGINT UNSIGNED NULL,
    donor_contact_id BIGINT UNSIGNED NULL,
    received_by_user_id BIGINT UNSIGNED NULL,
    donation_status ENUM('pledged','received','verified','rejected') NOT NULL DEFAULT 'pledged',
    received_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_relief_donations_code (donation_code),
    KEY idx_relief_donations_campaign (campaign_id),
    KEY idx_relief_donations_point (collection_point_id),
    KEY idx_relief_donations_donor_user (donor_user_id),
    KEY idx_relief_donations_donor_contact (donor_contact_id),
    CONSTRAINT fk_relief_donations_campaign FOREIGN KEY (campaign_id) REFERENCES relief_collection_campaigns(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_donations_point FOREIGN KEY (collection_point_id) REFERENCES relief_collection_points(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_donations_donor_user FOREIGN KEY (donor_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_donations_donor_contact FOREIGN KEY (donor_contact_id) REFERENCES reporter_contacts(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_donations_received_by FOREIGN KEY (received_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE relief_donation_items (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    donation_id BIGINT UNSIGNED NOT NULL,
    relief_item_id BIGINT UNSIGNED NOT NULL,
    quantity_donated DECIMAL(12,2) NOT NULL,
    condition_note VARCHAR(500) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_relief_donation_items_donation_item (donation_id, relief_item_id),
    KEY idx_relief_donation_items_item (relief_item_id),
    CONSTRAINT fk_relief_donation_items_donation FOREIGN KEY (donation_id) REFERENCES relief_donations(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_donation_items_item FOREIGN KEY (relief_item_id) REFERENCES relief_items(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_relief_donation_items_quantity_positive CHECK (quantity_donated > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
