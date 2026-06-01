-- ============================================================
-- 11. Relief Distribution (BCNF — facility/shelter scoped)
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

CREATE TABLE relief_request_statuses (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    status_code VARCHAR(100) NOT NULL,
    name VARCHAR(150) NOT NULL,
    description VARCHAR(500) NULL,
    sort_order INT NOT NULL DEFAULT 0,
    is_terminal BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (id),
    UNIQUE KEY uq_relief_request_statuses_code (status_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE relief_request_status_transitions (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    from_status_id BIGINT UNSIGNED NOT NULL,
    to_status_id BIGINT UNSIGNED NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    requires_note BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (id),
    UNIQUE KEY uq_relief_request_status_transitions_from_to (from_status_id, to_status_id),
    KEY idx_relief_request_status_transitions_to (to_status_id),
    CONSTRAINT fk_rrst_from FOREIGN KEY (from_status_id) REFERENCES relief_request_statuses(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_rrst_to FOREIGN KEY (to_status_id) REFERENCES relief_request_statuses(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE relief_requests (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_uuid CHAR(36) NOT NULL,
    request_code VARCHAR(80) NOT NULL,
    disaster_event_id BIGINT UNSIGNED NOT NULL,
    shelter_activation_id BIGINT UNSIGNED NOT NULL,
    current_status_id BIGINT UNSIGNED NOT NULL,
    requested_by_user_id BIGINT UNSIGNED NOT NULL,
    requesting_agency_id BIGINT UNSIGNED NULL,
    request_note VARCHAR(1000) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_relief_requests_code (request_code),
    UNIQUE KEY uq_relief_requests_public_uuid (public_uuid),
    KEY idx_relief_requests_disaster (disaster_event_id),
    KEY idx_relief_requests_shelter (shelter_activation_id),
    KEY idx_relief_requests_status (current_status_id),
    CONSTRAINT fk_relief_requests_disaster FOREIGN KEY (disaster_event_id) REFERENCES disaster_events(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_requests_shelter FOREIGN KEY (shelter_activation_id) REFERENCES shelter_activations(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_requests_status FOREIGN KEY (current_status_id) REFERENCES relief_request_statuses(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_requests_user FOREIGN KEY (requested_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_requests_agency FOREIGN KEY (requesting_agency_id) REFERENCES agencies(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE relief_request_status_history (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    relief_request_id BIGINT UNSIGNED NOT NULL,
    status_id BIGINT UNSIGNED NOT NULL,
    changed_by_user_id BIGINT UNSIGNED NULL,
    changed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    note VARCHAR(500) NULL,
    PRIMARY KEY (id),
    KEY idx_rrsh_request_changed (relief_request_id, changed_at),
    KEY idx_rrsh_status (status_id),
    CONSTRAINT fk_rrsh_request FOREIGN KEY (relief_request_id) REFERENCES relief_requests(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_rrsh_status FOREIGN KEY (status_id) REFERENCES relief_request_statuses(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_rrsh_user FOREIGN KEY (changed_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
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

CREATE TABLE relief_stock_receipts (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_uuid CHAR(36) NOT NULL,
    relief_hub_activation_id BIGINT UNSIGNED NOT NULL,
    relief_item_id BIGINT UNSIGNED NOT NULL,
    quantity_received DECIMAL(12,2) NOT NULL,
    received_by_user_id BIGINT UNSIGNED NOT NULL,
    received_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    note VARCHAR(500) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_relief_stock_receipts_public_uuid (public_uuid),
    KEY idx_relief_stock_receipts_hub (relief_hub_activation_id),
    KEY idx_relief_stock_receipts_item (relief_item_id),
    CONSTRAINT fk_relief_stock_receipts_hub FOREIGN KEY (relief_hub_activation_id) REFERENCES relief_hub_activations(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_stock_receipts_item FOREIGN KEY (relief_item_id) REFERENCES relief_items(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_stock_receipts_user FOREIGN KEY (received_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_relief_stock_receipts_quantity_positive CHECK (quantity_received > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE relief_distributions (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_uuid CHAR(36) NOT NULL,
    distribution_code VARCHAR(80) NOT NULL,
    relief_request_id BIGINT UNSIGNED NOT NULL,
    source_hub_activation_id BIGINT UNSIGNED NOT NULL,
    destination_shelter_activation_id BIGINT UNSIGNED NOT NULL,
    distributed_by_user_id BIGINT UNSIGNED NOT NULL,
    distributed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    note VARCHAR(500) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_relief_distributions_code (distribution_code),
    UNIQUE KEY uq_relief_distributions_public_uuid (public_uuid),
    KEY idx_relief_distributions_request (relief_request_id),
    KEY idx_relief_distributions_source (source_hub_activation_id),
    KEY idx_relief_distributions_destination (destination_shelter_activation_id),
    CONSTRAINT fk_relief_distributions_request FOREIGN KEY (relief_request_id) REFERENCES relief_requests(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_distributions_source FOREIGN KEY (source_hub_activation_id) REFERENCES relief_hub_activations(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_distributions_destination FOREIGN KEY (destination_shelter_activation_id) REFERENCES shelter_activations(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_relief_distributions_user FOREIGN KEY (distributed_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE relief_distribution_items (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    relief_distribution_id BIGINT UNSIGNED NOT NULL,
    relief_item_id BIGINT UNSIGNED NOT NULL,
    quantity_delivered DECIMAL(12,2) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_relief_distribution_items_distribution_item (relief_distribution_id, relief_item_id),
    KEY idx_relief_distribution_items_item (relief_item_id),
    CONSTRAINT fk_rdi_distribution FOREIGN KEY (relief_distribution_id) REFERENCES relief_distributions(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_rdi_item FOREIGN KEY (relief_item_id) REFERENCES relief_items(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_rdi_quantity_positive CHECK (quantity_delivered > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
