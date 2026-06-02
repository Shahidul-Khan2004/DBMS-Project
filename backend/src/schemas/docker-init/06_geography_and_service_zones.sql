-- Geography tables are created before user_profiles because profiles can reference locations.

-- ============================================================
-- 2. Geography and Locations
-- ============================================================

CREATE TABLE administrative_areas (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    parent_area_id BIGINT UNSIGNED NULL,
    area_type ENUM('division','district','upazila','union','ward','area') NOT NULL,
    name VARCHAR(150) NOT NULL,
    code VARCHAR(80) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_administrative_areas_code (code),
    UNIQUE KEY uq_administrative_areas_parent_type_name (parent_area_id, area_type, name),
    KEY idx_administrative_areas_parent (parent_area_id),
    KEY idx_administrative_areas_type (area_type),
    CONSTRAINT fk_administrative_areas_parent FOREIGN KEY (parent_area_id) REFERENCES administrative_areas(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_administrative_areas_name_not_blank CHECK (CHAR_LENGTH(TRIM(name)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE locations (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_uuid CHAR(36) NOT NULL,
    admin_area_id BIGINT UNSIGNED NULL,
    latitude DECIMAL(9,6) NOT NULL,
    longitude DECIMAL(9,6) NOT NULL,
    geo_point POINT NOT NULL SRID 4326,
    address_text VARCHAR(255) NOT NULL,
    place_name VARCHAR(150) NULL,
    source ENUM('user_shared','dispatcher_selected','api_geocoded','manual_entry') NOT NULL,
    created_by_user_id BIGINT UNSIGNED NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_locations_public_uuid (public_uuid),
    KEY idx_locations_admin_area (admin_area_id),
    KEY idx_locations_created_by (created_by_user_id),
    KEY idx_locations_lat_lng (latitude, longitude),
    SPATIAL INDEX idx_locations_geo_point (geo_point),
    CONSTRAINT fk_locations_admin_area FOREIGN KEY (admin_area_id) REFERENCES administrative_areas(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_locations_created_by_user FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_locations_latitude CHECK (latitude BETWEEN -90.000000 AND 90.000000),
    CONSTRAINT chk_locations_longitude CHECK (longitude BETWEEN -180.000000 AND 180.000000),
    CONSTRAINT chk_locations_address_not_blank CHECK (CHAR_LENGTH(TRIM(address_text)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE user_profiles (
    user_id BIGINT UNSIGNED NOT NULL,
    full_name VARCHAR(150) NOT NULL,
    phone_number VARCHAR(30) NOT NULL,
    secondary_phone_number VARCHAR(30) NULL,
    preferred_language ENUM('bn','en') NOT NULL DEFAULT 'bn',
    address_location_id BIGINT UNSIGNED NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id),
    KEY idx_user_profiles_address_location (address_location_id),
    CONSTRAINT fk_user_profiles_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_user_profiles_address_location FOREIGN KEY (address_location_id) REFERENCES locations(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_user_profiles_full_name_not_blank CHECK (CHAR_LENGTH(TRIM(full_name)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE auth_tokens (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    token_hash CHAR(64) NOT NULL,
    token_type ENUM('refresh','password_reset','email_verification') NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP NULL,
    revoked_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_auth_tokens_token_hash (token_hash),
    KEY idx_auth_tokens_user_type (user_id, token_type),
    CONSTRAINT fk_auth_tokens_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT chk_auth_tokens_expires_after_created CHECK (expires_at > created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE service_zones (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    zone_code VARCHAR(100) NOT NULL,
    name VARCHAR(150) NOT NULL,
    description VARCHAR(500) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_service_zones_zone_code (zone_code),
    CONSTRAINT chk_service_zones_name_not_blank CHECK (CHAR_LENGTH(TRIM(name)) > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE service_zone_areas (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    service_zone_id BIGINT UNSIGNED NOT NULL,
    admin_area_id BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_service_zone_areas_zone_area (service_zone_id, admin_area_id),
    KEY idx_service_zone_areas_admin_area (admin_area_id),
    CONSTRAINT fk_service_zone_areas_zone FOREIGN KEY (service_zone_id) REFERENCES service_zones(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_service_zone_areas_admin_area FOREIGN KEY (admin_area_id) REFERENCES administrative_areas(id) ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE saved_locations (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_uuid CHAR(36) NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    location_id BIGINT UNSIGNED NOT NULL,
    label VARCHAR(100) NULL,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_saved_locations_public_uuid (public_uuid),
    UNIQUE KEY uq_saved_locations_user_location_active (user_id, location_id, is_deleted),
    KEY idx_saved_locations_user_active_created (user_id, is_deleted, created_at),
    KEY idx_saved_locations_location (location_id),
    CONSTRAINT fk_saved_locations_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT fk_saved_locations_location
        FOREIGN KEY (location_id) REFERENCES locations(id)
        ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;