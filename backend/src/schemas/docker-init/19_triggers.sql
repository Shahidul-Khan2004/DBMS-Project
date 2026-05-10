-- ============================================================
-- Triggers
-- ============================================================

DELIMITER $$

CREATE TRIGGER trg_intake_report_status_history_after_insert
AFTER INSERT ON intake_report_status_history
FOR EACH ROW
BEGIN
    UPDATE intake_reports
       SET intake_status = NEW.status
     WHERE id = NEW.intake_report_id;
END$$

CREATE TRIGGER trg_service_cases_before_insert
BEFORE INSERT ON service_cases
FOR EACH ROW
BEGIN
    IF NEW.parent_case_id IS NOT NULL AND NEW.id IS NOT NULL AND NEW.parent_case_id = NEW.id THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Service case cannot be its own parent.';
    END IF;
END$$

CREATE TRIGGER trg_service_cases_before_update
BEFORE UPDATE ON service_cases
FOR EACH ROW
BEGIN
    IF NEW.parent_case_id IS NOT NULL AND NEW.parent_case_id = NEW.id THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Service case cannot be its own parent.';
    END IF;
END$$

CREATE TRIGGER trg_case_status_history_after_insert
AFTER INSERT ON case_status_history
FOR EACH ROW
BEGIN
    UPDATE service_cases
       SET current_status_id = NEW.status_id
     WHERE id = NEW.case_id;
END$$

CREATE TRIGGER trg_incident_status_history_after_insert
AFTER INSERT ON incident_status_history
FOR EACH ROW
BEGIN
    UPDATE emergency_incidents
       SET current_status_id = NEW.status_id
     WHERE id = NEW.incident_id;
END$$

CREATE TRIGGER trg_unit_status_history_after_insert
AFTER INSERT ON unit_status_history
FOR EACH ROW
BEGIN
    UPDATE emergency_units
       SET current_status = NEW.status
     WHERE id = NEW.unit_id;
END$$

CREATE TRIGGER trg_dispatches_before_insert
BEFORE INSERT ON dispatches
FOR EACH ROW
BEGIN
    DECLARE v_agency_id BIGINT UNSIGNED;

    SELECT agency_id INTO v_agency_id
      FROM emergency_units
     WHERE id = NEW.unit_id;

    IF v_agency_id IS NULL THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Dispatch failed: unit_id does not reference a valid emergency unit.';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM incident_agency_participation iap
         WHERE iap.incident_id = NEW.incident_id
           AND iap.agency_id = v_agency_id
           AND iap.participation_status IN ('requested','active')
    ) THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Dispatch failed: unit agency is not participating in this incident.';
    END IF;
END$$

CREATE TRIGGER trg_dispatches_before_update
BEFORE UPDATE ON dispatches
FOR EACH ROW
BEGIN
    DECLARE v_agency_id BIGINT UNSIGNED;

    SELECT agency_id INTO v_agency_id
      FROM emergency_units
     WHERE id = NEW.unit_id;

    IF v_agency_id IS NULL THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Dispatch update failed: unit_id does not reference a valid emergency unit.';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM incident_agency_participation iap
         WHERE iap.incident_id = NEW.incident_id
           AND iap.agency_id = v_agency_id
           AND iap.participation_status IN ('requested','active')
    ) THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Dispatch update failed: unit agency is not participating in this incident.';
    END IF;
END$$

CREATE TRIGGER trg_dispatch_status_history_after_insert
AFTER INSERT ON dispatch_status_history
FOR EACH ROW
BEGIN
    UPDATE dispatches
       SET dispatch_status = NEW.status,
           dispatched_at = CASE WHEN NEW.status = 'dispatched' AND dispatched_at IS NULL THEN NEW.changed_at ELSE dispatched_at END,
           arrived_at = CASE WHEN NEW.status = 'arrived' AND arrived_at IS NULL THEN NEW.changed_at ELSE arrived_at END,
           completed_at = CASE WHEN NEW.status = 'completed' AND completed_at IS NULL THEN NEW.changed_at ELSE completed_at END,
           cancelled_at = CASE WHEN NEW.status = 'cancelled' AND cancelled_at IS NULL THEN NEW.changed_at ELSE cancelled_at END
     WHERE id = NEW.dispatch_id;
END$$

CREATE TRIGGER trg_incident_location_history_after_insert
AFTER INSERT ON incident_location_history
FOR EACH ROW
BEGIN
    IF NEW.is_current THEN
        UPDATE incident_location_history
           SET is_current = FALSE
         WHERE incident_id = NEW.incident_id
           AND id <> NEW.id
           AND is_current = TRUE;

        UPDATE emergency_incidents
           SET current_location_id = NEW.location_id
         WHERE id = NEW.incident_id;
    END IF;
END$$

-- locations.geo_point: always derived from longitude/latitude (SRID 4326). INSERT may omit geo_point;
-- BEFORE INSERT assigns it. BEFORE UPDATE overwrites geo_point so ad-hoc edits to only geo_point cannot drift from lat/lng.
CREATE TRIGGER trg_locations_before_insert
BEFORE INSERT ON locations
FOR EACH ROW
BEGIN
    SET NEW.geo_point = ST_SRID(POINT(NEW.longitude, NEW.latitude), 4326);
END$$

CREATE TRIGGER trg_locations_before_update
BEFORE UPDATE ON locations
FOR EACH ROW
BEGIN
    SET NEW.geo_point = ST_SRID(POINT(NEW.longitude, NEW.latitude), 4326);
END$$

DELIMITER ;
