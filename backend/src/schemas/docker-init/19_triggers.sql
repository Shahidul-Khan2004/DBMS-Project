-- ============================================================
-- Triggers
-- ============================================================

DELIMITER $$

CREATE TRIGGER trg_case_status_history_before_insert
BEFORE INSERT ON case_status_history
FOR EACH ROW
BEGIN
    DECLARE v_current_status_id BIGINT UNSIGNED;
    DECLARE v_is_terminal BOOLEAN DEFAULT FALSE;
    DECLARE v_transition_id BIGINT UNSIGNED DEFAULT NULL;

    SELECT sc.current_status_id, cs.is_terminal
      INTO v_current_status_id, v_is_terminal
      FROM service_cases sc
      INNER JOIN case_statuses cs ON cs.id = sc.current_status_id
     WHERE sc.id = NEW.case_id
     LIMIT 1;

    IF v_current_status_id IS NULL THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Case status history: parent service case not found.';
    END IF;

    IF NEW.status_id <> v_current_status_id THEN
        IF v_is_terminal THEN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'Cannot transition case from a terminal status.';
        END IF;

        SELECT cst.id
          INTO v_transition_id
          FROM case_status_transitions cst
         WHERE cst.from_status_id = v_current_status_id
           AND cst.to_status_id = NEW.status_id
           AND cst.is_active = TRUE
         LIMIT 1;

        IF v_transition_id IS NULL THEN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'Invalid case status transition.';
        END IF;

        IF EXISTS (
            SELECT 1
              FROM case_status_transitions cst
             WHERE cst.id = v_transition_id
               AND cst.requires_note = TRUE
               AND (NEW.note IS NULL OR CHAR_LENGTH(TRIM(NEW.note)) = 0)
        ) THEN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'Case status transition requires a note.';
        END IF;
    END IF;
END$$

CREATE TRIGGER trg_incident_status_history_before_insert
BEFORE INSERT ON incident_status_history
FOR EACH ROW
BEGIN
    DECLARE v_current_status_id BIGINT UNSIGNED;
    DECLARE v_is_terminal BOOLEAN DEFAULT FALSE;
    DECLARE v_transition_id BIGINT UNSIGNED DEFAULT NULL;
    DECLARE v_requires_outcome BOOLEAN DEFAULT FALSE;

    SELECT ei.current_status_id, ist.is_terminal
      INTO v_current_status_id, v_is_terminal
      FROM emergency_incidents ei
      INNER JOIN incident_statuses ist ON ist.id = ei.current_status_id
     WHERE ei.id = NEW.incident_id
     LIMIT 1;

    IF v_current_status_id IS NULL THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Incident status history: parent incident not found.';
    END IF;

    IF NEW.status_id <> v_current_status_id THEN
        IF v_is_terminal THEN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'Cannot transition incident from a terminal status.';
        END IF;

        SELECT istt.id, istt.requires_outcome
          INTO v_transition_id, v_requires_outcome
          FROM incident_status_transitions istt
         WHERE istt.from_status_id = v_current_status_id
           AND istt.to_status_id = NEW.status_id
           AND istt.is_active = TRUE
         LIMIT 1;

        IF v_transition_id IS NULL THEN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'Invalid incident status transition.';
        END IF;

        IF EXISTS (
            SELECT 1
              FROM incident_status_transitions istt
             WHERE istt.id = v_transition_id
               AND istt.requires_note = TRUE
               AND (NEW.note IS NULL OR CHAR_LENGTH(TRIM(NEW.note)) = 0)
        ) THEN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'Incident status transition requires a note.';
        END IF;

        IF v_requires_outcome AND NEW.outcome_id IS NULL THEN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'Incident status transition requires an outcome.';
        END IF;
    END IF;
END$$

CREATE TRIGGER trg_intake_report_status_history_before_insert
BEFORE INSERT ON intake_report_status_history
FOR EACH ROW
BEGIN
    DECLARE v_current_status_id BIGINT UNSIGNED;
    DECLARE v_is_terminal BOOLEAN DEFAULT FALSE;
    DECLARE v_transition_id BIGINT UNSIGNED DEFAULT NULL;

    SELECT ir.current_status_id, ist.is_terminal
      INTO v_current_status_id, v_is_terminal
      FROM intake_reports ir
      INNER JOIN intake_statuses ist ON ist.id = ir.current_status_id
     WHERE ir.id = NEW.intake_report_id
     LIMIT 1;

    IF v_current_status_id IS NULL THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Intake status history: parent intake report not found.';
    END IF;

    IF NEW.status_id <> v_current_status_id THEN
        IF v_is_terminal THEN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'Cannot transition intake from a terminal status.';
        END IF;

        SELECT istt.id
          INTO v_transition_id
          FROM intake_status_transitions istt
         WHERE istt.from_status_id = v_current_status_id
           AND istt.to_status_id = NEW.status_id
           AND istt.is_active = TRUE
         LIMIT 1;

        IF v_transition_id IS NULL THEN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'Invalid intake status transition.';
        END IF;

        IF EXISTS (
            SELECT 1
              FROM intake_status_transitions istt
             WHERE istt.id = v_transition_id
               AND istt.requires_note = TRUE
               AND (NEW.note IS NULL OR CHAR_LENGTH(TRIM(NEW.note)) = 0)
        ) THEN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'Intake status transition requires a note.';
        END IF;
    END IF;
END$$

CREATE TRIGGER trg_dispatch_status_history_before_insert
BEFORE INSERT ON dispatch_status_history
FOR EACH ROW
BEGIN
    DECLARE v_current_status_id BIGINT UNSIGNED;
    DECLARE v_is_terminal BOOLEAN DEFAULT FALSE;
    DECLARE v_transition_id BIGINT UNSIGNED DEFAULT NULL;

    SELECT d.current_status_id, ds.is_terminal
      INTO v_current_status_id, v_is_terminal
      FROM dispatches d
      INNER JOIN dispatch_statuses ds ON ds.id = d.current_status_id
     WHERE d.id = NEW.dispatch_id
     LIMIT 1;

    IF v_current_status_id IS NULL THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Dispatch status history: parent dispatch not found.';
    END IF;

    IF NEW.status_id <> v_current_status_id THEN
        IF v_is_terminal THEN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'Cannot transition dispatch from a terminal status.';
        END IF;

        SELECT dst.id
          INTO v_transition_id
          FROM dispatch_status_transitions dst
         WHERE dst.from_status_id = v_current_status_id
           AND dst.to_status_id = NEW.status_id
           AND dst.is_active = TRUE
         LIMIT 1;

        IF v_transition_id IS NULL THEN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'Invalid dispatch status transition.';
        END IF;

        IF EXISTS (
            SELECT 1
              FROM dispatch_status_transitions dst
             WHERE dst.id = v_transition_id
               AND dst.requires_note = TRUE
               AND (NEW.note IS NULL OR CHAR_LENGTH(TRIM(NEW.note)) = 0)
        ) THEN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'Dispatch status transition requires a note.';
        END IF;
    END IF;
END$$

CREATE TRIGGER trg_unit_status_history_before_insert
BEFORE INSERT ON unit_status_history
FOR EACH ROW
BEGIN
    DECLARE v_current_status_id BIGINT UNSIGNED;
    DECLARE v_is_terminal BOOLEAN DEFAULT FALSE;
    DECLARE v_transition_id BIGINT UNSIGNED DEFAULT NULL;

    SELECT eu.current_status_id, us.is_terminal
      INTO v_current_status_id, v_is_terminal
      FROM emergency_units eu
      INNER JOIN unit_statuses us ON us.id = eu.current_status_id
     WHERE eu.id = NEW.unit_id
     LIMIT 1;

    IF v_current_status_id IS NULL THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Unit status history: parent unit not found.';
    END IF;

    IF NEW.status_id <> v_current_status_id THEN
        IF v_is_terminal THEN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'Cannot transition unit from a terminal status.';
        END IF;

        SELECT ust.id
          INTO v_transition_id
          FROM unit_status_transitions ust
         WHERE ust.from_status_id = v_current_status_id
           AND ust.to_status_id = NEW.status_id
           AND ust.is_active = TRUE
         LIMIT 1;

        IF v_transition_id IS NULL THEN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'Invalid unit status transition.';
        END IF;

        IF EXISTS (
            SELECT 1
              FROM unit_status_transitions ust
             WHERE ust.id = v_transition_id
               AND ust.requires_note = TRUE
               AND (NEW.note IS NULL OR CHAR_LENGTH(TRIM(NEW.note)) = 0)
        ) THEN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'Unit status transition requires a note.';
        END IF;
    END IF;
END$$

CREATE TRIGGER trg_intake_report_status_history_after_insert
AFTER INSERT ON intake_report_status_history
FOR EACH ROW
BEGIN
    SET @allow_intake_status_sync = TRUE;
    UPDATE intake_reports
       SET current_status_id = NEW.status_id
     WHERE id = NEW.intake_report_id;
    SET @allow_intake_status_sync = FALSE;
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
    SET @allow_case_status_sync = TRUE;
    UPDATE service_cases
       SET current_status_id = NEW.status_id
     WHERE id = NEW.case_id;
    SET @allow_case_status_sync = FALSE;
END$$

CREATE TRIGGER trg_incident_status_history_after_insert
AFTER INSERT ON incident_status_history
FOR EACH ROW
BEGIN
    DECLARE v_status_code VARCHAR(100);

    SELECT status_code INTO v_status_code
      FROM incident_statuses
     WHERE id = NEW.status_id
     LIMIT 1;

    SET @allow_incident_status_sync = TRUE;
    UPDATE emergency_incidents
       SET current_status_id = NEW.status_id,
           resolved_at = CASE
             WHEN v_status_code IN ('resolved', 'closed') AND resolved_at IS NULL
             THEN NEW.changed_at
             ELSE resolved_at
           END,
           closed_at = CASE
             WHEN v_status_code = 'closed' AND closed_at IS NULL
             THEN NEW.changed_at
             ELSE closed_at
           END,
           final_outcome_id = CASE
             WHEN NEW.outcome_id IS NOT NULL THEN NEW.outcome_id
             ELSE final_outcome_id
           END
     WHERE id = NEW.incident_id;
    SET @allow_incident_status_sync = FALSE;
END$$

CREATE TRIGGER trg_unit_status_history_after_insert
AFTER INSERT ON unit_status_history
FOR EACH ROW
BEGIN
    SET @allow_unit_status_sync = TRUE;
    UPDATE emergency_units
       SET current_status_id = NEW.status_id
     WHERE id = NEW.unit_id;
    SET @allow_unit_status_sync = FALSE;
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
    DECLARE v_status_code VARCHAR(100);

    SELECT status_code INTO v_status_code
      FROM dispatch_statuses
     WHERE id = NEW.status_id
     LIMIT 1;

    SET @allow_dispatch_status_sync = TRUE;
    UPDATE dispatches
       SET current_status_id = NEW.status_id,
           dispatched_at = CASE WHEN v_status_code = 'dispatched' AND dispatched_at IS NULL THEN NEW.changed_at ELSE dispatched_at END,
           arrived_at = CASE WHEN v_status_code = 'arrived' AND arrived_at IS NULL THEN NEW.changed_at ELSE arrived_at END,
           completed_at = CASE WHEN v_status_code = 'completed' AND completed_at IS NULL THEN NEW.changed_at ELSE completed_at END,
           cancelled_at = CASE WHEN v_status_code = 'cancelled' AND cancelled_at IS NULL THEN NEW.changed_at ELSE cancelled_at END
     WHERE id = NEW.dispatch_id;
    SET @allow_dispatch_status_sync = FALSE;
END$$

CREATE TRIGGER trg_service_cases_prevent_direct_status_update
BEFORE UPDATE ON service_cases
FOR EACH ROW
BEGIN
    IF OLD.current_status_id <> NEW.current_status_id
       AND COALESCE(@allow_case_status_sync, FALSE) = FALSE THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'service_cases.current_status_id cannot be updated directly; use case_status_history instead.';
    END IF;
END$$

CREATE TRIGGER trg_emergency_incidents_prevent_direct_status_update
BEFORE UPDATE ON emergency_incidents
FOR EACH ROW
BEGIN
    IF OLD.current_status_id <> NEW.current_status_id
       AND COALESCE(@allow_incident_status_sync, FALSE) = FALSE THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'emergency_incidents.current_status_id cannot be updated directly; use incident_status_history instead.';
    END IF;
END$$

CREATE TRIGGER trg_intake_reports_prevent_direct_status_update
BEFORE UPDATE ON intake_reports
FOR EACH ROW
BEGIN
    IF OLD.current_status_id <> NEW.current_status_id
       AND COALESCE(@allow_intake_status_sync, FALSE) = FALSE THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'intake_reports.current_status_id cannot be updated directly; use intake_report_status_history instead.';
    END IF;
END$$

CREATE TRIGGER trg_dispatches_prevent_direct_status_update
BEFORE UPDATE ON dispatches
FOR EACH ROW
BEGIN
    IF OLD.current_status_id <> NEW.current_status_id
       AND COALESCE(@allow_dispatch_status_sync, FALSE) = FALSE THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'dispatches.current_status_id cannot be updated directly; use dispatch_status_history instead.';
    END IF;
END$$

CREATE TRIGGER trg_emergency_units_prevent_direct_status_update
BEFORE UPDATE ON emergency_units
FOR EACH ROW
BEGIN
    IF OLD.current_status_id <> NEW.current_status_id
       AND COALESCE(@allow_unit_status_sync, FALSE) = FALSE THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'emergency_units.current_status_id cannot be updated directly; use unit_status_history instead.';
    END IF;
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

CREATE TRIGGER trg_disaster_event_status_history_before_insert
BEFORE INSERT ON disaster_event_status_history
FOR EACH ROW
BEGIN
    DECLARE v_current_status_id BIGINT UNSIGNED;
    DECLARE v_is_terminal BOOLEAN DEFAULT FALSE;
    DECLARE v_transition_id BIGINT UNSIGNED DEFAULT NULL;

    SELECT de.current_status_id, des.is_terminal
      INTO v_current_status_id, v_is_terminal
      FROM disaster_events de
      INNER JOIN disaster_event_statuses des ON des.id = de.current_status_id
     WHERE de.id = NEW.disaster_event_id
     LIMIT 1;

    IF v_current_status_id IS NULL THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Disaster status history: parent disaster event not found.';
    END IF;

    IF NEW.status_id <> v_current_status_id THEN
        IF v_is_terminal THEN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'Cannot transition disaster from a terminal status.';
        END IF;

        SELECT dst.id
          INTO v_transition_id
          FROM disaster_event_status_transitions dst
         WHERE dst.from_status_id = v_current_status_id
           AND dst.to_status_id = NEW.status_id
           AND dst.is_active = TRUE
         LIMIT 1;

        IF v_transition_id IS NULL THEN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'Invalid disaster status transition.';
        END IF;

        IF EXISTS (
            SELECT 1
              FROM disaster_event_status_transitions dst
             WHERE dst.id = v_transition_id
               AND dst.requires_note = TRUE
               AND (NEW.note IS NULL OR CHAR_LENGTH(TRIM(NEW.note)) = 0)
        ) THEN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'Disaster status transition requires a note.';
        END IF;
    END IF;
END$$

CREATE TRIGGER trg_disaster_event_status_history_after_insert
AFTER INSERT ON disaster_event_status_history
FOR EACH ROW
BEGIN
    DECLARE v_status_code VARCHAR(100);

    SELECT status_code INTO v_status_code
      FROM disaster_event_statuses
     WHERE id = NEW.status_id
     LIMIT 1;

    SET @allow_disaster_status_sync = TRUE;
    UPDATE disaster_events
       SET current_status_id = NEW.status_id,
           ended_at = CASE
             WHEN v_status_code IN ('closed', 'cancelled') AND ended_at IS NULL
             THEN NEW.changed_at
             ELSE ended_at
           END
     WHERE id = NEW.disaster_event_id;
    SET @allow_disaster_status_sync = FALSE;
END$$

CREATE TRIGGER trg_disaster_events_prevent_direct_status_update
BEFORE UPDATE ON disaster_events
FOR EACH ROW
BEGIN
    IF OLD.current_status_id <> NEW.current_status_id
       AND COALESCE(@allow_disaster_status_sync, FALSE) = FALSE THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'disaster_events.current_status_id cannot be updated directly; use disaster_event_status_history instead.';
    END IF;
END$$

CREATE TRIGGER trg_relief_request_status_history_before_insert
BEFORE INSERT ON relief_request_status_history
FOR EACH ROW
BEGIN
    DECLARE v_current_status_id BIGINT UNSIGNED;
    DECLARE v_is_terminal BOOLEAN DEFAULT FALSE;
    DECLARE v_transition_id BIGINT UNSIGNED DEFAULT NULL;

    SELECT rr.current_status_id, rrs.is_terminal
      INTO v_current_status_id, v_is_terminal
      FROM relief_requests rr
      INNER JOIN relief_request_statuses rrs ON rrs.id = rr.current_status_id
     WHERE rr.id = NEW.relief_request_id
     LIMIT 1;

    IF v_current_status_id IS NULL THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Relief request status history: parent request not found.';
    END IF;

    IF NEW.status_id <> v_current_status_id THEN
        IF v_is_terminal THEN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'Cannot transition relief request from a terminal status.';
        END IF;

        SELECT rst.id
          INTO v_transition_id
          FROM relief_request_status_transitions rst
         WHERE rst.from_status_id = v_current_status_id
           AND rst.to_status_id = NEW.status_id
           AND rst.is_active = TRUE
         LIMIT 1;

        IF v_transition_id IS NULL THEN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'Invalid relief request status transition.';
        END IF;

        IF EXISTS (
            SELECT 1
              FROM relief_request_status_transitions rst
             WHERE rst.id = v_transition_id
               AND rst.requires_note = TRUE
               AND (NEW.note IS NULL OR CHAR_LENGTH(TRIM(NEW.note)) = 0)
        ) THEN
            SIGNAL SQLSTATE '45000'
                SET MESSAGE_TEXT = 'Relief request status transition requires a note.';
        END IF;
    END IF;
END$$

CREATE TRIGGER trg_relief_request_status_history_after_insert
AFTER INSERT ON relief_request_status_history
FOR EACH ROW
BEGIN
    SET @allow_relief_request_status_sync = TRUE;
    UPDATE relief_requests
       SET current_status_id = NEW.status_id
     WHERE id = NEW.relief_request_id;
    SET @allow_relief_request_status_sync = FALSE;
END$$

CREATE TRIGGER trg_relief_requests_prevent_direct_status_update
BEFORE UPDATE ON relief_requests
FOR EACH ROW
BEGIN
    IF OLD.current_status_id <> NEW.current_status_id
       AND COALESCE(@allow_relief_request_status_sync, FALSE) = FALSE THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'relief_requests.current_status_id cannot be updated directly; use relief_request_status_history instead.';
    END IF;
END$$

CREATE TRIGGER trg_disaster_affected_areas_before_insert
BEFORE INSERT ON disaster_affected_areas
FOR EACH ROW
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM administrative_areas aa
         WHERE aa.id = NEW.admin_area_id
           AND aa.area_type = 'upazila'
    ) THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Disaster affected areas must reference an upazila administrative area.';
    END IF;
END$$

DELIMITER ;
