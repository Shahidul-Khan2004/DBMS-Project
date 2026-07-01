CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_users_updated_at ON users;
CREATE TRIGGER trg_users_updated_at
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS trg_user_profiles_updated_at ON user_profiles;
CREATE TRIGGER trg_user_profiles_updated_at
BEFORE UPDATE ON user_profiles
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS trg_service_cases_updated_at ON service_cases;
CREATE TRIGGER trg_service_cases_updated_at
BEFORE UPDATE ON service_cases
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS trg_intake_reports_updated_at ON intake_reports;
CREATE TRIGGER trg_intake_reports_updated_at
BEFORE UPDATE ON intake_reports
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS trg_emergency_incidents_updated_at ON emergency_incidents;
CREATE TRIGGER trg_emergency_incidents_updated_at
BEFORE UPDATE ON emergency_incidents
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS trg_dispatches_updated_at ON dispatches;
CREATE TRIGGER trg_dispatches_updated_at
BEFORE UPDATE ON dispatches
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS trg_emergency_units_updated_at ON emergency_units;
CREATE TRIGGER trg_emergency_units_updated_at
BEFORE UPDATE ON emergency_units
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS trg_disaster_events_updated_at ON disaster_events;
CREATE TRIGGER trg_disaster_events_updated_at
BEFORE UPDATE ON disaster_events
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS trg_relief_requests_updated_at ON relief_requests;
CREATE TRIGGER trg_relief_requests_updated_at
BEFORE UPDATE ON relief_requests
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS trg_facilities_updated_at ON facilities;
CREATE TRIGGER trg_facilities_updated_at
BEFORE UPDATE ON facilities
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS trg_shelter_activations_updated_at ON shelter_activations;
CREATE TRIGGER trg_shelter_activations_updated_at
BEFORE UPDATE ON shelter_activations
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS trg_relief_hub_activations_updated_at ON relief_hub_activations;
CREATE TRIGGER trg_relief_hub_activations_updated_at
BEFORE UPDATE ON relief_hub_activations
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();


CREATE OR REPLACE FUNCTION trg_case_status_history_before_insert_fn()
RETURNS TRIGGER AS $$
DECLARE
  v_current_status_id BIGINT;
  v_is_terminal BOOLEAN := FALSE;
  v_transition_id BIGINT := NULL;
BEGIN
  SELECT sc.current_status_id, cs.is_terminal
  INTO v_current_status_id, v_is_terminal
  FROM service_cases sc
  INNER JOIN case_statuses cs ON cs.id = sc.current_status_id
  WHERE sc.id = NEW.case_id
  LIMIT 1;
  IF v_current_status_id IS NULL THEN
  RAISE EXCEPTION 'Case status history: parent service case not found.';
  END IF;
  IF NEW.status_id <> v_current_status_id THEN
  IF v_is_terminal THEN
  RAISE EXCEPTION 'Cannot transition case from a terminal status.';
  END IF;
  SELECT cst.id
  INTO v_transition_id
  FROM case_status_transitions cst
  WHERE cst.from_status_id = v_current_status_id
  AND cst.to_status_id = NEW.status_id
  AND cst.is_active = TRUE
  LIMIT 1;
  IF v_transition_id IS NULL THEN
  RAISE EXCEPTION 'Invalid case status transition.';
  END IF;
  IF EXISTS (
  SELECT 1
  FROM case_status_transitions cst
  WHERE cst.id = v_transition_id
  AND cst.requires_note = TRUE
  AND (NEW.note IS NULL OR CHAR_LENGTH(TRIM(NEW.note)) = 0)
  ) THEN
  RAISE EXCEPTION 'Case status transition requires a note.';
  END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_case_status_history_before_insert
BEFORE INSERT ON case_status_history
FOR EACH ROW
EXECUTE FUNCTION trg_case_status_history_before_insert_fn();

CREATE OR REPLACE FUNCTION trg_incident_status_history_before_insert_fn()
RETURNS TRIGGER AS $$
DECLARE
  v_current_status_id BIGINT;
  v_is_terminal BOOLEAN := FALSE;
  v_transition_id BIGINT := NULL;
  v_requires_outcome BOOLEAN := FALSE;
BEGIN
  SELECT ei.current_status_id, ist.is_terminal
  INTO v_current_status_id, v_is_terminal
  FROM emergency_incidents ei
  INNER JOIN incident_statuses ist ON ist.id = ei.current_status_id
  WHERE ei.id = NEW.incident_id
  LIMIT 1;
  IF v_current_status_id IS NULL THEN
  RAISE EXCEPTION 'Incident status history: parent incident not found.';
  END IF;
  IF NEW.status_id <> v_current_status_id THEN
  IF v_is_terminal THEN
  RAISE EXCEPTION 'Cannot transition incident from a terminal status.';
  END IF;
  SELECT istt.id, istt.requires_outcome
  INTO v_transition_id, v_requires_outcome
  FROM incident_status_transitions istt
  WHERE istt.from_status_id = v_current_status_id
  AND istt.to_status_id = NEW.status_id
  AND istt.is_active = TRUE
  LIMIT 1;
  IF v_transition_id IS NULL THEN
  RAISE EXCEPTION 'Invalid incident status transition.';
  END IF;
  IF EXISTS (
  SELECT 1
  FROM incident_status_transitions istt
  WHERE istt.id = v_transition_id
  AND istt.requires_note = TRUE
  AND (NEW.note IS NULL OR CHAR_LENGTH(TRIM(NEW.note)) = 0)
  ) THEN
  RAISE EXCEPTION 'Incident status transition requires a note.';
  END IF;
  IF v_requires_outcome AND NEW.outcome_id IS NULL THEN
  RAISE EXCEPTION 'Incident status transition requires an outcome.';
  END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_incident_status_history_before_insert
BEFORE INSERT ON incident_status_history
FOR EACH ROW
EXECUTE FUNCTION trg_incident_status_history_before_insert_fn();

CREATE OR REPLACE FUNCTION trg_intake_report_status_history_before_insert_fn()
RETURNS TRIGGER AS $$
DECLARE
  v_current_status_id BIGINT;
  v_is_terminal BOOLEAN := FALSE;
  v_transition_id BIGINT := NULL;
BEGIN
  SELECT ir.current_status_id, ist.is_terminal
  INTO v_current_status_id, v_is_terminal
  FROM intake_reports ir
  INNER JOIN intake_statuses ist ON ist.id = ir.current_status_id
  WHERE ir.id = NEW.intake_report_id
  LIMIT 1;
  IF v_current_status_id IS NULL THEN
  RAISE EXCEPTION 'Intake status history: parent intake report not found.';
  END IF;
  IF NEW.status_id <> v_current_status_id THEN
  IF v_is_terminal THEN
  RAISE EXCEPTION 'Cannot transition intake from a terminal status.';
  END IF;
  SELECT istt.id
  INTO v_transition_id
  FROM intake_status_transitions istt
  WHERE istt.from_status_id = v_current_status_id
  AND istt.to_status_id = NEW.status_id
  AND istt.is_active = TRUE
  LIMIT 1;
  IF v_transition_id IS NULL THEN
  RAISE EXCEPTION 'Invalid intake status transition.';
  END IF;
  IF EXISTS (
  SELECT 1
  FROM intake_status_transitions istt
  WHERE istt.id = v_transition_id
  AND istt.requires_note = TRUE
  AND (NEW.note IS NULL OR CHAR_LENGTH(TRIM(NEW.note)) = 0)
  ) THEN
  RAISE EXCEPTION 'Intake status transition requires a note.';
  END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_intake_report_status_history_before_insert
BEFORE INSERT ON intake_report_status_history
FOR EACH ROW
EXECUTE FUNCTION trg_intake_report_status_history_before_insert_fn();

CREATE OR REPLACE FUNCTION trg_dispatch_status_history_before_insert_fn()
RETURNS TRIGGER AS $$
DECLARE
  v_current_status_id BIGINT;
  v_is_terminal BOOLEAN := FALSE;
  v_transition_id BIGINT := NULL;
BEGIN
  SELECT d.current_status_id, ds.is_terminal
  INTO v_current_status_id, v_is_terminal
  FROM dispatches d
  INNER JOIN dispatch_statuses ds ON ds.id = d.current_status_id
  WHERE d.id = NEW.dispatch_id
  LIMIT 1;
  IF v_current_status_id IS NULL THEN
  RAISE EXCEPTION 'Dispatch status history: parent dispatch not found.';
  END IF;
  IF NEW.status_id <> v_current_status_id THEN
  IF v_is_terminal THEN
  RAISE EXCEPTION 'Cannot transition dispatch from a terminal status.';
  END IF;
  SELECT dst.id
  INTO v_transition_id
  FROM dispatch_status_transitions dst
  WHERE dst.from_status_id = v_current_status_id
  AND dst.to_status_id = NEW.status_id
  AND dst.is_active = TRUE
  LIMIT 1;
  IF v_transition_id IS NULL THEN
  RAISE EXCEPTION 'Invalid dispatch status transition.';
  END IF;
  IF EXISTS (
  SELECT 1
  FROM dispatch_status_transitions dst
  WHERE dst.id = v_transition_id
  AND dst.requires_note = TRUE
  AND (NEW.note IS NULL OR CHAR_LENGTH(TRIM(NEW.note)) = 0)
  ) THEN
  RAISE EXCEPTION 'Dispatch status transition requires a note.';
  END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_dispatch_status_history_before_insert
BEFORE INSERT ON dispatch_status_history
FOR EACH ROW
EXECUTE FUNCTION trg_dispatch_status_history_before_insert_fn();

CREATE OR REPLACE FUNCTION trg_unit_status_history_before_insert_fn()
RETURNS TRIGGER AS $$
DECLARE
  v_current_status_id BIGINT;
  v_is_terminal BOOLEAN := FALSE;
  v_transition_id BIGINT := NULL;
BEGIN
  SELECT eu.current_status_id, us.is_terminal
  INTO v_current_status_id, v_is_terminal
  FROM emergency_units eu
  INNER JOIN unit_statuses us ON us.id = eu.current_status_id
  WHERE eu.id = NEW.unit_id
  LIMIT 1;
  IF v_current_status_id IS NULL THEN
  RAISE EXCEPTION 'Unit status history: parent unit not found.';
  END IF;
  IF NEW.status_id <> v_current_status_id THEN
  IF v_is_terminal THEN
  RAISE EXCEPTION 'Cannot transition unit from a terminal status.';
  END IF;
  SELECT ust.id
  INTO v_transition_id
  FROM unit_status_transitions ust
  WHERE ust.from_status_id = v_current_status_id
  AND ust.to_status_id = NEW.status_id
  AND ust.is_active = TRUE
  LIMIT 1;
  IF v_transition_id IS NULL THEN
  RAISE EXCEPTION 'Invalid unit status transition.';
  END IF;
  IF EXISTS (
  SELECT 1
  FROM unit_status_transitions ust
  WHERE ust.id = v_transition_id
  AND ust.requires_note = TRUE
  AND (NEW.note IS NULL OR CHAR_LENGTH(TRIM(NEW.note)) = 0)
  ) THEN
  RAISE EXCEPTION 'Unit status transition requires a note.';
  END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_unit_status_history_before_insert
BEFORE INSERT ON unit_status_history
FOR EACH ROW
EXECUTE FUNCTION trg_unit_status_history_before_insert_fn();

CREATE OR REPLACE FUNCTION trg_intake_report_status_history_after_insert_fn()
RETURNS TRIGGER AS $$
BEGIN
  PERFORM set_config('niers.allow_intake_status_sync', 'on', true);
  UPDATE intake_reports
  SET current_status_id = NEW.status_id
  WHERE id = NEW.intake_report_id;
  PERFORM set_config('niers.allow_intake_status_sync', 'off', true);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_intake_report_status_history_after_insert
AFTER INSERT ON intake_report_status_history
FOR EACH ROW
EXECUTE FUNCTION trg_intake_report_status_history_after_insert_fn();

CREATE OR REPLACE FUNCTION trg_service_cases_before_insert_fn()
RETURNS TRIGGER AS $$
BEGIN
  IF NEW.parent_case_id IS NOT NULL AND NEW.id IS NOT NULL AND NEW.parent_case_id = NEW.id THEN
  RAISE EXCEPTION 'Service case cannot be its own parent.';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_service_cases_before_insert
BEFORE INSERT ON service_cases
FOR EACH ROW
EXECUTE FUNCTION trg_service_cases_before_insert_fn();

CREATE OR REPLACE FUNCTION trg_service_cases_before_update_fn()
RETURNS TRIGGER AS $$
BEGIN
  IF NEW.parent_case_id IS NOT NULL AND NEW.parent_case_id = NEW.id THEN
  RAISE EXCEPTION 'Service case cannot be its own parent.';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_service_cases_before_update
BEFORE UPDATE ON service_cases
FOR EACH ROW
EXECUTE FUNCTION trg_service_cases_before_update_fn();

CREATE OR REPLACE FUNCTION trg_case_status_history_after_insert_fn()
RETURNS TRIGGER AS $$
BEGIN
  PERFORM set_config('niers.allow_case_status_sync', 'on', true);
  UPDATE service_cases
  SET current_status_id = NEW.status_id
  WHERE id = NEW.case_id;
  PERFORM set_config('niers.allow_case_status_sync', 'off', true);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_case_status_history_after_insert
AFTER INSERT ON case_status_history
FOR EACH ROW
EXECUTE FUNCTION trg_case_status_history_after_insert_fn();

CREATE OR REPLACE FUNCTION trg_incident_status_history_after_insert_fn()
RETURNS TRIGGER AS $$
DECLARE
  v_status_code VARCHAR(100);
BEGIN
  SELECT status_code INTO v_status_code
  FROM incident_statuses
  WHERE id = NEW.status_id
  LIMIT 1;
  PERFORM set_config('niers.allow_incident_status_sync', 'on', true);
  UPDATE emergency_incidents
  SET current_status_id = NEW.status_id,
  resolved_at = CASE
  WHEN v_status_code IN ('resolved', 'closed') AND resolved_at IS NULL
  THEN NEW.changed_at
  ELSE resolved_at
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_incident_status_history_after_insert
AFTER INSERT ON incident_status_history
FOR EACH ROW
EXECUTE FUNCTION trg_incident_status_history_after_insert_fn();

CREATE OR REPLACE FUNCTION trg_unit_status_history_after_insert_fn()
RETURNS TRIGGER AS $$
BEGIN
  PERFORM set_config('niers.allow_unit_status_sync', 'on', true);
  UPDATE emergency_units
  SET current_status_id = NEW.status_id
  WHERE id = NEW.unit_id;
  PERFORM set_config('niers.allow_unit_status_sync', 'off', true);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_unit_status_history_after_insert
AFTER INSERT ON unit_status_history
FOR EACH ROW
EXECUTE FUNCTION trg_unit_status_history_after_insert_fn();

CREATE OR REPLACE FUNCTION trg_dispatches_before_insert_fn()
RETURNS TRIGGER AS $$
DECLARE
  v_agency_id BIGINT;
BEGIN
  SELECT agency_id INTO v_agency_id
  FROM emergency_units
  WHERE id = NEW.unit_id;
  IF v_agency_id IS NULL THEN
  RAISE EXCEPTION 'Dispatch failed: unit_id does not reference a valid emergency unit.';
  END IF;
  IF NOT EXISTS (
  SELECT 1
  FROM incident_agency_participation iap
  WHERE iap.incident_id = NEW.incident_id
  AND iap.agency_id = v_agency_id
  AND iap.participation_status IN ('requested','active')
  ) THEN
  RAISE EXCEPTION 'Dispatch failed: unit agency is not participating in this incident.';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_dispatches_before_insert
BEFORE INSERT ON dispatches
FOR EACH ROW
EXECUTE FUNCTION trg_dispatches_before_insert_fn();

CREATE OR REPLACE FUNCTION trg_dispatches_before_update_fn()
RETURNS TRIGGER AS $$
DECLARE
  v_agency_id BIGINT;
BEGIN
  SELECT agency_id INTO v_agency_id
  FROM emergency_units
  WHERE id = NEW.unit_id;
  IF v_agency_id IS NULL THEN
  RAISE EXCEPTION 'Dispatch update failed: unit_id does not reference a valid emergency unit.';
  END IF;
  IF NOT EXISTS (
  SELECT 1
  FROM incident_agency_participation iap
  WHERE iap.incident_id = NEW.incident_id
  AND iap.agency_id = v_agency_id
  AND iap.participation_status IN ('requested','active')
  ) THEN
  RAISE EXCEPTION 'Dispatch update failed: unit agency is not participating in this incident.';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_dispatches_before_update
BEFORE UPDATE ON dispatches
FOR EACH ROW
EXECUTE FUNCTION trg_dispatches_before_update_fn();

CREATE OR REPLACE FUNCTION trg_dispatch_status_history_after_insert_fn()
RETURNS TRIGGER AS $$
DECLARE
  v_status_code VARCHAR(100);
BEGIN
  SELECT status_code INTO v_status_code
  FROM dispatch_statuses
  WHERE id = NEW.status_id
  LIMIT 1;
  PERFORM set_config('niers.allow_dispatch_status_sync', 'on', true);
  UPDATE dispatches
  SET current_status_id = NEW.status_id,
  dispatched_at = CASE WHEN v_status_code = 'dispatched' AND dispatched_at IS NULL THEN NEW.changed_at ELSE dispatched_at
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_dispatch_status_history_after_insert
AFTER INSERT ON dispatch_status_history
FOR EACH ROW
EXECUTE FUNCTION trg_dispatch_status_history_after_insert_fn();

CREATE OR REPLACE FUNCTION trg_service_cases_prevent_direct_status_update_fn()
RETURNS TRIGGER AS $$
BEGIN
  IF OLD.current_status_id <> NEW.current_status_id
  AND COALESCE(current_setting('niers.allow_case_status_sync', true), 'off') <> 'on' THEN
  RAISE EXCEPTION 'service_cases.current_status_id cannot be updated directly; use case_status_history instead.';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_service_cases_prevent_direct_status_update
BEFORE UPDATE ON service_cases
FOR EACH ROW
EXECUTE FUNCTION trg_service_cases_prevent_direct_status_update_fn();

CREATE OR REPLACE FUNCTION trg_emergency_incidents_prevent_direct_status_update_fn()
RETURNS TRIGGER AS $$
BEGIN
  IF OLD.current_status_id <> NEW.current_status_id
  AND COALESCE(current_setting('niers.allow_incident_status_sync', true), 'off') <> 'on' THEN
  RAISE EXCEPTION 'emergency_incidents.current_status_id cannot be updated directly; use incident_status_history instead.';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_emergency_incidents_prevent_direct_status_update
BEFORE UPDATE ON emergency_incidents
FOR EACH ROW
EXECUTE FUNCTION trg_emergency_incidents_prevent_direct_status_update_fn();

CREATE OR REPLACE FUNCTION trg_intake_reports_prevent_direct_status_update_fn()
RETURNS TRIGGER AS $$
BEGIN
  IF OLD.current_status_id <> NEW.current_status_id
  AND COALESCE(current_setting('niers.allow_intake_status_sync', true), 'off') <> 'on' THEN
  RAISE EXCEPTION 'intake_reports.current_status_id cannot be updated directly; use intake_report_status_history instead.';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_intake_reports_prevent_direct_status_update
BEFORE UPDATE ON intake_reports
FOR EACH ROW
EXECUTE FUNCTION trg_intake_reports_prevent_direct_status_update_fn();

CREATE OR REPLACE FUNCTION trg_dispatches_prevent_direct_status_update_fn()
RETURNS TRIGGER AS $$
BEGIN
  IF OLD.current_status_id <> NEW.current_status_id
  AND COALESCE(current_setting('niers.allow_dispatch_status_sync', true), 'off') <> 'on' THEN
  RAISE EXCEPTION 'dispatches.current_status_id cannot be updated directly; use dispatch_status_history instead.';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_dispatches_prevent_direct_status_update
BEFORE UPDATE ON dispatches
FOR EACH ROW
EXECUTE FUNCTION trg_dispatches_prevent_direct_status_update_fn();

CREATE OR REPLACE FUNCTION trg_emergency_units_prevent_direct_status_update_fn()
RETURNS TRIGGER AS $$
BEGIN
  IF OLD.current_status_id <> NEW.current_status_id
  AND COALESCE(current_setting('niers.allow_unit_status_sync', true), 'off') <> 'on' THEN
  RAISE EXCEPTION 'emergency_units.current_status_id cannot be updated directly; use unit_status_history instead.';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_emergency_units_prevent_direct_status_update
BEFORE UPDATE ON emergency_units
FOR EACH ROW
EXECUTE FUNCTION trg_emergency_units_prevent_direct_status_update_fn();

CREATE OR REPLACE FUNCTION trg_incident_location_history_after_insert_fn()
RETURNS TRIGGER AS $$
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
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_incident_location_history_after_insert
AFTER INSERT ON incident_location_history
FOR EACH ROW
EXECUTE FUNCTION trg_incident_location_history_after_insert_fn();

CREATE OR REPLACE FUNCTION trg_locations_before_insert_fn()
RETURNS TRIGGER AS $$
BEGIN
  NEW.geo_point := ST_SetSRID(ST_MakePoint(NEW.longitude, NEW.latitude), 4326)::geography;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_locations_before_insert
BEFORE INSERT ON locations
FOR EACH ROW
EXECUTE FUNCTION trg_locations_before_insert_fn();

CREATE OR REPLACE FUNCTION trg_locations_before_update_fn()
RETURNS TRIGGER AS $$
BEGIN
  NEW.geo_point := ST_SetSRID(ST_MakePoint(NEW.longitude, NEW.latitude), 4326)::geography;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_locations_before_update
BEFORE UPDATE ON locations
FOR EACH ROW
EXECUTE FUNCTION trg_locations_before_update_fn();

CREATE OR REPLACE FUNCTION trg_disaster_event_status_history_before_insert_fn()
RETURNS TRIGGER AS $$
DECLARE
  v_current_status_id BIGINT;
  v_is_terminal BOOLEAN := FALSE;
  v_transition_id BIGINT := NULL;
BEGIN
  SELECT de.current_status_id, des.is_terminal
  INTO v_current_status_id, v_is_terminal
  FROM disaster_events de
  INNER JOIN disaster_event_statuses des ON des.id = de.current_status_id
  WHERE de.id = NEW.disaster_event_id
  LIMIT 1;
  IF v_current_status_id IS NULL THEN
  RAISE EXCEPTION 'Disaster status history: parent disaster event not found.';
  END IF;
  IF NEW.status_id <> v_current_status_id THEN
  IF v_is_terminal THEN
  RAISE EXCEPTION 'Cannot transition disaster from a terminal status.';
  END IF;
  SELECT dst.id
  INTO v_transition_id
  FROM disaster_event_status_transitions dst
  WHERE dst.from_status_id = v_current_status_id
  AND dst.to_status_id = NEW.status_id
  AND dst.is_active = TRUE
  LIMIT 1;
  IF v_transition_id IS NULL THEN
  RAISE EXCEPTION 'Invalid disaster status transition.';
  END IF;
  IF EXISTS (
  SELECT 1
  FROM disaster_event_status_transitions dst
  WHERE dst.id = v_transition_id
  AND dst.requires_note = TRUE
  AND (NEW.note IS NULL OR CHAR_LENGTH(TRIM(NEW.note)) = 0)
  ) THEN
  RAISE EXCEPTION 'Disaster status transition requires a note.';
  END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_disaster_event_status_history_before_insert
BEFORE INSERT ON disaster_event_status_history
FOR EACH ROW
EXECUTE FUNCTION trg_disaster_event_status_history_before_insert_fn();

CREATE OR REPLACE FUNCTION trg_disaster_event_status_history_after_insert_fn()
RETURNS TRIGGER AS $$
DECLARE
  v_status_code VARCHAR(100);
BEGIN
  SELECT status_code INTO v_status_code
  FROM disaster_event_statuses
  WHERE id = NEW.status_id
  LIMIT 1;
  PERFORM set_config('niers.allow_disaster_status_sync', 'on', true);
  UPDATE disaster_events
  SET current_status_id = NEW.status_id,
  ended_at = CASE
  WHEN v_status_code IN ('closed', 'cancelled') AND ended_at IS NULL
  THEN NEW.changed_at
  ELSE ended_at
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_disaster_event_status_history_after_insert
AFTER INSERT ON disaster_event_status_history
FOR EACH ROW
EXECUTE FUNCTION trg_disaster_event_status_history_after_insert_fn();

CREATE OR REPLACE FUNCTION trg_disaster_events_prevent_direct_status_update_fn()
RETURNS TRIGGER AS $$
BEGIN
  IF OLD.current_status_id <> NEW.current_status_id
  AND COALESCE(current_setting('niers.allow_disaster_status_sync', true), 'off') <> 'on' THEN
  RAISE EXCEPTION 'disaster_events.current_status_id cannot be updated directly; use disaster_event_status_history instead.';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_disaster_events_prevent_direct_status_update
BEFORE UPDATE ON disaster_events
FOR EACH ROW
EXECUTE FUNCTION trg_disaster_events_prevent_direct_status_update_fn();

CREATE OR REPLACE FUNCTION trg_relief_request_status_history_before_insert_fn()
RETURNS TRIGGER AS $$
DECLARE
  v_current_status_id BIGINT;
  v_is_terminal BOOLEAN := FALSE;
  v_transition_id BIGINT := NULL;
BEGIN
  SELECT rr.current_status_id, rrs.is_terminal
  INTO v_current_status_id, v_is_terminal
  FROM relief_requests rr
  INNER JOIN relief_request_statuses rrs ON rrs.id = rr.current_status_id
  WHERE rr.id = NEW.relief_request_id
  LIMIT 1;
  IF v_current_status_id IS NULL THEN
  RAISE EXCEPTION 'Relief request status history: parent request not found.';
  END IF;
  IF NEW.status_id <> v_current_status_id THEN
  IF v_is_terminal THEN
  RAISE EXCEPTION 'Cannot transition relief request from a terminal status.';
  END IF;
  SELECT rst.id
  INTO v_transition_id
  FROM relief_request_status_transitions rst
  WHERE rst.from_status_id = v_current_status_id
  AND rst.to_status_id = NEW.status_id
  AND rst.is_active = TRUE
  LIMIT 1;
  IF v_transition_id IS NULL THEN
  RAISE EXCEPTION 'Invalid relief request status transition.';
  END IF;
  IF EXISTS (
  SELECT 1
  FROM relief_request_status_transitions rst
  WHERE rst.id = v_transition_id
  AND rst.requires_note = TRUE
  AND (NEW.note IS NULL OR CHAR_LENGTH(TRIM(NEW.note)) = 0)
  ) THEN
  RAISE EXCEPTION 'Relief request status transition requires a note.';
  END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_relief_request_status_history_before_insert
BEFORE INSERT ON relief_request_status_history
FOR EACH ROW
EXECUTE FUNCTION trg_relief_request_status_history_before_insert_fn();

CREATE OR REPLACE FUNCTION trg_relief_request_status_history_after_insert_fn()
RETURNS TRIGGER AS $$
BEGIN
  PERFORM set_config('niers.allow_relief_request_status_sync', 'on', true);
  UPDATE relief_requests
  SET current_status_id = NEW.status_id
  WHERE id = NEW.relief_request_id;
  PERFORM set_config('niers.allow_relief_request_status_sync', 'off', true);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_relief_request_status_history_after_insert
AFTER INSERT ON relief_request_status_history
FOR EACH ROW
EXECUTE FUNCTION trg_relief_request_status_history_after_insert_fn();

CREATE OR REPLACE FUNCTION trg_relief_requests_prevent_direct_status_update_fn()
RETURNS TRIGGER AS $$
BEGIN
  IF OLD.current_status_id <> NEW.current_status_id
  AND COALESCE(current_setting('niers.allow_relief_request_status_sync', true), 'off') <> 'on' THEN
  RAISE EXCEPTION 'relief_requests.current_status_id cannot be updated directly; use relief_request_status_history instead.';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_relief_requests_prevent_direct_status_update
BEFORE UPDATE ON relief_requests
FOR EACH ROW
EXECUTE FUNCTION trg_relief_requests_prevent_direct_status_update_fn();

CREATE OR REPLACE FUNCTION trg_disaster_affected_areas_before_insert_fn()
RETURNS TRIGGER AS $$
BEGIN
  IF NOT EXISTS (
  SELECT 1
  FROM administrative_areas aa
  WHERE aa.id = NEW.admin_area_id
  AND aa.area_type = 'upazila'
  ) THEN
  RAISE EXCEPTION 'Disaster affected areas must reference an upazila administrative area.';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_disaster_affected_areas_before_insert
BEFORE INSERT ON disaster_affected_areas
FOR EACH ROW
EXECUTE FUNCTION trg_disaster_affected_areas_before_insert_fn();
