import * as disasterRepo from "../repositories/disasterOperationsRepo.js";
import { resolveGeoSortFromQuery } from "./geoSortService.js";

export const createDisaster = disasterRepo.createDisaster;
export const listDisasters = disasterRepo.listDisasters;
export const getDisasterByPublicUuid = disasterRepo.getDisasterByPublicUuid;

export async function getDisasterDashboard(publicUuid, query = {}) {
  const { geoSort } = await resolveGeoSortFromQuery(query, {
    disasterPublicUuid: publicUuid,
  });
  return disasterRepo.getDisasterDashboard(publicUuid, { geoSort });
}
export const transitionDisasterStatus = disasterRepo.transitionDisasterStatus;
export const addAffectedAreas = disasterRepo.addAffectedAreas;
export const updateAffectedAreaAssessment = disasterRepo.updateAffectedAreaAssessment;
export const assignResponsibility = disasterRepo.assignResponsibility;
export const issueInitialDeclaration = disasterRepo.issueInitialDeclaration;
export const issueDeclarationAmendment = disasterRepo.issueDeclarationAmendment;
export const manualActivateShelter = disasterRepo.manualActivateShelter;
export const manualActivateReliefHub = disasterRepo.manualActivateReliefHub;
export const linkIncident = disasterRepo.linkIncident;
export const unlinkIncident = disasterRepo.unlinkIncident;
export const listLinkedIncidents = disasterRepo.listLinkedIncidents;
export const listCandidateIncidents = disasterRepo.listCandidateIncidents;
export const assignShelterManagingAgency = disasterRepo.assignShelterManagingAgency;
export const recordShelterOccupancy = disasterRepo.recordShelterOccupancy;
export const recordStockReceipt = disasterRepo.recordStockReceipt;
export const createReliefRequest = disasterRepo.createReliefRequest;
export const approveReliefRequest = disasterRepo.approveReliefRequest;
export const rejectReliefRequest = disasterRepo.rejectReliefRequest;
export const createReliefDistribution = disasterRepo.createReliefDistribution;
export const listPublicDisasters = disasterRepo.listPublicDisasters;
export const getPublicDisasterSummary = disasterRepo.getPublicDisasterSummary;
