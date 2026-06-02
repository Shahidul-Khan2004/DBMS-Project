export type DisasterDetailTab =
  | "overview"
  | "affected-areas"
  | "responsibilities"
  | "declarations"
  | "incidents"
  | "shelters"
  | "relief-hubs"
  | "relief-requests"
  | "relief-distributions";

export const DISASTER_DETAIL_TABS: { id: DisasterDetailTab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "affected-areas", label: "Affected Areas" },
  { id: "responsibilities", label: "Responsibilities" },
  { id: "declarations", label: "Declarations" },
  { id: "incidents", label: "Linked Incidents" },
  { id: "shelters", label: "Shelters" },
  { id: "relief-hubs", label: "Relief Hubs" },
  { id: "relief-requests", label: "Relief Requests" },
  { id: "relief-distributions", label: "Distributions" },
];
