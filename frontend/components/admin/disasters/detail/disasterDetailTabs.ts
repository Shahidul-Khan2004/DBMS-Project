export type DisasterDetailTab =
  | "overview"
  | "affected-areas"
  | "shelter-network"
  | "relief-hubs"
  | "support-facilities"
  | "agencies"
  | "incidents"
  | "relief"
  | "timeline";

export const DISASTER_DETAIL_TABS: { id: DisasterDetailTab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "affected-areas", label: "Affected Areas" },
  { id: "shelter-network", label: "Shelter Network" },
  { id: "relief-hubs", label: "Relief Hubs" },
  { id: "support-facilities", label: "Support Facilities" },
  { id: "agencies", label: "Agencies" },
  { id: "incidents", label: "Linked Incidents" },
  { id: "relief", label: "Relief" },
  { id: "timeline", label: "Timeline" },
];
