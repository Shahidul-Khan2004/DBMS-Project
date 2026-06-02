export type AdministrativeAreaSearchResult = {
  id: number;
  code: string;
  name: string;
  areaType: "district" | "upazila";
  hierarchyPath: string;
};

export type AdministrativeAreaSearchResponse = {
  areas: AdministrativeAreaSearchResult[];
};
