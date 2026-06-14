export type AdministrativeAreaNode = {
  id: number;
  name: string;
  code: string;
  areaType: string;
};

export type AdministrativeAreaDetail = {
  id: number;
  code: string;
  name: string;
  areaType: string;
  hierarchyPath: string;
  division: AdministrativeAreaNode | null;
  district: AdministrativeAreaNode | null;
  upazila: AdministrativeAreaNode | null;
  union: AdministrativeAreaNode | null;
};

export type AdministrativeAreaDetailResponse = {
  adminArea: AdministrativeAreaDetail;
};
